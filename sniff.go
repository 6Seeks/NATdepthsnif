package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime/debug"
	"strconv"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"

	"net/http"
	_ "net/http/pprof"
)

var (
	device                        string = "en0"
	localhardwareaddr             net.HardwareAddr
	localaddr                     net.IP
	snapshotlen                   int  = 1024
	promiscuous                   bool = true // 混杂模式，嗅探时需要打开
	err                           error
	handleRecv                    *pcap.Handle
	inactiveRecv                  *pcap.InactiveHandle
	handleSend                    *pcap.Handle
	inactiveSend                  *pcap.InactiveHandle
	packetSourceToFilter          chan PacketAndNum
	generatePayloadTopacketOutput chan []byte
	gorunNum                      int       = 4 // 默认4路并行
	currentTime                   time.Time = time.Now()
)

// Raw is icmp probe payload
type Raw struct {
	SrcIP   string
	DstIP   string
	SrcPort int
	DstPort int
	RecvTTL int
	ID      int
	Key     int
}

func (r *Raw) showRaw() {
	fmt.Printf("generateRaw\n")
	fmt.Printf("From %s : %d to %s : %d\n", r.SrcIP, r.SrcPort, r.DstIP, r.DstPort)
	fmt.Printf("RecvTTL : %d\n", r.RecvTTL)
	fmt.Printf("set ID : %d\n", r.ID)
	fmt.Printf("Key : %d", r.Key)
	fmt.Println()
}

// 保证每一个接收到的数据包的唯一性
type PacketAndNum struct {
	Packet gopacket.Packet
	curKey int
}

// Payloadchecksum 获取主动探测返回报文完整性
func Payloadchecksum(bytes []byte) uint8 {

	var csum uint8
	for i := 0; i < len(bytes); i++ {
		csum += bytes[i]
	}
	return csum
}

// 生成探测包负载
func generatePayload(SrcMAC net.HardwareAddr, SrcIP net.IP, DstIP net.IP, SrcPort int, DstPort int, RecvTTL int, curKey int) func() []byte {
	curID := 0
	return func() []byte {
		buffer := gopacket.NewSerializeBuffer()
		options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
		raw := &Raw{
			SrcIP.String(),
			DstIP.String(),
			SrcPort,
			DstPort,
			RecvTTL,
			curID,
			curKey,
		}
		rawbytes, _ := json.Marshal(raw)
		SetTTL := 0 - curID - RecvTTL
		if RecvTTL < 64 {
			SetTTL = 64 + SetTTL
		} else if RecvTTL < 128 {
			SetTTL = 128 + SetTTL
		} else {
			SetTTL = 255 + SetTTL
		}
		if SetTTL < 0 {
			fmt.Printf("SetTTL < 0, RecvTTL :%d\n", RecvTTL)
			return nil
		}
		gopacket.SerializeLayers(buffer, options,
			&layers.Ethernet{
				SrcMAC:       localhardwareaddr,
				DstMAC:       SrcMAC,
				EthernetType: layers.EthernetTypeIPv4,
			},
			&layers.IPv4{
				Version:    4,
				IHL:        20,
				TOS:        0x00000000,
				Flags:      0x0000,
				FragOffset: 0,
				Id:         uint16(curID),
				// DstIP:      net.IP{36, 152, 44, 95},
				DstIP:    SrcIP,
				SrcIP:    localaddr,
				TTL:      uint8(SetTTL),
				Protocol: layers.IPProtocolICMPv4,
			},
			&layers.ICMPv4{
				TypeCode: 0x0800,
				Id:       uint16(curID),
				Seq:      0,
			},
			gopacket.Payload(append([]byte{Payloadchecksum(rawbytes)}, rawbytes...)),
			// gopacket.Payload(rawbytes),
		)
		curID = curID + 1
		return buffer.Bytes()
	}
}

// filter
// 从packetSourceToFilter接收报文，分类：
// 第一类，被动接收报文 ，存在IP层的非主动探测返回报文
// 第二类，主动探测返回报文，icmp报文 且raw负载的
func filter(pcapName string) {
	// 保存探测返回报文
	// Open output pcap file and write header
	f, _ := os.Create(pcapName)
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(uint32(snapshotlen), layers.LinkTypeEthernet)
	defer f.Close()
	// start 过滤
	for {
		packetandnum := <-packetSourceToFilter
		packet := packetandnum.Packet
		curKey := packetandnum.curKey
		fmt.Println("curKey ", curKey)

		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer == nil {
			fmt.Println("decode Ethernet fail")
			continue
		}
		ethernet, _ := ethernetLayer.(*layers.Ethernet)
		// 自己发送的报文 不要检测
		if ethernet.SrcMAC.String() == localhardwareaddr.String() {
			continue
		}
		switch ethernet.EthernetType {
		case layers.EthernetTypeIPv4:
			ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
			if ipv4Layer == nil {
				fmt.Println("decode IPv4 fail")
				continue
			}
			ipv4, _ := ipv4Layer.(*layers.IPv4)

			// 自己发送的报文 不要检测
			if ipv4.SrcIP.String() == localaddr.String() {
				continue
			}

			switch ipv4.Protocol {
			case layers.IPProtocolICMPv4:
				icmpv4Layer := packet.Layer(layers.LayerTypeICMPv4)
				if icmpv4Layer == nil {
					fmt.Println("decode ICMPv4 fail")
					continue
				}
				icmpv4, _ := icmpv4Layer.(*layers.ICMPv4)
				// 接下来检测是否是主动探测返回报文
				icmpv4data := icmpv4.Payload
				if len(icmpv4data) < 2 { // 补丁patch
					fmt.Println("icmp is not reply")
					continue
				}
				if icmpv4data[0] != Payloadchecksum(icmpv4data[1:]) {
					fmt.Println("icmp is not reply")
					continue
				}
				// 先简单打印吧
				raw := &Raw{}
				err := json.Unmarshal(icmpv4data[1:], raw)
				if err != nil {
					fmt.Println("json decode fail")
				} else {
					raw.showRaw()
					w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
				}

			case layers.IPProtocolUDP:
				udpLayer := packet.Layer(layers.LayerTypeUDP)
				if udpLayer == nil {
					fmt.Println("decode UDP fail")
				}
				udp, _ := udpLayer.(*layers.UDP)

				// 生成探测负载

				gP := generatePayload(ethernet.SrcMAC, ipv4.SrcIP, ipv4.DstIP, int(udp.SrcPort), int(udp.DstPort), int(ipv4.TTL), curKey)
				go func() {
					for i := 0; i < 5; i++ {
						gPbufferBytes := gP()
						if gPbufferBytes == nil {
							break
						}
						generatePayloadTopacketOutput <- gPbufferBytes
					}
				}()
			case layers.IPProtocolTCP:
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer == nil {
					fmt.Println("decode TCP fail")
				}
				tcp, _ := tcpLayer.(*layers.TCP)

				// 生成探测负载

				gP := generatePayload(ethernet.SrcMAC, ipv4.SrcIP, ipv4.DstIP, int(tcp.SrcPort), int(tcp.DstPort), int(ipv4.TTL), curKey)

				go func() {
					for i := 0; i < 5; i++ {
						gPbufferBytes := gP()
						if gPbufferBytes == nil {
							break
						}
						generatePayloadTopacketOutput <- gPbufferBytes
					}
				}()
			default:
				fmt.Println("no 3 layers")
				continue
			}

		case layers.EthernetTypeIPv6:
			// ipv6 以后有机会再做吧
			ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
			if ipv6Layer == nil {
				fmt.Println("decode IPv6 fail")
			}
			// ipv6, _ := ipv6Layer.(*layers.IPv6)
			// 以后在做
			continue
		default:
			fmt.Println("no 2 layers")
			continue
		}

	}

}

func packetOutput() {

	inactiveSend, err := pcap.NewInactiveHandle(device)
	if err != nil {
		log.Fatal(err)
	}
	defer inactiveSend.CleanUp()
	handleSend, err := inactiveSend.Activate() // after this, inactive is no longer valid
	if err != nil {
		log.Fatal(err)
		return
	}
	defer handleSend.Close()
	for {
		bytesOutput := <-generatePayloadTopacketOutput

		fmt.Println("_____________output____________________")
		for i := 0; i < 5; i++ {
			// 每一次探测报文发送5次

			err := handleSend.WritePacketData(bytesOutput)

			if err != nil {
				fmt.Println(err)
				fmt.Println(debug.Stack())
				continue
			}

		}

	}

}

func main() {
	fmt.Println(currentTime)

	fmt.Println("____________________init______________________")
	var curKey int // 需要回应的报文数
	go func() {
		http.ListenAndServe("0.0.0.0:10000", nil)
	}()
	//

	inactiveRecv, err := pcap.NewInactiveHandle(device)
	if err != nil {
		log.Fatal(err)
	}
	defer inactiveRecv.CleanUp()

	// Call various functions on inactive to set it up the way you'd like:
	if err = inactiveRecv.SetTimeout(pcap.BlockForever); err != nil {
		log.Fatal(err)
	}
	if err = inactiveRecv.SetPromisc(promiscuous); err != nil {
		log.Fatal(err)
	}
	if err = inactiveRecv.SetSnapLen(snapshotlen); err != nil {
		log.Fatal(err)
	}

	loaclinterface, err := net.InterfaceByName(device)
	if err != nil {
		fmt.Println(err)
		return
	}
	localhardwareaddr = loaclinterface.HardwareAddr
	addrs, err := loaclinterface.Addrs()
	if err != nil {
		fmt.Println(err)
		return
	}
	for i := range addrs {
		tmpIP := addrs[i].(*net.IPNet)
		if tmpIP.IP.To4() != nil {
			localaddr = tmpIP.IP
		}

	}
	// 避免死锁
	packetSourceToFilter = make(chan PacketAndNum)
	defer close(packetSourceToFilter)
	generatePayloadTopacketOutput = make(chan []byte)
	defer close(generatePayloadTopacketOutput)
	// start
	handleRecv, err := inactiveRecv.Activate() // after this, inactive is no longer valid
	if err != nil {
		log.Fatal(err)
		return
	}
	defer handleRecv.Close()
	// // 多个过滤器协程
	for i := 0; i < gorunNum; i++ {
		go filter(currentTime.String() + strconv.Itoa(i) + ".pcap")
	}
	go packetOutput()
	// Use the handle as a packet source to process all packets
	curKey = 0
	packetSource := gopacket.NewPacketSource(handleRecv, handleRecv.LinkType())
	for {
		packet, err := packetSource.NextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			fmt.Println(err)
			continue
		}
		// resolvePacket(packet)
		packetandnum := PacketAndNum{
			packet,
			curKey,
		}
		packetSourceToFilter <- packetandnum
		curKey++
	}

}
