package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"runtime/debug"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
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
	packetSourceToFilter          chan gopacket.Packet
	generatePayloadTopacketOutput chan []byte
)

// Raw is icmp probe payload
type Raw struct {
	SrcIP   string
	DstIP   string
	SrcPort int
	DstPort int
	RecvTTL int
	ID      int
}

func (r *Raw) showRaw() {
	fmt.Printf("generateRaw\n")
	fmt.Printf("From %s : %d to %s : %d\n", r.SrcIP, r.SrcPort, r.DstIP, r.DstPort)
	fmt.Printf("RecvTTL : %d\n", r.RecvTTL)
	fmt.Printf("set ID : %d\n", r.ID)
	fmt.Println()
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
func generatePayload(SrcMAC net.HardwareAddr, SrcIP net.IP, DstIP net.IP, SrcPort int, DstPort int, RecvTTL int) func() []byte {
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
			log.Fatal("SetTTL < 0")
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
				Id:         1,
				DstIP:      net.IP{36, 152, 44, 95},
				SrcIP:      localaddr,
				TTL:        uint8(SetTTL),
				Protocol:   layers.IPProtocolICMPv4,
			},
			&layers.ICMPv4{
				TypeCode: 0x0800,
				Id:       2,
				Seq:      0,
			},
			gopacket.Payload(append([]byte{Payloadchecksum(rawbytes)}, rawbytes...)),
			// gopacket.Payload(rawbytes),
		)
		curID = curID + 1
		return buffer.Bytes()
	}
}

func resolvePacket(packet gopacket.Packet) {
	// fmt.Println(packet.LinkLayer())
	// fmt.Println(packet.NetworkLayer())
	// fmt.Println(packet.TransportLayer())
	// fmt.Println(packet.ApplicationLayer())
	// fmt.Println(packet.Dump())
	// fmt.Println("__________________________________________")
	// fmt.Println(packet.Data())
	// fmt.Println("__________________________________________")
	// fmt.Println(packet.Metadata())
	// fmt.Println("__________________________________________")
	// fmt.Println(packet.String())
	// fmt.Println("__________________________________________")
	// Iterate over all layers, printing out each layer type
	// ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	// if ethernetLayer == nil {
	// 	fmt.Println("no Ethernet layers")
	// 	return
	// }
	// ipLayer := packet.Layer(layers.LayerTypeIPv4)
	// if ipLayer == nil {
	// 	fmt.Println("no IPv4 layers")
	// 	return
	// }
	// udpLayer := packet.Layer(layers.LayerTypeUDP)
	// if udpLayer == nil {
	// 	fmt.Println("no UDP layers")
	// 	return
	// }
	// // Iterate over all layers, printing out each layer type
	// fmt.Println("All packet layers:")
	// for _, layer := range packet.Layers() {
	// 	fmt.Println("- ", layer.LayerType())
	// }
	// fmt.Println("IPv4 and UDP layers detected")
	// ethernet, _ := ethernetLayer.(*layers.Ethernet)
	// ip, _ := ipLayer.(*layers.IPv4)
	// udp, _ := udpLayer.(*layers.UDP)
	// if ethernet.SrcMAC.String() == localhardwareaddr.String() || ip.SrcIP.String() == localaddr.String() {
	// 	fmt.Println("drop")
	// 	return
	// }
	// fmt.Printf("From %s to %s \n", ethernet.SrcMAC.String(), ethernet.DstMAC.String())
	// fmt.Printf("From %s : %d to %s : %d\n", ip.SrcIP, udp.SrcPort, ip.DstIP, udp.DstPort)
	// fmt.Printf("TTL : %d", ip.TTL)
	// fmt.Println()
	// gP := generatePayload(ethernet.SrcMAC, ip.SrcIP, ip.DstIP, udp.SrcPort, udp.DstPort, ip.TTL)
	// err = handle.WritePacketData(gP())
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// err = handle.WritePacketData(gP())
	// if err != nil {
	// 	fmt.Println(err)
	// }
	// err = handle.WritePacketData(gP())
	// if err != nil {
	// 	fmt.Println(err)
	// }

}

// filter
// 从packetSourceToFilter接收报文，分类：
// 第一类，被动接收报文 ，存在IP层的非主动探测返回报文
// 第二类，主动探测返回报文，icmp报文 且raw负载的
func filter() {
	for {
		packet := <-packetSourceToFilter

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
				}

			case layers.IPProtocolUDP:
				udpLayer := packet.Layer(layers.LayerTypeUDP)
				if udpLayer == nil {
					fmt.Println("decode UDP fail")
				}
				udp, _ := udpLayer.(*layers.UDP)

				// 生成探测负载

				gP := generatePayload(ethernet.SrcMAC, ipv4.SrcIP, ipv4.DstIP, int(udp.SrcPort), int(udp.DstPort), int(ipv4.TTL))
				go func() {
					for i := 0; i < 5; i++ {
						generatePayloadTopacketOutput <- gP()
					}
				}()
			case layers.IPProtocolTCP:
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer == nil {
					fmt.Println("decode TCP fail")
				}
				tcp, _ := tcpLayer.(*layers.TCP)

				// 生成探测负载

				gP := generatePayload(ethernet.SrcMAC, ipv4.SrcIP, ipv4.DstIP, int(tcp.SrcPort), int(tcp.DstPort), int(ipv4.TTL))
				go func() {
					for i := 0; i < 5; i++ {
						generatePayloadTopacketOutput <- gP()
					}
				}()
			default:
				fmt.Println("no 3 layers")
				continue
			}

		case layers.EthernetTypeIPv6:
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
	fmt.Println("____________________init______________________")

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
	packetSourceToFilter = make(chan gopacket.Packet)
	generatePayloadTopacketOutput = make(chan []byte)
	// start
	handleRecv, err := inactiveRecv.Activate() // after this, inactive is no longer valid
	if err != nil {
		log.Fatal(err)
		return
	}
	defer handleRecv.Close()
	// // 过滤器
	go filter()
	go packetOutput()
	// Use the handle as a packet source to process all packets
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
		packetSourceToFilter <- packet

	}

}
