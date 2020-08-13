package main

import (
	"encoding/json"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket/pcapgo"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// common config
var (
	RecvDevice       string
	RecvIP           net.IP
	RecvHardwareAddr net.HardwareAddr
	SendDevice       string
	SendIP           net.IP
	SendHardwareAddr net.HardwareAddr
	currentTime      time.Time
	logFile          *os.File
	err              error
)

// IDKEYencode encode ID seq
func IDKEYencode(ID uint32) (uint16, uint16) {
	//ICMP ID uint16,ICMP seq uint16 = 32 bit
	return uint16((ID >> 16) & 0xffff), uint16(ID & 0xffff)
}

// IDKEYdecode decode ID seq
func IDKEYdecode(ICMPID uint16, ICMPseq uint16) uint32 {

	return uint32(ICMPID)<<16 + uint32(ICMPseq)

}

// PayloadChecksum 获取主动探测返回报文完整性
func PayloadChecksum(bytes []byte) uint8 {

	var csum uint8
	for i := 0; i < len(bytes); i++ {
		csum += bytes[i]
	}
	return csum
}

// filter class

// FILETRTYPE decide result
type FILETRTYPE uint16

// OTHER no use
var (
	OTHER  FILETRTYPE = 0x0000
	IPICMP FILETRTYPE = 0x0001
	IPUDP  FILETRTYPE = 0x0002
	IPTCP  FILETRTYPE = 0x0003
)

// FilterClassifier 过滤分类器
type FilterClassifier struct {
	eth           layers.Ethernet
	ip            layers.IPv4
	tcp           layers.TCP
	udp           layers.UDP
	icmp          layers.ICMPv4
	payload       gopacket.Payload
	parser        *gopacket.DecodingLayerParser
	decodedLayers []gopacket.LayerType
}

func (fc *FilterClassifier) init() {
	fc.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &fc.eth, &fc.ip, &fc.tcp, &fc.udp, &fc.icmp, &fc.payload)
	fc.decodedLayers = make([]gopacket.LayerType, 0, 10)

}

func (fc *FilterClassifier) run(data []byte) (FILETRTYPE, FilterClassifier) {
	err = fc.parser.DecodeLayers(data, &fc.decodedLayers)
	if err != nil {
		// log.Println("Error DecodeLayer :", err)
	}
	for i := 0; i < len(fc.decodedLayers); i++ {
		typ := fc.decodedLayers[i]
		switch typ {
		case layers.LayerTypeEthernet:
			// 如果是自己发送的 直接返回 other
			if fc.eth.SrcMAC.String() == RecvHardwareAddr.String() || fc.eth.SrcMAC.String() == SendHardwareAddr.String() {
				return OTHER, *fc
			}
		case layers.LayerTypeIPv4:
			// 如果是自己发送的 直接返回 other
			if fc.ip.SrcIP.Equal(RecvIP) || fc.ip.SrcIP.Equal(SendIP) {
				return OTHER, *fc
			}
		case layers.LayerTypeUDP:
			// log.Println("    UDP ", fc.udp.SrcPort, fc.udp.DstPort)

			return IPUDP, *fc
		case layers.LayerTypeTCP:
			// log.Println("    TCP ", fc.tcp.SrcPort, fc.tcp.DstPort)

			return IPTCP, *fc
		case layers.LayerTypeICMPv4:
			// log.Println("    ICMP ", fc.icmp.TypeCode)
			// 需要一些判断条件
			// 只有是发给自己的才收
			if fc.ip.DstIP.Equal(RecvIP) {
				return IPICMP, *fc
			}
			return OTHER, *fc
		}
	}
	return OTHER, *fc
}

// FCtoGPchan FilterClassifier to GeneratePayload
type FCtoGPchan struct {
	CurID      uint32
	RecvSrcMAC net.HardwareAddr
	RecvSrcIP  net.IP
	RecvTTL    int
}

// Raw is icmp probe payload
type Raw struct {
	RecvSrcIP string
	RecvTTL   int
	ID        uint32
	Key       int
}

// GeneratePayload class
type GeneratePayload struct {
	curKey   int
	curID    uint32
	buffer   gopacket.SerializeBuffer
	options  gopacket.SerializeOptions
	raw      Raw
	rawbytes []byte
	eth      layers.Ethernet
	ip       layers.IPv4
	icmp     layers.ICMPv4
	payload  gopacket.Payload
}

// GeneratePayload 初始化
func (GP *GeneratePayload) init() {
	GP.options = gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	GP.eth.EthernetType = layers.EthernetTypeIPv4
	GP.eth.SrcMAC = SendHardwareAddr

	// Version    uint8
	// IHL        uint8
	// TOS        uint8
	// Length     uint16
	// Id         uint16
	// Flags      IPv4Flag
	// FragOffset uint16
	// TTL        uint8
	// Protocol   IPProtocol
	// Checksum   uint16
	// SrcIP      net.IP
	// DstIP      net.IP
	// Options    []IPv4Option
	// Padding    []byte
	GP.ip.Version = 4
	GP.ip.IHL = 20
	GP.ip.TOS = 0
	GP.ip.Flags = 0
	GP.ip.FragOffset = 0
	GP.ip.SrcIP = SendIP
	GP.ip.Protocol = layers.IPProtocolICMPv4
	// TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, layers.ICMPv4CodeNet),
	// Id:       ICMPID,
	// Seq:      ICMPseq,
	GP.icmp.TypeCode = layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, layers.ICMPv4CodeNet)
}
func (GP *GeneratePayload) config(RecvSrcMAC net.HardwareAddr, RecvSrcIP net.IP, RecvTTL int, curID uint32) {
	GP.curKey = 0
	GP.curID = curID
	// 给特定数据包初值
	// 本数据包内固定值
	GP.eth.DstMAC = RecvSrcMAC
	GP.ip.DstIP = RecvSrcIP
	GP.ip.Id = uint16(GP.curKey)
	if RecvTTL < 64 {
		GP.ip.TTL = 64
	} else if RecvTTL < 128 {
		GP.ip.TTL = 128
	} else {
		GP.ip.TTL = 255
	}

	GP.ip.TTL = GP.ip.TTL - uint8(RecvTTL) + 1
	//
	GP.raw.Key = GP.curKey
	GP.raw.ID = curID
	GP.raw.RecvSrcIP = RecvSrcIP.String()
	GP.raw.RecvTTL = RecvTTL
	// 本数据包内动态值的初始化

	GP.icmp.Id, GP.icmp.Seq = IDKEYencode(GP.raw.ID)
	GP.rawbytes, _ = json.Marshal(GP.raw)
	GP.payload = append([]byte{PayloadChecksum(GP.rawbytes)}, GP.rawbytes...)

}

func (GP *GeneratePayload) update() bool {
	GP.curKey++
	GP.ip.Id = uint16(GP.curKey)
	GP.raw.Key = GP.curKey
	GP.ip.TTL--
	if GP.curKey >= 4 {
		return false
	}
	if GP.ip.TTL <= 0 {
		return false
	}
	GP.icmp.Id, GP.icmp.Seq = IDKEYencode(GP.curID)
	GP.rawbytes, _ = json.Marshal(GP.raw)
	GP.payload = append([]byte{PayloadChecksum(GP.rawbytes)}, GP.rawbytes...)
	return true
}
func (GP *GeneratePayload) generate() []byte {
	buffer := gopacket.NewSerializeBuffer()
	gopacket.SerializeLayers(buffer, GP.options, &GP.eth, &GP.ip, &GP.icmp, GP.payload)
	return buffer.Bytes()
}

// // GeneratePayload 闭包实现
// func GeneratePayload(RecvSrcMAC net.HardwareAddr, RecvSrcIP net.IP, RecvTTL int, curID uint64) func() []byte {
// 	// 实现思路，每一个TTL发4次，正常状态下TTL会递减4次，除非为0，这样次curkey不会超过16

// 	curKey := 0

// 	return func() []byte {
// 		//
// 		if curKey >= 16 {
// 			log.Println("over curKey cap", curKey)
// 			return nil
// 		}
// 		// SetTTL = 0 ？
// 		var SetTTL int
// 		if RecvTTL < 64 {
// 			SetTTL = 64
// 		} else if RecvTTL < 128 {
// 			SetTTL = 128
// 		} else {
// 			SetTTL = 255
// 		}
// 		SetTTL = SetTTL - (curKey >> 2) - RecvTTL + 1
// 		if SetTTL <= 0 {
// 			log.Printf("SetTTL <= 0, RecvTTL :%d\n", RecvTTL)
// 			return nil
// 		}
// 		IPID, ICMPID, ICMPseq := IDKEYencode(curID, curKey>>2)
// 		buffer := gopacket.NewSerializeBuffer()
// 		options := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
// 		raw := &Raw{
// 			RecvSrcIP.String(),
// 			RecvTTL,
// 			curID,
// 			curKey,
// 		}
// 		rawbytes, _ := json.Marshal(raw)
// 		gopacket.SerializeLayers(buffer, options,
// 			&layers.Ethernet{
// 				SrcMAC:       localhardwareaddr,
// 				DstMAC:       RecvSrcMAC,
// 				EthernetType: layers.EthernetTypeIPv4,
// 			},
// 			&layers.IPv4{
// 				Version:    4,
// 				IHL:        20,
// 				TOS:        0x00000000,
// 				Flags:      0x0000,
// 				FragOffset: 0,
// 				Id:         IPID,
// 				DstIP:      RecvSrcIP,
// 				SrcIP:      localaddr,
// 				TTL:        uint8(SetTTL),
// 				Protocol:   layers.IPProtocolICMPv4,
// 			},
// 			&layers.ICMPv4{
// 				TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, layers.ICMPv4CodeNet),
// 				Id:       ICMPID,
// 				Seq:      ICMPseq,
// 			},
// 			gopacket.Payload(append([]byte{Payloadchecksum(rawbytes)}, rawbytes...)),
// 			// gopacket.Payload(rawbytes),
// 		)
// 		curID = curID + 1
// 		return buffer.Bytes()
// 	}
// }

// PacketOutput send packet class
type PacketOutput struct {
	inactiveSend *pcap.InactiveHandle
	handleSend   *pcap.Handle
	circle       int
}

func (PO *PacketOutput) init(device string, circle int) bool {
	PO.inactiveSend, err = pcap.NewInactiveHandle(device)
	if err != nil {
		log.Fatal(err)
		return false
	}
	PO.handleSend, err = PO.inactiveSend.Activate()
	if err != nil {
		log.Fatal(err)
		return false
	}
	PO.circle = circle
	return true
}

func (PO *PacketOutput) send(data []byte) {
	for i := 0; i < PO.circle; i++ {
		err = PO.handleSend.WritePacketData(data)
		if err != nil {
			log.Println(err)
		}
	}
}

// GPtoPOchan GeneratePayload to PacketOutput
type GPtoPOchan struct {
	CurID uint32
	Data  []byte
}

// PacketInput recv packet class
type PacketInput struct {
	inactiveRecv *pcap.InactiveHandle
	handleRecv   *pcap.Handle
	count        uint64
}

func (PI *PacketInput) init(device string) bool {
	PI.inactiveRecv, err = pcap.NewInactiveHandle(device)
	if err != nil {
		log.Fatal(err)
		return false
	}
	if err = PI.inactiveRecv.SetTimeout(pcap.BlockForever); err != nil {
		log.Fatal(err)
		return false
	}
	if err = PI.inactiveRecv.SetPromisc(true); err != nil {
		log.Fatal(err)
		return false
	}
	PI.handleRecv, err = PI.inactiveRecv.Activate()
	if err != nil {
		log.Fatal(err)
		return false
	}
	PI.count = 0
	return true
}

func (PI *PacketInput) recv(count uint64) (bool, uint64, []byte, gopacket.CaptureInfo) {
	data, ci, _ := PI.handleRecv.ReadPacketData()

	PI.count++
	if PI.count > count {
		return false, PI.count, data, ci
	}
	return true, PI.count, data, ci
}

// PItoFCchan PacketInput to FilterClassifier
type PItoFCchan struct {
	Data []byte
	Ci   gopacket.CaptureInfo
}

// WriteFile write packet to pcap
type WriteFile struct {
	f       *os.File
	w       *pcapgo.Writer
	snaplen uint32
}

func (WF *WriteFile) init(filename string, snaplen uint32) bool {
	WF.f, err = os.Create(filename)
	if err != nil {
		log.Fatal(err)
		return false
	}
	WF.w = pcapgo.NewWriter(WF.f)
	WF.w.WriteFileHeader(snaplen, layers.LinkTypeEthernet)
	return true
}

func (WF *WriteFile) write(data []byte, ci gopacket.CaptureInfo) {
	err = WF.w.WritePacket(ci, data)
	if err != nil {
		log.Println(err)
	}
}

// FCtoWFchan FilterClassifier to WriteFile
type FCtoWFchan struct {
	Data         []byte
	Ci           gopacket.CaptureInfo
	RecvCurID    uint32
	RecvKey      int
	RecvTypeCode layers.ICMPv4TypeCode
}

// SystemINIT 对整个系统初始化
func SystemINIT(RecvDeviceName string, SendDeviceName string) {
	var ohmyflag bool
	// 首先是当前时间
	currentTime = time.Now()
	// 日志
	logFile, err = os.OpenFile(currentTime.String()+".log", os.O_CREATE|os.O_RDWR|os.O_APPEND, 0666)
	if err != nil {
		log.Println("Fail to find", *logFile, "cServer start Failed")
		os.Exit(1)
	}
	log.SetOutput(logFile)
	// 网络环境配置
	RecvDevice = RecvDeviceName
	SendDevice = SendDeviceName
	RecvInterface, err := net.InterfaceByName(RecvDevice)
	if err != nil {
		log.Println("Fail to get InterfaceByName in RecvDevice")
		os.Exit(1)
	}
	RecvHardwareAddr = RecvInterface.HardwareAddr
	RecvAddrs, err := RecvInterface.Addrs()
	if err != nil {
		log.Println("Fail to get InterfaceAddrs in RecvDevice")
		os.Exit(1)
	}
	ohmyflag = true // 需要exit
	for _, tmpAddr := range RecvAddrs {

		if ipnet, ok := tmpAddr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil && len(ipnet.IP) == net.IPv6len {

			ohmyflag = false // 找到了，不用exit
			RecvIP = ipnet.IP
		}

	}
	if ohmyflag {
		log.Println("Fail to get Interface IPv4 in RecvDevice")
		os.Exit(1)
	}

	SendInterface, err := net.InterfaceByName(SendDevice)
	if err != nil {
		log.Println("Fail to get InterfaceByName in SendDevice")
		os.Exit(1)
	}
	SendHardwareAddr = SendInterface.HardwareAddr
	SendAddrs, err := SendInterface.Addrs()
	if err != nil {
		log.Println("Fail to get InterfaceAddrs in SendDevice")
		os.Exit(1)
	}
	ohmyflag = true // 需要exit
	for _, tmpAddr := range SendAddrs {

		if ipnet, ok := tmpAddr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil && len(ipnet.IP) == net.IPv6len {

			ohmyflag = false // 找到了，不用exit
			SendIP = ipnet.IP
		}

	}
	if ohmyflag {
		log.Println("Fail to get Interface IPv4 in SendDevice")
		os.Exit(1)
	}

}
