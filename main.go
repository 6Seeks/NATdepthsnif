package main

import (
	"log"
	"os"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func main() {
	// PI : PacketInput
	// PO : PacketOutput
	// FC : FilterClassifier
	// GP : GeneratePayload
	// WF : WriteFile
	var (
		PItoFC chan PItoFCchan
		FCtoGP chan FCtoGPchan
		FCtoWF chan FCtoWFchan
		GPtoPO chan GPtoPOchan
		wg     sync.WaitGroup
	)
	// 整个系统初始化
	SystemINIT("eth0", "eth1")
	PItoFC = make(chan PItoFCchan, 100)
	FCtoGP = make(chan FCtoGPchan, 100)
	FCtoWF = make(chan FCtoWFchan, 100)
	GPtoPO = make(chan GPtoPOchan, 100)
	PI := PacketInput{}
	FC := FilterClassifier{}
	WF := WriteFile{}
	GP := GeneratePayload{}
	PO := PacketOutput{}
	if ok := PI.init(RecvDevice); !ok {
		log.Println("PacketInput init fail")
		os.Exit(1)
	}
	FC.init()
	if ok := WF.init(currentTime.String()+".pcap", 1024); !ok {
		log.Println("WriteFile init fail")
		os.Exit(1)
	}
	GP.init()
	PO.init(SendDevice, 4)
	// wait group
	wg.Add(5)
	// PacketInput
	go func() {
		var curID interface{}
		var data []byte
		var ci gopacket.CaptureInfo
		for {
			curID, data, ci = PI.recv()
			PItoFC <- PItoFCchan{
				CurID: curID,
				Data:  data,
				Ci:    ci,
			}
			if curID == false {
				PI.handleRecv.Close()
				PI.inactiveRecv.CleanUp()
				break // 计数器用完了
			}
			log.Println("PacketInput ", curID)
		}
		wg.Done()
	}()
	// FilterClassifier
	go func() {

		var piresult PItoFCchan
		var fctype FILETRTYPE
		var fcret1 interface{}
		var fcret2 interface{}
		for {
			piresult = <-PItoFC
			fctype, fcret1, fcret2 = FC.run(piresult.Data)
			if piresult.CurID == false {
				FCtoGP <- FCtoGPchan{
					CurID:      piresult.CurID,
					RecvSrcMAC: fcret1.(layers.Ethernet).SrcMAC,
					RecvSrcIP:  fcret2.(layers.IPv4).SrcIP,
					RecvTTL:    int(fcret2.(layers.IPv4).TTL),
				}
				FCtoWF <- FCtoWFchan{
					Run:  false,
					Data: piresult.Data,
					Ci:   piresult.Ci,
				}
				// 出口
				break
			}
			log.Println("FilterClassifier ", piresult.CurID)
			switch fctype {
			case OTHER:
				continue
			case IPTCP, IPUDP:
				FCtoGP <- FCtoGPchan{
					CurID:      piresult.CurID,
					RecvSrcMAC: fcret1.(layers.Ethernet).SrcMAC,
					RecvSrcIP:  fcret2.(layers.IPv4).SrcIP,
					RecvTTL:    int(fcret2.(layers.IPv4).TTL),
				}
			case IPICMP:
				FCtoWF <- FCtoWFchan{
					Run:  true,
					Data: piresult.Data,
					Ci:   piresult.Ci,
				}
			}

		}
		wg.Done()
	}()
	// WriteFile
	go func() {
		var fcresult FCtoWFchan
		for {
			fcresult = <-FCtoWF
			if fcresult.Run == false {
				WF.f.Close()
				break
			}
			log.Println("WriteFile ")
			WF.write(fcresult.Data, fcresult.Ci)
		}
		wg.Done()
	}()
	// GeneratePayload
	go func() {
		var fcresult FCtoGPchan
		for {
			fcresult = <-FCtoGP
			log.Println("GeneratePayload ", fcresult.CurID)
			GP.config(fcresult.RecvSrcMAC, fcresult.RecvSrcIP, fcresult.RecvTTL, fcresult.CurID.(uint64))
			for i := 0; i < 4; i++ {
				GPtoPO <- GPtoPOchan{
					Run:  !(fcresult.CurID == false),
					Data: GP.generate(),
				}
				GP.generate()
				if ok := GP.update(); !ok {
					break
				}
			}
			if fcresult.CurID == false {
				break
			}
		}
		wg.Done()
	}()
	// PacketOutput
	go func() {
		var gpresult GPtoPOchan
		for {
			gpresult = <-GPtoPO
			if gpresult.Run == false {
				PO.handleSend.Close()
				PO.inactiveSend.CleanUp()
				break
			}
			log.Println("PacketOutput ")
			PO.send(gpresult.Data)
		}
		wg.Done()
	}()
	wg.Wait()
}
