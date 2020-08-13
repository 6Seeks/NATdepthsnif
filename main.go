package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/willf/bloom"
)

// 全局变量
var (
	PItoFC        chan PItoFCchan
	FCtoGP        chan FCtoGPchan
	FCtoWF        chan FCtoWFchan
	GPtoPO        chan GPtoPOchan
	PItoFCrunflag chan bool
	FCtoGPrunflag chan bool
	FCtoWFrunflag chan bool
	GPtoPOrunflag chan bool
	wg            sync.WaitGroup
)

func main() {
	// PI : PacketInput
	// PO : PacketOutput
	// FC : FilterClassifier
	// GP : GeneratePayload
	// WF : WriteFile
	// 整个系统初始化
	SystemINIT("en0", "en0")
	PItoFC = make(chan PItoFCchan, 100)
	FCtoGP = make(chan FCtoGPchan, 100)
	FCtoWF = make(chan FCtoWFchan, 100)
	GPtoPO = make(chan GPtoPOchan, 100)
	PItoFCrunflag = make(chan bool, 100)
	FCtoGPrunflag = make(chan bool, 100)
	FCtoWFrunflag = make(chan bool, 100)
	GPtoPOrunflag = make(chan bool, 100)
	defer close(PItoFC)
	defer close(FCtoGP)
	defer close(FCtoWF)
	defer close(GPtoPO)
	defer close(PItoFCrunflag)
	defer close(FCtoGPrunflag)
	defer close(FCtoWFrunflag)
	defer close(GPtoPOrunflag)
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
	PO.init(SendDevice, 3)
	// wait group
	wg.Add(5)
	//
	start := time.Now().Unix()
	// PacketInput
	go func() {
		var runflag bool
		var count uint64
		var data []byte
		var ci gopacket.CaptureInfo
		for {

			runflag, count, data, ci = PI.recv(100)
			PItoFCrunflag <- runflag
			if runflag == false {
				PI.handleRecv.Close()
				PI.inactiveRecv.CleanUp()
				break // 计数器用完了
			}
			PItoFC <- PItoFCchan{
				Data: data,
				Ci:   ci,
			}

		}
		// log.Println("PI packets ", count)
		fmt.Println("PI packets ", count)
		wg.Done()
	}()
	// FilterClassifier
	go func() {

		var piresult PItoFCchan
		var fctype FILETRTYPE
		var fc FilterClassifier
		var curID uint32
		var runflag bool
		// bloom filter
		// 10000000	个包不超过0.01的假阳率
		bf := bloom.NewWithEstimates(10000000, 0.01)
		fmt.Println(bf.Cap(), bf.K())
		curID = 0
		for {
			runflag = <-PItoFCrunflag
			if runflag == false {
				// 出口
				FCtoGPrunflag <- runflag
				FCtoWFrunflag <- runflag
				break
			}
			piresult = <-PItoFC

			fctype, fc = FC.run(piresult.Data)

			switch fctype {
			case OTHER:
				continue
			case IPTCP, IPUDP:
				// 布隆过滤器
				if curID%1000000 == 0 {
					bf.ClearAll()
				}
				if bf.Test(append(piresult.Data[26:38], piresult.Data[23])) {
					continue
				}
				bf.Add(append(piresult.Data[26:38], piresult.Data[23]))
				// 通过过滤器的才进行以下内容
				FCtoGP <- FCtoGPchan{
					CurID:      curID,
					RecvSrcMAC: fc.eth.SrcMAC,
					RecvSrcIP:  fc.ip.SrcIP,
					RecvTTL:    int(fc.ip.TTL),
				}
				// 可以统计2^32次方个有效包
				FCtoGPrunflag <- runflag
				curID++

			case IPICMP:
				var recvKey int
				var recvCurID uint32
				if fc.icmp.TypeCode == 0x0000 && PayloadChecksum(fc.icmp.Payload[1:]) == fc.icmp.Payload[0] {
					// icmp reply
					var raw Raw
					json.Unmarshal(fc.icmp.Payload[1:], &raw)
					recvKey = raw.Key
					recvCurID = raw.ID
					if recvCurID != IDKEYdecode(fc.icmp.Id, fc.icmp.Seq) {
						log.Println("warming IPICMP")
					}
				} else if fc.icmp.TypeCode == 0x0b00 {
					// TTL exceed
					recvKey = int(binary.BigEndian.Uint16(fc.icmp.Payload[4:6])) // ip id
					recvCurID = binary.BigEndian.Uint32(fc.icmp.Payload[24:28])  // icmp id + seq
				}
				FCtoWF <- FCtoWFchan{

					Data:         piresult.Data,
					Ci:           piresult.Ci,
					RecvCurID:    recvCurID,
					RecvKey:      recvKey,
					RecvTypeCode: fc.icmp.TypeCode,
				}
				FCtoWFrunflag <- runflag
			}

		}
		fmt.Println("curID", curID)
		wg.Done()
	}()
	// WriteFile
	go func() {
		var fcresult FCtoWFchan
		var runflag bool
		var FileData = make(map[uint32][]int8)
		for {
			runflag = <-FCtoWFrunflag
			if runflag == false {
				WF.f.Close()
				break
			}
			fcresult = <-FCtoWF

			// log.Println("WriteFile  RecvCurID, RecvKey, RecvTypeCode", fcresult.RecvCurID, fcresult.RecvKey, fcresult.RecvTypeCode.String())
			// 1 reply
			// 0 no response
			// -1 ttl exceed
			if _, ok := FileData[fcresult.RecvCurID]; !ok {
				// 没有创建
				FileData[fcresult.RecvCurID] = []int8{-1, -1, -1, -1, -1}
			}
			if fcresult.RecvTypeCode == 0x0000 {
				FileData[fcresult.RecvCurID][fcresult.RecvKey] = 1
			} else if fcresult.RecvTypeCode == 0x0b00 && FileData[fcresult.RecvCurID][fcresult.RecvKey] != 1 {

				FileData[fcresult.RecvCurID][fcresult.RecvKey] = 0
			}

			// WF.write(fcresult.Data, fcresult.Ci)

		}
		fmt.Println(FileData)

		wg.Done()
	}()
	// GeneratePayload
	go func() {
		var fcresult FCtoGPchan
		var runflag bool
		for {
			runflag = <-FCtoGPrunflag
			if runflag == false {
				GPtoPOrunflag <- runflag
				break
			}
			fcresult = <-FCtoGP
			// log.Println("GeneratePayload ", fcresult.CurID)
			GP.config(fcresult.RecvSrcMAC, fcresult.RecvSrcIP, fcresult.RecvTTL, fcresult.CurID)
			for i := 0; i < 5; i++ { // 4层 dynamic TTL

				GPtoPO <- GPtoPOchan{
					Data:  GP.generate(),
					CurID: fcresult.CurID,
				}
				GPtoPOrunflag <- runflag
				ok := GP.update()
				if !ok {
					break
				}
			}

		}
		wg.Done()
	}()
	// PacketOutput
	go func() {
		var gpresult GPtoPOchan
		var runflag bool
		for {
			runflag = <-GPtoPOrunflag
			if runflag == false {
				PO.handleSend.Close()
				PO.inactiveSend.CleanUp()
				break
			}
			gpresult = <-GPtoPO
			// log.Println("PacketOutput ", gpresult.CurID, gpresult.Data[22])
			PO.send(gpresult.Data)

		}
		wg.Done()
	}()
	wg.Wait()
	fmt.Println(time.Now().Unix() - start)
}
