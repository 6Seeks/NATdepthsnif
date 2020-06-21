package main

import (
	"encoding/binary"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/willf/bloom"
)

func main() {

	n := uint(1000)
	filter := bloom.New(20*n, 5) // load of 20, 5 keys
	filter.Add([]byte("Love"))

	fmt.Println(filter.Test([]byte("Love")))
	fmt.Println(filter.Test([]byte("Loveasdas")))

	i := uint32(1048156150)
	fmt.Println((i))
	n1 := make([]byte, 4)
	fmt.Println(n1)
	binary.BigEndian.PutUint32(n1, i)
	fmt.Println(n1)
	filter.Add(n1)

	PI := PacketInput{}
	var curID interface{}
	var data []byte
	var ci gopacket.CaptureInfo
	for {
		curID, data, ci = PI.recv()

		if curID == false {
			PI.handleRecv.Close()
			PI.inactiveRecv.CleanUp()
			break // 计数器用完了
		}
		log.Println("PacketInput ", curID)
	}

}
