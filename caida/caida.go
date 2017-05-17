//package for testing with the caida packet traces
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	// "github.com/hosslen/shadow_lfd/baseline"
	"github.com/hosslen/shadow_lfd/eardet"
	"github.com/hosslen/shadow_lfd/murmur3"
)

const (
	//pcap file
	filename = "equinix-chicago.dirA.20160406-125912.UTC.anon.pcap"
	//number of packets in that file
	numPkts = 23676763
)

var (
	packets [numPkts](*caidaPkt)
	packetsInitialized = false
	errCounter = 0
	tcpCounter = 0
	udpCounter = 0
	res2 bool
)

//encapsulates the information of one "packet" of the caida trace file
type caidaPkt struct {
	Duration time.Duration
	//SrcIP (4 bytes)| DstIP (4 bytes)| Protocol (1 byte)| PortNumSrc (2 bytes)| PortNumDst (2 bytes)
	Id [16]byte
	Size uint32
}

//loades the caida trace file into packets
func loadPCAPFile() {
	c := 0
	if handle, err := pcap.OpenOffline(filename); err != nil {
		panic(err)
	} else {
		var decoder gopacket.Decoder
		if handle.LinkType() == 12 {
    			decoder = layers.LayerTypeIPv4
		} else {
    			decoder = handle.LinkType()
		}
		packetSource := gopacket.NewPacketSource(handle, decoder)
		for packet := range packetSource.Packets() {
			packets[c] = handlePacket(packet)
			c++
		}
	}
	packetsInitialized = true
	fmt.Printf("Total number of packets: %d\n", c)
	fmt.Printf("Total number of errors: %d\n", errCounter)
	fmt.Printf("Number of TCP over IPv4 packets: %d\n", tcpCounter)
	fmt.Printf("Number of UDP over IPv4 packets: %d\n", udpCounter)
}

//transforms a packet into a caidaPkt
func handlePacket(packet gopacket.Packet) *caidaPkt {
	pkt := &caidaPkt{}
	captureInfo := &packet.Metadata().CaptureInfo
	pkt.Duration = captureInfo.Timestamp.Sub(time.Unix(0, 0))
	pkt.Size = uint32(captureInfo.Length)

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		//ip.SrcIP []byte (4 bytes)
		copy(pkt.Id[:4], ip.SrcIP[:4])
		//ip.DstIP []byte (4 bytes)
		copy(pkt.Id[4:8], ip.DstIP[:4])
		//ip.Protocol uint8 which is an alias for byte
		pkt.Id[8] = byte(ip.Protocol)
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		// tcp.SrcPort uint16
		pkt.Id[9] = byte(tcp.SrcPort >> 8)
		pkt.Id[10] = byte(tcp.SrcPort)
		// tcp.DstPort uint16
		pkt.Id[11] = byte(tcp.DstPort >> 8)
		pkt.Id[12] = byte(tcp.DstPort)
		tcpCounter++
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		pkt.Id[9] = byte(udp.SrcPort >> 8)
		pkt.Id[10] = byte(udp.SrcPort)
		// tcp.DstPort uint16
		pkt.Id[11] = byte(udp.DstPort >> 8)
		pkt.Id[12] = byte(udp.DstPort)
		udpCounter++
	}

	//note that this is about 0.04% of all packets of this trace
	if err := packet.ErrorLayer(); err != nil {
		errCounter++
		// fmt.Printf("Error decoding some part of the packet: %v\n", err)
	}
	// fmt.Println(pkt)

	return pkt
}

//parses the caida packet trace and writes the output to a binary file
func writeParsedTraceToBinary() {
	//open file
	f, err := os.Create("temp.dat")
	if err != nil {
		fmt.Println("os.Create failed:", err)
	}
	defer f.Close()

	//counter
	var pktCounter int

	//loop over trace
	var pkt *caidaPkt
	if handle, err := pcap.OpenOffline(filename); err != nil {
		panic(err)
	} else {
		var decoder gopacket.Decoder
		if handle.LinkType() == 12 {
    			decoder = layers.LayerTypeIPv4
		} else {
    			decoder = handle.LinkType()
		}
		packetSource := gopacket.NewPacketSource(handle, decoder)
		for packet := range packetSource.Packets() {
			pkt = handlePacket(packet)
			//write to binary file
			err = binary.Write(f, binary.LittleEndian, pkt)
			if err != nil {
				fmt.Println("binary.Write failed:", err)
			}
			if pktCounter < 10 {
				fmt.Println(pkt)
			}
			pktCounter++
		}
	}
	fmt.Printf("Total number of packets: %d\n", pktCounter)
	fmt.Printf("Total number of errors: %d\n", errCounter)
	fmt.Printf("Number of TCP over IPv4 packets: %d\n", tcpCounter)
	fmt.Printf("Number of UDP over IPv4 packets: %d\n", udpCounter)

	// //rewind file
	// f.Seek(0, 0)

	// //test read
	// pkt2 := &caidaPkt{}
	// for i := 0; i < 10; i++ {
	// 	err = binary.Read(f, binary.LittleEndian, pkt2)
	// 	if err != nil {
	// 		fmt.Println("binary.Read failed:", err)
	// 	}
	// 	fmt.Println(pkt2)
	// }
}

func main() {
	var totalProcTime time.Duration
	var tic time.Time
	//10Gbps = 1.25B/ns
	detector := eardet.NewEardetDtctr(500, 1000, 1.25)
	var flowID uint32
	pkt := &caidaPkt{}
	var set bool
	var temp time.Duration
	var max time.Duration = 0
	var min time.Duration = 9223372036854775807
	murmur3.ResetSeed()

	//open file
	f, err := os.Open("temp.dat")
	if err != nil {
		fmt.Println("os.Open failed:", err)
	}
	defer f.Close()

	for i := 0; i < numPkts; i++ {
		err = binary.Read(f, binary.LittleEndian, pkt)
		if err != nil {
			fmt.Println("binary.Read failed:", err)
		}
		//for testing
		// if i < 10 {
		// 	fmt.Println(pkt)
		// } else {
		// 	break
		// }

		if !set {
			detector.SetCurrentTime(pkt.Duration)
			set = true
		}
		flowID = murmur3.Murmur3_32_caida(&pkt.Id)
		tic = time.Now()
		res2 = detector.Detect(flowID, pkt.Size, pkt.Duration)
		temp = time.Since(tic)
		totalProcTime += temp
		if temp > max {
			max = temp
		} else if temp < min {
			min = temp
		}
	}
	fmt.Printf("Average time spend processing: %f ns.\n", float64(totalProcTime)/float64(numPkts))
	fmt.Printf("Longest processing time: %d ns, shortest %d ns\n", max, min)
}


