//package for testing with the caida packet traces
package caida

import (
    "encoding/binary"
    "fmt"
    "os"
    "time"
    "bufio"
    "strings"
    "strconv"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"

    "github.com/hosslen/lfd/eardet"
    "github.com/hosslen/lfd/murmur3"
)

type TraceData struct {
    Packets [](*CaidaPkt)
    PacketsInitialized bool
    PacketCounter int
    ErrCounter int
    TcpCounter int
    UdpCounter int
}

type packetHandler func(packet gopacket.Packet, pktTime time.Duration) bool

//encapsulates the information of one "packet" of the caida trace file
type CaidaPkt struct {
    Duration time.Duration
    //SrcIP (4 bytes)| DstIP (4 bytes)| Protocol (1 byte)| PortNumSrc (2 bytes)| PortNumDst (2 bytes) | 0 (3 bytes)
    Id [16]byte
    Size uint32
}

// Create a TraceData instance
func newTraceData(maxNumPkts int) *TraceData {
    trace := &TraceData{}
    trace.Packets = make([](*CaidaPkt), maxNumPkts)
    trace.PacketsInitialized = false
    trace.PacketCounter = 0
    trace.ErrCounter = 0
    trace.TcpCounter = 0
    trace.UdpCounter = 0
    return trace
}

//prints out the counters
func printCounters(trace *TraceData) {
    fmt.Printf("Total number of packets: %d\n", trace.PacketCounter)
    fmt.Printf("Total number of errors: %d\n", trace.ErrCounter)
    fmt.Printf("Number of TCP over IPv4 packets: %d\n", trace.TcpCounter)
    fmt.Printf("Number of UDP over IPv4 packets: %d\n", trace.UdpCounter)
}

//loops over all packets in the pcap file
// timesFilename is the path of the file containing nanosecond timestamps
// for each packet. 
func loopOverPCAPFile(
        pcapFilename string, timesFilename string, myHandler packetHandler) {
    pcapHandle, pcapErr := pcap.OpenOffline(pcapFilename);
    timesHandle, timesErr := os.Open(timesFilename);

    if pcapErr != nil {
        fmt.Printf("Failed to open pcap file: %v\n", pcapErr)
        os.Exit(1)
    } else if timesErr != nil {
        fmt.Printf("Failed to open times file: %v\n", timesErr)
        os.Exit(1)
    } else {
        var decoder gopacket.Decoder
        if pcapHandle.LinkType() == 12 {
            decoder = layers.LayerTypeIPv4
        } else {
            decoder = pcapHandle.LinkType()
        }
        packetSource := gopacket.NewPacketSource(pcapHandle, decoder)
        timesScanner := bufio.NewScanner(timesHandle)
        for packet := range packetSource.Packets() {
            if !timesScanner.Scan() {
                // no time stamp to read
                fmt.Printf("Wrong trace files: timestamps are less" +
                    "than packets\n")
                os.Exit(1)
            }
            // timestamp with precision of nanosecond
            pktTime, _ := time.ParseDuration(timesScanner.Text() + "s")
            if !myHandler(packet, pktTime) {break}
        }
        timesHandle.Close()
    }
}

//converts a gopacket.Packet into a CaidaPkt
func convertToCaidaPkt(
        trace *TraceData,
        packet gopacket.Packet,
        pktTime time.Duration) *CaidaPkt {
    pkt := &CaidaPkt{}
    captureInfo := &packet.Metadata().CaptureInfo
    // pkt.Duration = captureInfo.Timestamp.Sub(time.Unix(0, 0))
    pkt.Duration = pktTime
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
        trace.TcpCounter++
    }

    if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
        udp, _ := udpLayer.(*layers.UDP)
        pkt.Id[9] = byte(udp.SrcPort >> 8)
        pkt.Id[10] = byte(udp.SrcPort)
        // tcp.DstPort uint16
        pkt.Id[11] = byte(udp.DstPort >> 8)
        pkt.Id[12] = byte(udp.DstPort)
        trace.UdpCounter++
    }

    //note that this is about 0.04% of all packets of this trace
    if err := packet.ErrorLayer(); err != nil {
        trace.ErrCounter++
        // fmt.Printf("Error decoding some part of the packet: %v\n", err)
    }
    // fmt.Println(pkt)

    return pkt
}

//loads the caida trace file into packets
func LoadPCAPFile(
        pcapFilename string, timesFilename string, maxNumPkts int) *TraceData{
    trace := newTraceData(maxNumPkts)
    loopOverPCAPFile(
        pcapFilename,
        timesFilename,
        func(packet gopacket.Packet, pktTime time.Duration) bool {
            trace.Packets[trace.PacketCounter] =
                convertToCaidaPkt(trace, packet, pktTime)
            trace.PacketCounter++
            
            if trace.PacketCounter >= len(trace.Packets) {
                // should break the loop, because packets is full
                return false
            }
            // can read the next packet
            return true   
        })

    trace.PacketsInitialized = true
    printCounters(trace)

    return trace
}

func LoadTxtTraceFile(txtTraceFilename string, maxNumPkts int) *TraceData{
    trace := newTraceData(maxNumPkts)
    file, err := os.Open(txtTraceFilename)
    if err != nil {
        fmt.Println(err)
    }
    defer file.Close()

    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        if trace.PacketCounter >= maxNumPkts { break }

        line := scanner.Text()
        strs := strings.Split(line, " ")
        flowId, _ := strconv.Atoi(strs[0])
        pktSize, _ := strconv.Atoi(strs[1])
        
        pkt := &CaidaPkt{}
        pkt.Duration, _ = time.ParseDuration(strs[2] + "s")
        pkt.Size = uint32(pktSize)
        
        bs := make([]byte, 4)
        binary.LittleEndian.PutUint32(bs, uint32(flowId))
        copy(pkt.Id[:4], bs)

        trace.Packets[trace.PacketCounter] = pkt
        trace.PacketCounter ++
        // fmt.Printf("%d, %d, %f\n", pkt.Id, pkt.Size, pkt.Duration)
    }
    trace.PacketsInitialized = true

    if err := scanner.Err(); err != nil {
        fmt.Println(err)
    }

    return trace
}

//parses the caida packet trace and writes the output to a binary file
func writeParsedTraceToBinary(
        pcapFilename string, timesFilename string) int {
    //open file
    f, err := os.Create("temp.dat")
    if err != nil {
        fmt.Printf("os.Create failed: %v\n", err)
        os.Exit(1)
    }
    defer f.Close()

    trace := newTraceData(0) // no need to store packets here
    //loop over trace
    loopOverPCAPFile(
        pcapFilename,
        timesFilename,
        func(packet gopacket.Packet, pktTime time.Duration) bool {
            pkt := convertToCaidaPkt(trace, packet, pktTime)
            //write to binary file
            err = binary.Write(f, binary.LittleEndian, pkt)
            if err != nil {
                fmt.Printf("binary.Write failed: %v\n", err)
                os.Exit(1)
            }
            if trace.PacketCounter < 10 {
                fmt.Println(pkt)
            }
            trace.PacketCounter++

            // can read and write the next packet
            return true
        })

    printCounters(trace)
    return trace.PacketCounter
    // //rewind file
    // f.Seek(0, 0)

    // //test read
    // pkt2 := &CaidaPkt{}
    // for i := 0; i < 10; i++ {
    //  err = binary.Read(f, binary.LittleEndian, pkt2)
    //  if err != nil {
    //      fmt.Println("binary.Read failed:", err)
    //  }
    //  fmt.Println(pkt2)
    // }
}


//////////////////Refractor////////////////////////////////

func test() {
    // TODO: What is this function for???

    var totalProcTime time.Duration
    var tic time.Time
    //10Gbps = 1.25B/ns
    detector := eardet.NewEardetDtctr(128, 500, 1000, 1.25)
    var flowID uint32
    pkt := &CaidaPkt{}
    var set bool
    var temp time.Duration
    var max time.Duration = 0
    var min time.Duration = 9223372036854775807
    murmur3.ResetSeed()

    //open file
    f, err := os.Open("temp.dat")
    if err != nil {
        fmt.Println("os.Open failed:", err)
        os.Exit(1)
    }
    defer f.Close()

    //TODO: temporarily put this variable here
    var numPkts = 1000
    for i := 0; i < numPkts; i++ {
        err = binary.Read(f, binary.LittleEndian, pkt)
        if err != nil {
            fmt.Println("binary.Read failed:", err)
            os.Exit(1)
        }

        //for testing
        // if i < 10 {
        //  fmt.Println(pkt)
        // } else {
        //  break
        // }

        if !set {
            detector.SetCurrentTime(pkt.Duration)
            set = true
        }
        flowID = murmur3.Murmur3_32_caida(&pkt.Id)
        tic = time.Now()
        // res2 = detector.Detect(flowID, pkt.Size, pkt.Duration)
        detector.Detect(flowID, pkt.Size, pkt.Duration) 
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


