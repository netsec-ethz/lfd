package caida

import (
    "encoding/binary"
    "fmt"
    "os"
    "bufio"
    "testing"
    "time"
    "unsafe"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"

    "github.com/hosslen/lfd/baseline"
    "github.com/hosslen/lfd/eardet"
    "github.com/hosslen/lfd/murmur3"
    "github.com/hosslen/lfd/rlfd"
    "github.com/hosslen/lfd/clef"

    "github.com/stretchr/testify/assert"
)

var (
    //to prevent too much optimization
    res bool

    //parameters for
    //TH_l(t) = gamma_l*t + beta_l
    //TH_h(t) = gamma_h*t + beta_h
    //beta_th = ((beta_l + (gamma_l * (alpha + beta_l)) / (linkCapacity / (numOfCounters + 1) - gamma_l)) + 1;
    //beta_h = alpha + 2*beta_th
    //gamma_h > p / (n + 1) = p / 129
    p = float64(1.25) //10Gbps = 1.25B/ns
    ed_counter_num = uint32(128)
    gamma_h = p / float64(ed_counter_num + 1)
    gamma_l = float64(p / 1000) // low-bandwidth threshold is flow spec
    beta_l = uint32(3008)       // low-bandwidth threshold is flow spec
    alpha = uint32(1504)
    // beta_th = uint32(5000)
    
    // flow spec:
    beta = float64(beta_l)
    gamma = float64(gamma_l)
    t_l = time.Duration(beta/gamma)

    // trace for testing
    trace *TraceData
    pcapFilename = "../resource/10k-test-pkts.pcap"
    timesFilename = "../resource/10k-test-pkts.times"
    maxNumPkts = 10000
    pktNumInBinary int     // number of packets written into the binary file

    maxWatchlistSize = uint32(512)
)

//to test if it compiles ...
func TestDoNothing(t *testing.T) {
    fmt.Println("Do nothing ...")
}

//parses the trace file specified in caida.go and writes the caidaPkts to a binary file
func TestWriteParsedTraceToBinary(t *testing.T) {
    // This test is required to run at very beginning to ensure
    // the binary file has been generated
    // write binary file in temp.dat
    pktNumInBinary = writeParsedTraceToBinary(pcapFilename, timesFilename)
}

func TestPacketTimestamp(t *testing.T) {
    // load packets with nanosecond timestamps from timesFilename
    if trace == nil {
        trace = loadPCAPFile(pcapFilename, timesFilename, maxNumPkts)
    }

    // load packets with microsecond timestamps from pcapFilename
    pcapHandle, pcapErr := pcap.OpenOffline(pcapFilename);

    if pcapErr != nil {
        fmt.Printf("Failed to open pcap file: %v\n", pcapErr)
        os.Exit(1)
    } else {
        var decoder gopacket.Decoder
        if pcapHandle.LinkType() == 12 {
            decoder = layers.LayerTypeIPv4
        } else {
            decoder = pcapHandle.LinkType()
        }
        packetSource := gopacket.NewPacketSource(pcapHandle, decoder)
        var count = 0
        for packet := range packetSource.Packets() {
            captureInfo := &packet.Metadata().CaptureInfo
            msTime := captureInfo.Timestamp.Sub(time.Unix(0, 0))

            truncatedNanoTime :=
                trace.packets[count].Duration.Nanoseconds() / 1000
            microTime := msTime.Nanoseconds() / 1000
            // verify the timestamps from timesFilename is aligned with
            // those from pcapFilename
            assert.Equal(t, microTime, truncatedNanoTime)
            // fmt.Printf("%d | %d\n", microTime, truncatedNanoTime)

            count++
            if count >= maxNumPkts {break}
        }
    }

}

//measure detection performance of the EARDet detector against the baseline detector
func TestEARDetPerformanceAgainstBaseline(t *testing.T) {
    //FP and FN
    falsePositives := 0
    falseNegatives := 0

    //damage metric
    overuseDamage := uint32(0)
    falsePositiveDamage := uint32(0)

    //blacklists
    blackListED := make(map[uint32]int)
    blackListBD := make(map[uint32]int)

    //initialize detectors
    ed := eardet.NewConfigedEardetDtctr(
        ed_counter_num, alpha, beta_l, gamma_l, p)
    bd := baseline.NewBaselineDtctr(beta, gamma)

    //initialize packets
    if trace == nil {
        trace = loadPCAPFile(pcapFilename, timesFilename, maxNumPkts)
    }

    var flowID uint32
    var pkt *caidaPkt
    murmur3.ResetSeed()
    ed.SetCurrentTime(trace.packets[0].Duration)
    var resED, resBD bool
    for i := 0; i < len(trace.packets); i++ {
        pkt = trace.packets[i]
        flowID = murmur3.Murmur3_32_caida(&pkt.Id)
        if _, ok := blackListED[flowID]; !ok {
            resED = ed.Detect(flowID, pkt.Size, pkt.Duration)
        } else {
            resED = true
        }
        if _, ok := blackListBD[flowID]; !ok {
            resBD = bd.Detect(flowID, pkt.Size, pkt.Duration)
        } else {
            resBD = true
        }

        //update blacklists
        if resED {
            blackListED[flowID]++
        }
        if resBD {
            blackListBD[flowID]++
        }

        //damage metric
        if resBD && !resED {
            overuseDamage += pkt.Size
        } else if !resBD && resED {
            falsePositiveDamage += pkt.Size
        }
    }

    //compare blacklists
    for k, _ := range blackListED {
        if _, ok := blackListBD[k]; !ok {
            falsePositives++
        } 
    }
    for k, _ := range blackListBD {
        if _, ok := blackListED[k]; !ok {
            falseNegatives++
        } 
    }
    fmt.Printf("TestEARDetPerformanceAgainstBaseline:\n")
    fmt.Printf("eardetDtctr: alpha=%d, gamma_l=%d, beta_l=%d, gamma_h=%d, beta_h=%d, beta_th=%d, p=%fB/ns\n",
                ed.GetAlpha, ed.GetGamma_l, ed.GetBeta_l,
                ed.GetGamma_h, ed.GetBeta_h, ed.GetBeta_th, p)
    fmt.Printf("baselineDtctr: beta=%f, gamma=%f\n", beta, gamma)
    fmt.Printf("Seed for murmur3: %d\n", murmur3.GetSeed())
    fmt.Printf("Number of flows: %d\n", bd.NumFlows)
    fmt.Printf("Number of flows detected by baseline: %d\n", len(blackListBD))
    fmt.Printf("Number of flows detected by eardet: %d\n", len(blackListED))
    fmt.Printf("FP (flows): %d FN (flows): %d\n", falsePositives, falseNegatives)
    fmt.Printf("overuseDamage: %dB, falsePositiveDamage: %dB\n", overuseDamage, falsePositiveDamage)
}

//measure detection performance of the RLFD detector against the baseline detector
func TestRLFDPerformanceAgainstBaseline(t *testing.T) {
    //FP and FN
    falsePositives := 0
    falseNegatives := 0

    //damage metric
    overuseDamage := uint32(0)
    falsePositiveDamage := uint32(0)

    //blacklists
    blackListRD := make(map[uint32]int)
    blackListBD := make(map[uint32]int)

    //initialize detectors
    rd := rlfd.NewRlfdDtctr(uint32(beta), gamma, t_l)
    bd := baseline.NewBaselineDtctr(beta, gamma)

    //initialize packets
    if trace == nil {
        trace = loadPCAPFile(pcapFilename, timesFilename, maxNumPkts)
    }

    var flowID uint32
    var pkt *caidaPkt
    murmur3.ResetSeed()
    rd.SetCurrentTime(trace.packets[0].Duration)
    var resRD, resBD bool
    for i := 0; i < len(trace.packets); i++ {
        pkt = trace.packets[i]
        flowID = murmur3.Murmur3_32_caida(&pkt.Id)
        if _, ok := blackListRD[flowID]; !ok {
            resRD = rd.Detect(flowID, pkt.Size, pkt.Duration)
        } else {
            resRD = true
        }
        if _, ok := blackListBD[flowID]; !ok {
            resBD = bd.Detect(flowID, pkt.Size, pkt.Duration)
        } else {
            resBD = true
        }

        //update blacklists
        if resRD {
            blackListRD[flowID]++
        }
        if resBD {
            blackListBD[flowID]++
        }

        //damage metric
        if resBD && !resRD {
            overuseDamage += pkt.Size
        } else if !resBD && resRD {
            falsePositiveDamage += pkt.Size
        }
    }

    //compare blacklists
    for k, _ := range blackListRD {
        if _, ok := blackListBD[k]; !ok {
            falsePositives++
        } 
    }
    for k, _ := range blackListBD {
        if _, ok := blackListRD[k]; !ok {
            falseNegatives++
        } 
    }
    fmt.Printf("TestRLFDPerformanceAgainstBaseline:\n")
    fmt.Printf("rlfdDtctr: beta=%fB, gamma=%fB/ns\n", beta, gamma)
    fmt.Printf("baselineDtctr: beta=%fB, gamma=%fB/ns\n", beta, gamma)
    fmt.Printf("Seed for murmur3: %d\n", murmur3.GetSeed())
    fmt.Printf("Number of flows: %d\n", bd.NumFlows)
    fmt.Printf("Number of flows detected by baseline: %d\n", len(blackListBD))
    fmt.Printf("Number of flows detected by rlfd: %d\n", len(blackListRD))
    fmt.Printf("FP (flows): %d FN (flows): %d\n", falsePositives, falseNegatives)
    fmt.Printf("overuseDamage: %dB, falsePositiveDamage: %dB\n", overuseDamage, falsePositiveDamage)
}

//measure detection performance of the CLEF detector against the baseline detector
func TestCLEFPerformanceAgainstBaseline(t *testing.T) {

    //FP and FN
    falsePositives := 0
    falseNegatives := 0

    //damage metric in Byte
    overuseDamage := uint32(0)
    falsePositiveDamage := uint32(0)

    //blacklists
    blackListRD := make(map[complex128]int)
    blackListBD := make(map[complex128]int)

    //initialize detectors
    eardet := eardet.NewConfigedEardetDtctr(ed_counter_num, alpha, beta_l, gamma_l, p)
    rlfd1 := rlfd.NewRlfdDtctr(uint32(beta), gamma, t_l)
    rlfd2 := rlfd.NewRlfdDtctr(uint32(beta), gamma, t_l)
    cd := clef.NewClefDtctr(eardet, rlfd1, rlfd2, t_l, gamma, beta, maxWatchlistSize)
    bd := baseline.NewBaselineDtctr(beta, gamma)

    //initialize packets
    if trace == nil {
        trace = loadPCAPFile(pcapFilename, maxNumPkts)
    }

    var pkt *caidaPkt
    var flowID complex128
    murmur3.ResetSeed()

    cd.SetCurrentTime(trace.packets[0].Duration)
    var resCD, resBD bool
    for i := 0; i < len(trace.packets); i++ {
        pkt = trace.packets[i]
        flowID = *((*complex128) (unsafe.Pointer(&pkt.Id)))
        if _, ok := blackListRD[flowID]; !ok {
            resCD = cd.Detect(&pkt.Id, pkt.Size, pkt.Duration)
        } else {
            resCD = true
        }
        if _, ok := blackListBD[flowID]; !ok {
            //TODO: Change this
            resBD = bd.Detect(0, pkt.Size, pkt.Duration)
        } else {
            resBD = true
        }

        //update blacklists
        if resCD {
            blackListRD[flowID]++
        }
        if resBD {
            blackListBD[flowID]++
        }

        //damage metric
        if resBD && !resCD {
            overuseDamage += pkt.Size
        } else if !resBD && resCD {
            falsePositiveDamage += pkt.Size
        }
    }

    //compare blacklists
    for k, _ := range blackListRD {
        if _, ok := blackListBD[k]; !ok {
            falsePositives++
        } 
    }
    for k, _ := range blackListBD {
        if _, ok := blackListRD[k]; !ok {
            falseNegatives++
        } 
    }
    fmt.Printf("TestCLEFPerformanceAgainstBaseline:\n")
    fmt.Printf("clefDtctr: beta=%fB, gamma=%fB/ns\n", beta, gamma)
    fmt.Printf("baselineDtctr: beta=%fB, gamma=%fB/ns\n", beta, gamma)
    fmt.Printf("Seed for murmur3: %d\n", murmur3.GetSeed())
    fmt.Printf("Number of flows: %d\n", bd.NumFlows)
    fmt.Printf("Number of flows detected by baseline: %d\n", len(blackListBD))
    fmt.Printf("Number of flows detected by clef: %d\n", len(blackListRD))
    fmt.Printf("FP (flows): %d FN (flows): %d\n", falsePositives, falseNegatives)
    fmt.Printf("overuseDamage: %dB, falsePositiveDamage: %dB\n", overuseDamage, falsePositiveDamage)
}

//count the hash collisions
func TestForHashCollisions(t *testing.T) {
    //initialize packets
    if trace == nil {
        trace = loadPCAPFile(pcapFilename, timesFilename, maxNumPkts)
    }

    myMap := make(map[uint32]([]string))

    var flowID uint32
    var bucket []string
    var pkt *caidaPkt
    murmur3.ResetSeed()
    for i := 0; i < len(trace.packets); i++ {
        pkt = trace.packets[i]
        flowID = murmur3.Murmur3_32_caida(&pkt.Id)
        bucket = myMap[flowID]
        if bucket == nil {
            bucket = make([]string, 0)
            myMap[flowID] = bucket
        }
        //append if not equal
        temp := string(pkt.Id[:])
        b := false
        for _, s := range bucket {
            if s == temp {
                b = true
            }
        }
        if !b {
            myMap[flowID] = append(bucket, temp)
        }
    }

    colCounter := 0
    for k, v := range myMap {
        if len(v) > 1 {
            fmt.Printf("%d: %d\n", k, len(v))
            colCounter++
        }
    }
    fmt.Printf("Collisions: %d\n", colCounter)
    fmt.Printf("Seed for murmur3: %d\n", murmur3.GetSeed())
}

///////////////////////////////////////////////////////////////////////////////////////////
//////Benchmark EARDet and Baseline detector with binary file /////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////
func BenchmarkEARDetWithTraceMemoryLowBinary(b *testing.B) {
    //10Gbps = 1.25B/ns
    detector := eardet.NewConfigedEardetDtctr(
        ed_counter_num, alpha, beta_l, gamma_l, p)
    var flowID uint32
    pkt := &caidaPkt{}
    var set bool
    murmur3.ResetSeed()

    //open file
    f, err := os.Open("temp.dat")
    if err != nil {
        fmt.Println("os.Open failed:", err)
    }
    defer f.Close()

    b.StopTimer()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        err = binary.Read(f, binary.LittleEndian, pkt)
        if err != nil {
            if err.Error() == "EOF" {
                // if file is ended, rewind and performa again
                f.Seek(0, 0)
                binary.Read(f, binary.LittleEndian, pkt)
                detector.SetCurrentTime(pkt.Duration)
            } else {
                fmt.Println("binary.Read failed:", err)
            }
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
        b.StartTimer()
        res = detector.Detect(flowID, pkt.Size, pkt.Duration)
        b.StopTimer()
    }
}

func BenchmarkBaselineWithTraceMemoryLowBinary(b *testing.B) {
    //10Gbps = 1.25B/ns
    detector := baseline.NewBaselineDtctr(beta, gamma)
    var flowID uint32
    pkt := &caidaPkt{}
    murmur3.ResetSeed()

    //open file
    f, err := os.Open("temp.dat")
    if err != nil {
        fmt.Println("os.Open failed:", err)
    }
    defer f.Close()

    b.StopTimer()
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        err = binary.Read(f, binary.LittleEndian, pkt)
        if err != nil {
            if err.Error() == "EOF" {
                // if file is ended, rewind and performa again
                f.Seek(0, 0)
                binary.Read(f, binary.LittleEndian, pkt)
            } else {
                fmt.Println("binary.Read failed:", err)
            }
        }
        //for testing
        // if i < 10 {
        //  fmt.Println(pkt)
        // } else {
        //  break
        // }

        flowID = murmur3.Murmur3_32_caida(&pkt.Id)
        b.StartTimer()
        res = detector.Detect(flowID, pkt.Size, pkt.Duration)
        b.StopTimer()
    }
}

func TestEARDetWithTraceMemoryLowBinary(t *testing.T) {
    var totalProcTime time.Duration
    var tic time.Time
    //10Gbps = 1.25B/ns
    detector := eardet.NewConfigedEardetDtctr(
        ed_counter_num, alpha, beta_l, gamma_l, p)
    var flowID uint32
    pkt := &caidaPkt{}
    var set bool
    var temp time.Duration
    var max time.Duration = 0
    var min time.Duration = 9223372036854775807
    murmur3.ResetSeed()

    //open file
    // TODO: this test depends one the TestWriteParsedTraceToBinary
    // which is not good.
    f, err := os.Open("temp.dat")
    if err != nil {
        fmt.Println("os.Open failed:", err)
    }
    defer f.Close()

    for i := 0; i < pktNumInBinary; i++ {
        err = binary.Read(f, binary.LittleEndian, pkt)
        if err != nil {
            fmt.Println("binary.Read failed:", err)
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
        res = detector.Detect(flowID, pkt.Size, pkt.Duration)
        temp = time.Since(tic)
        totalProcTime += temp
        if temp > max {
            max = temp
        } else if temp < min {
            min = temp
        }
    }
    fmt.Printf("Average time spend processing: %f ns.\n",
        float64(totalProcTime)/float64(pktNumInBinary))
    fmt.Printf("Longest processing time: %d ns, shortest %d ns\n", max, min)
}

func TestBaselinetWithTraceMemoryLowBinary(t *testing.T) {
    var totalProcTime time.Duration
    var tic time.Time
    //10Gbps = 1.25B/ns
    detector := baseline.NewBaselineDtctr(beta, gamma)
    var flowID uint32
    pkt := &caidaPkt{}
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

    for i := 0; i < pktNumInBinary; i++ {
        err = binary.Read(f, binary.LittleEndian, pkt)
        if err != nil {
            fmt.Println("binary.Read failed:", err)
        }
        //for testing
        // if i < 10 {
        //  fmt.Println(pkt)
        // } else {
        //  break
        // }

        flowID = murmur3.Murmur3_32_caida(&pkt.Id)
        tic = time.Now()
        res = detector.Detect(flowID, pkt.Size, pkt.Duration)
        temp = time.Since(tic)
        totalProcTime += temp
        if temp > max {
            max = temp
        } else if temp < min {
            min = temp
        }
    }
    fmt.Printf("Average time spent processing a packet: %f ns.\n", float64(totalProcTime)/float64(pktNumInBinary))
    fmt.Printf("Longest processing time: %d ns, shortest %d ns\n", max, min)
}


///////////////////////////////////////////////////////////////////////////////////////////
//////Benchmark EARDet and Baseline directly with caida trace /////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////

func TestEARDetWithTraceMemoryLowDirect(t *testing.T) {
    var totalProcTime time.Duration
    var tic time.Time
    //10Gbps = 1.25B/ns
    detector := eardet.NewConfigedEardetDtctr(
        ed_counter_num, alpha, beta_l, gamma_l, p)
    var flowID uint32
    var pkt *caidaPkt
    var set bool
    var temp time.Duration
    var max time.Duration = 0
    var min time.Duration = 9223372036854775807
    murmur3.ResetSeed()

    //test
    loopOverPCAPFile(
        pcapFilename,
        timesFilename, 
        func(packet gopacket.Packet, pktTime time.Duration) bool {
            pkt = convertToCaidaPkt(&TraceData{}, packet, pktTime)
            if !set {
                detector.SetCurrentTime(pkt.Duration)
                set = true
            }
            flowID = murmur3.Murmur3_32_caida(&pkt.Id)
            tic = time.Now()
            res = detector.Detect(flowID, pkt.Size, pkt.Duration)
            temp = time.Since(tic)
            totalProcTime += temp
            if temp > max {
                max = temp
            } else if temp < min {
                min = temp
            }
            return true
        })

    fmt.Printf("Average time spend processing: %f ns.\n", float64(totalProcTime)/float64(pktNumInBinary))
    fmt.Printf("Longest processing time: %d ns, shortest %d ns\n", max, min)
}

func TestBaselineWithTraceMemoryLowDirect(t *testing.T) {
    var totalProcTime time.Duration
    var tic time.Time
    //10Gbps = 1.25B/ns
    detector := baseline.NewBaselineDtctr(beta, gamma)
    var flowID uint32
    var pkt *caidaPkt
    var temp time.Duration
    var max time.Duration = 0
    var min time.Duration = 9223372036854775807
    murmur3.ResetSeed()

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
            pktTime, _ := time.ParseDuration(timesScanner.Text() + "s")

            pkt = convertToCaidaPkt(&TraceData{}, packet, pktTime)

            flowID = murmur3.Murmur3_32_caida(&pkt.Id)
            tic = time.Now()
            res = detector.Detect(flowID, pkt.Size, pkt.Duration)
            temp = time.Since(tic)
            totalProcTime += temp
            if temp > max {
                max = temp
            } else if temp < min {
                min = temp
            }
        }
    }
    fmt.Printf("Average time spend processing: %f ns.\n", float64(totalProcTime)/float64(pktNumInBinary))
    fmt.Printf("Longest processing time: %d ns, shortest %d ns\n", max, min)
}

///////////////////////////////////////////////////////////////////////////////////////////
//////Benchmark EARDet and Baseline detector with loaded trace ////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////

func BenchmarkWithTraceLoadedBaseline(b *testing.B) {
    //initialize packets
    if trace == nil {
        trace = loadPCAPFile(pcapFilename, timesFilename, maxNumPkts)
    }
    //10Gbps = 1.25B/ns
    detector := baseline.NewBaselineDtctr(beta, gamma)
    var flowID uint32
    var pkt *caidaPkt
    murmur3.ResetSeed()
    if (maxNumPkts < b.N) {
        fmt.Printf("Warning: Not enough packets in the trace, benchmark might be inaccurate!")
    }

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        pkt = trace.packets[i % maxNumPkts]
        flowID = murmur3.Murmur3_32_caida(&pkt.Id)
        res = detector.Detect(flowID, pkt.Size, pkt.Duration)
    }
}

func BenchmarkWithTraceLoadedEARDet(b *testing.B) {
    //initialize packets
    if trace == nil {
        trace = loadPCAPFile(pcapFilename, timesFilename, maxNumPkts)
    }
    //10Gbps = 1.25B/ns
    detector := eardet.NewConfigedEardetDtctr(
        ed_counter_num, alpha, beta_l, gamma_l, p)
    var flowID uint32
    var pkt *caidaPkt
    murmur3.ResetSeed()
    detector.SetCurrentTime(trace.packets[0].Duration)
    if (maxNumPkts < b.N) {
        fmt.Printf("Warning: Not enough packets in the trace, benchmark might be inaccurate!")
    }

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        pkt = trace.packets[i % maxNumPkts]
        flowID = murmur3.Murmur3_32_caida(&pkt.Id)
        res = detector.Detect(flowID, pkt.Size, pkt.Duration)
    }
}

func BenchmarkWithTraceLoadedRlfd(b *testing.B) {
    //initialize packets
    if trace == nil {
        trace = loadPCAPFile(pcapFilename, timesFilename, maxNumPkts)
    }
    detector := rlfd.NewRlfdDtctr(uint32(beta), gamma, 100)
    var flowID uint32
    var pkt *caidaPkt
    murmur3.ResetSeed()
    detector.SetCurrentTime(trace.packets[0].Duration)
    if (maxNumPkts < b.N) {
        fmt.Printf("Warning: Not enough packets in the trace, benchmark might be inaccurate!")
    }

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        pkt = trace.packets[i % maxNumPkts]
        flowID = murmur3.Murmur3_32_caida(&pkt.Id)
        res = detector.Detect(flowID, pkt.Size, pkt.Duration)
    }
}




