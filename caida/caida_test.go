package caida

import (
	"encoding/binary"
	"fmt"
	"os"
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
)

var (
	//to prevent too much optimization
	res bool

	//parameters for
	//TH_l(t) = gamma_l*t + beta_l
	//TH_h(t) = gamma_h*t + beta_h
	//beta_h = alpha + 2*beta_th
	//gamma_h > p / (n + 1) = p / 129
	p = float32(1.25) //10Gbps = 1.25B/ns
	alpha = uint32(1504)
	beta_th = uint32(5000)
	beta = float64(alpha + 2*beta_th)
	gamma = float64(p / 129.0)
	t_l = time.Duration(beta/gamma)
)

//to test if it compiles ...
func TestDoNothing(t *testing.T) {
	fmt.Println("Do nothing ...")
}

//parses the trace file specified in caida.go and writes the caidaPkts to a binary file
func TestWriteParsedTraceToBinary(t *testing.T) {
	writeParsedTraceToBinary()
    if !packetsInitialized {
        resetCounters()
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
	ed := eardet.NewEardetDtctr(alpha, beta_th, p)
	bd := baseline.NewBaselineDtctr(beta, gamma)

	//initialize packets
	if !packetsInitialized {
        fmt.Println("bp1")
		loadPCAPFile()	
	}
    fmt.Println(packets)

	var flowID uint32
	var pkt *caidaPkt
	murmur3.ResetSeed()
	ed.SetCurrentTime(packets[0].Duration)
	var resED, resBD bool
	for i := 0; i < len(packets); i++ {
		pkt = packets[i]
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
	fmt.Printf("eardetDtctr: alpha=%d, beta_th=%d, p=%fB/ns\n", alpha, beta_th, p)
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
	rd := rlfd.NewRlfdDtctr(uint32(beta), uint32(gamma), t_l)
	bd := baseline.NewBaselineDtctr(beta, gamma)

	//initialize packets
	if !packetsInitialized {
		loadPCAPFile()	
	}

	var flowID uint32
	var pkt *caidaPkt
	murmur3.ResetSeed()
	rd.SetCurrentTime(packets[0].Duration)
	var resRD, resBD bool
	for i := 0; i < len(packets); i++ {
		pkt = packets[i]
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
	cd := clef.NewClefDtctr(p, alpha, beta_th, uint32(beta), uint32(gamma), t_l)
	bd := baseline.NewBaselineDtctr(beta, gamma)

	//initialize packets
	if !packetsInitialized {
		loadPCAPFile()	
	}

	var pkt *caidaPkt
	var flowID complex128
	cd.SetCurrentTime(packets[0].Duration)
	var resCD, resBD bool
	for i := 0; i < len(packets); i++ {
		pkt = packets[i]
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
	fmt.Printf("Number of flows detected by rlfd: %d\n", len(blackListRD))
	fmt.Printf("FP (flows): %d FN (flows): %d\n", falsePositives, falseNegatives)
	fmt.Printf("overuseDamage: %dB, falsePositiveDamage: %dB\n", overuseDamage, falsePositiveDamage)
}

//count the hash collisions
func TestForHashCollisions(t *testing.T) {
	//initialize packets
	if !packetsInitialized {
		loadPCAPFile()	
	}
	myMap := make(map[uint32]([]string))

	var flowID uint32
	var bucket []string
	var pkt *caidaPkt
	murmur3.ResetSeed()
	for i := 0; i < len(packets); i++ {
		pkt = packets[i]
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
	detector := eardet.NewEardetDtctr(alpha, beta_th, p)
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
			fmt.Println("binary.Read failed:", err)
		}
		//for testing
		// if i < 10 {
		// 	fmt.Println(pkt)
		// } else {
		// 	break
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
	detector := eardet.NewEardetDtctr(alpha, beta_th, p)
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
		res = detector.Detect(flowID, pkt.Size, pkt.Duration)
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
	fmt.Printf("Average time spent processing a packet: %f ns.\n", float64(totalProcTime)/float64(numPkts))
	fmt.Printf("Longest processing time: %d ns, shortest %d ns\n", max, min)
}


///////////////////////////////////////////////////////////////////////////////////////////
//////Benchmark EARDet and Baseline directly with caida trace /////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////

func TestEARDetWithTraceMemoryLowDirect(t *testing.T) {
	var totalProcTime time.Duration
	var tic time.Time
	//10Gbps = 1.25B/ns
	detector := eardet.NewEardetDtctr(alpha, beta_th, p)
	var flowID uint32
	var pkt *caidaPkt
	var set bool
	var temp time.Duration
	var max time.Duration = 0
	var min time.Duration = 9223372036854775807
	murmur3.ResetSeed()

	//test
	loopOverPCAPFile(filename, func(packet gopacket.Packet) {
			pkt = convertToCaidaPkt(packet)
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
		})

	fmt.Printf("Average time spend processing: %f ns.\n", float64(totalProcTime)/float64(numPkts))
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
			pkt = convertToCaidaPkt(packet)
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
	fmt.Printf("Average time spend processing: %f ns.\n", float64(totalProcTime)/float64(numPkts))
	fmt.Printf("Longest processing time: %d ns, shortest %d ns\n", max, min)
}

///////////////////////////////////////////////////////////////////////////////////////////
//////Benchmark EARDet and Baseline detector with loaded trace ////////////////////////////
///////////////////////////////////////////////////////////////////////////////////////////

func BenchmarkWithTraceLoadedBaseline(b *testing.B) {
	//initialize packets
	if !packetsInitialized {
		loadPCAPFile()	
	}
	//10Gbps = 1.25B/ns
	detector := baseline.NewBaselineDtctr(beta, gamma)
	var flowID uint32
	var pkt *caidaPkt
	murmur3.ResetSeed()
	if (numPkts < b.N) {
		fmt.Printf("Warning: Not enough packets in the trace, benchmark might be inaccurate!")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt = packets[i % numPkts]
		flowID = murmur3.Murmur3_32_caida(&pkt.Id)
		res = detector.Detect(flowID, pkt.Size, pkt.Duration)
	}
}

func BenchmarkWithTraceLoadedEARDet(b *testing.B) {
	//initialize packets
	if !packetsInitialized {
		loadPCAPFile()	
	}
	//10Gbps = 1.25B/ns
	detector := eardet.NewEardetDtctr(alpha, beta_th, p)
	var flowID uint32
	var pkt *caidaPkt
	murmur3.ResetSeed()
	detector.SetCurrentTime(packets[0].Duration)
	if (numPkts < b.N) {
		fmt.Printf("Warning: Not enough packets in the trace, benchmark might be inaccurate!")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt = packets[i % numPkts]
		flowID = murmur3.Murmur3_32_caida(&pkt.Id)
		res = detector.Detect(flowID, pkt.Size, pkt.Duration)
	}
}

func BenchmarkWithTraceLoadedRlfd(b *testing.B) {
	//initialize packets
	if !packetsInitialized {
		loadPCAPFile()	
	}
	detector := rlfd.NewRlfdDtctr(uint32(beta), uint32(gamma), 100)
	var flowID uint32
	var pkt *caidaPkt
	murmur3.ResetSeed()
	detector.SetCurrentTime(packets[0].Duration)
	if (numPkts < b.N) {
		fmt.Printf("Warning: Not enough packets in the trace, benchmark might be inaccurate!")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt = packets[i % numPkts]
		flowID = murmur3.Murmur3_32_caida(&pkt.Id)
		res = detector.Detect(flowID, pkt.Size, pkt.Duration)
	}
}




