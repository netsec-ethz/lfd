package main

import (
    "fmt"
    // "os"
    // "bufio"
    "time"

    "github.com/hosslen/lfd/baseline"
    "github.com/hosslen/lfd/eardet"
    "github.com/hosslen/lfd/rlfd"
    "github.com/hosslen/lfd/murmur3"
    "github.com/hosslen/lfd/caida"
)

var (
    
)

func main() {

    // evaluation config:
    // TODO(hao): read from config file
    maxNumPkts := 10000
    pcapFilename := "../resource/10k-test-pkts.pcap"
    timesFilename := "../resource/10k-test-pkts.times"

    // link capacity
    p := float64(1.25) //10Gbps = 1.25B/ns

    // detector config
    ed_counter_num := uint32(128)
    // gamma_h := p / float64(ed_counter_num + 1)
    gamma_l := float64(p / 1000) // low-bandwidth threshold is flow spec
    beta_l := uint32(3008)       // low-bandwidth threshold is flow spec
    alpha := uint32(1504)
    // beta_th = uint32(5000)
    
    // flow spec:
    beta := float64(beta_l)
    gamma := float64(gamma_l)

    // RLFD time length for each level
    t_l := time.Duration(beta/gamma)

    trace := caida.LoadPCAPFile(pcapFilename, timesFilename, maxNumPkts)


    //FP and FN
    edFP := 0
    edFN := 0
    rdFP := 0
    rdFN := 0

    //damage metric
    edOveruseDamage := uint32(0)
    edFPDamage := uint32(0)
    rdOveruseDamage := uint32(0)
    rdFPDamage := uint32(0)

    //blacklists
    blackListED := make(map[uint32]int)
    blackListRD := make(map[uint32]int)
    blackListBD := make(map[uint32]int)

    //initialize detectors
    ed := eardet.NewConfigedEardetDtctr(
        ed_counter_num, alpha, beta_l, gamma_l, p)
    // TODO(hao): RLFD's setting could be wrong
    rd := rlfd.NewRlfdDtctr(uint32(beta), gamma, t_l)
    bd := baseline.NewBaselineDtctr(beta, gamma)
    ed.SetCurrentTime(trace.Packets[0].Duration)
    rd.SetCurrentTime(trace.Packets[0].Duration)

    var flowID uint32
    var pkt *caida.CaidaPkt
    murmur3.ResetSeed()
    var resED, resRD, resBD bool

    // traverse packets in the trace
    for i := 0; i < len(trace.Packets); i++ {
        pkt = trace.Packets[i]
        // TODO(hao): change to AES hash?
        flowID = murmur3.Murmur3_32_caida(&pkt.Id)
        
        // passing packet to EARDet
        if _, ok := blackListED[flowID]; !ok {
            resED = ed.Detect(flowID, pkt.Size, pkt.Duration)
        } else {
            resED = true
        }
        
        // passing packet to RLFD
        if _, ok := blackListRD[flowID]; !ok {
            resRD = rd.Detect(flowID, pkt.Size, pkt.Duration)
        } else {
            resRD = true
        }

        // passing packet to Baseline Detector
        if _, ok := blackListBD[flowID]; !ok {
            resBD = bd.Detect(flowID, pkt.Size, pkt.Duration)
        } else {
            resBD = true
        }

        if resED {blackListED[flowID]++}
        if resRD {blackListRD[flowID]++}
        if resBD {blackListBD[flowID]++}

        //damage metric
        if resBD {
            if !resED {edOveruseDamage += pkt.Size}
            if !resRD {rdOveruseDamage += pkt.Size}
        } else {
            if resED {edFPDamage += pkt.Size}
            if resRD {rdFPDamage += pkt.Size}
        }
    }

    //compare blacklists
    // FPs
    for k, _ := range blackListED {
        if _, ok := blackListBD[k]; !ok {
            edFP++
        } 
    }
    for k, _ := range blackListRD {
        if _, ok := blackListBD[k]; !ok {
            rdFP++
        } 
    }

    // FNs
    for k, _ := range blackListBD {
        if _, ok := blackListED[k]; !ok {
            edFN++
        }
        if _, ok := blackListRD[k]; !ok {
            rdFN++
        }
    }




    fmt.Printf(
        "Evaluation over trace:\n" +
            "\tpcapFilename=%s\n" +
            "\ttimesFilename=%s\n",
        pcapFilename, timesFilename)
    fmt.Printf("Link capacity: p=%fB/ns\n", p)
    fmt.Printf("Flow spec: gamma=%f, beta=%f", gamma, beta)
    fmt.Printf("Seed for murmur3: %d\n", murmur3.GetSeed())
    // fmt.Printf("Baseline: gamma=%f, beta=%f\n", gamma, beta)
    
    fmt.Printf("\n========EARDet========\n")
    fmt.Printf(
        "Config: alpha=%d, gamma_l=%f, beta_l=%d, " +
            "gamma_h=%f, beta_h=%d, beta_th=%d\n",
        ed.GetAlpha(), ed.GetGamma_l(), ed.GetBeta_l(),
        ed.GetGamma_h(), ed.GetBeta_h(), ed.GetBeta_th())
    fmt.Printf("Number of flows: %d\n", bd.NumFlows)
    fmt.Printf("Number of flows detected by baseline: %d\n", len(blackListBD))
    fmt.Printf("Number of flows detected by EARDet: %d\n", len(blackListED))
    fmt.Printf("FP (flows): %d FN (flows): %d\n", edFP, edFN)
    fmt.Printf("overuseDamage: %dB, falsePositiveDamage: %dB\n",
        edOveruseDamage, edFPDamage)
    
    fmt.Printf("\n========Single RLFD========\n")
    fmt.Printf("Config: t_l=%d, th=%d, depth=%d, fanout=%d",
        rd.GetT_l(), rd.GetTh(), rd.GetDepth(), rd.GetNumCountersPerNode())
    fmt.Printf("Number of flows: %d\n", bd.NumFlows)
    fmt.Printf("Number of flows detected by baseline: %d\n", len(blackListBD))
    fmt.Printf("Number of flows detected by RLFD: %d\n", len(blackListRD))
    fmt.Printf("FP (flows): %d FN (flows): %d\n", rdFP, rdFN)
    fmt.Printf("overuseDamage: %dB, falsePositiveDamage: %dB\n",
        rdOveruseDamage, rdFPDamage)



    // fmt.Printf("Hello, world.\n")
    // f, err := os.Open("/Users/haowu/Desktop/codes/dp.py")

    // if err != nil {
    //     fmt.Println(err)        
    // } else {

    //     scanner := bufio.NewScanner(f)
    //     for scanner.Scan() {
    //         fmt.Println(scanner.Text())
    //     }

    //     f.Seek(0, 0)
    //     scanner = bufio.NewScanner(f)
    //     for scanner.Scan() {
    //         fmt.Println(scanner.Text())
    //     }
    //     f.Close()
    // }
}