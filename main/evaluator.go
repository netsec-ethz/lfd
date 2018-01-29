package main

import (
    "fmt"
    "time"
    "os"
    "encoding/json"
    "io/ioutil"
    "encoding/binary"

    "github.com/hosslen/lfd/baseline"
    "github.com/hosslen/lfd/slidingwindow"
    "github.com/hosslen/lfd/eardet"
    "github.com/hosslen/lfd/rlfd"
    "github.com/hosslen/lfd/clef"
    "github.com/hosslen/lfd/caida"
    "github.com/hosslen/lfd/aeshash"
    "github.com/hosslen/lfd/cuckoo"
)

const (
    NANO_SEC_PER_SEC = float64(1000000000.0)
    BASELINE_CONFIG_ID = "BASELINE"
    CLEF_CONFIG_ID = "CLEF"
    EARDet_CONFIG_ID = "EARDet"
    RLFD_CONFIG_ID = "RLFD"
)

type Dtctr interface {
    Detect(flowID uint32, size uint32, t time.Duration, ) bool
    GetBlacklist() *cuckoo.CuckooTable
    SetBlacklist(blacklist *cuckoo.CuckooTable)
}

type Config struct {
    ExpName string `json:"exp_name"`
    RunConfig struct {
        DetectorsToEvaluate []string `json:"detectors_to_evaluate"`
    } `json:"run_config"`
    TrafficConfig struct {
        LinkCapacity int `json:"link_capacity"`
        MaxPacketSize int `json:"max_pkt_size"`
        MaxPacketNum int `json:"max_pkt_num"`
        FlowSpecGamma int `json:"flow_spec_gamma"`
        FlowSpecBeta int `json:"flow_spec_beta"`
        PcapFile string `json:"pcap_file"`
        TimeFile string `json:"time_file"`
        TxtTraceFile string `json:"txt_trace_file"`
    } `json:"traffic_config"`
    EARDetConfig struct {
        GammaLow int `json:"gamma_low"`
        GammaHigh int `json:"gamma_high"`
        BetaLow int `json:"beta_low"`
    } `json:"eardet_config"`
    RLFDConfig struct {
        Gamma int `json:"gamma"`
        Beta int `json:"beta"`
        TlFactor float64 `json:"t_l_factor"`
    } `json:"RLFD_config"`
    CLEFConfig struct {
        AttackerFlowFactor float64 `json:"attacker_flow_factor"`
        MaxWatchlistSize uint32 `json:"max_watchlist_size"`
    } `json:"CLEF_config"`
}

func getConfig(jsonFilePath string) Config {
    raw, err := ioutil.ReadFile(jsonFilePath)
    if err != nil {
        fmt.Println(err.Error())
        os.Exit(1)
    }

    var config Config
    json.Unmarshal(raw, &config)
    return config
}

func main() {

    if len(os.Args) < 2 {
        fmt.Println("usage: go run evaluator.go <config_file_path>")
        os.Exit(1)
    }
    configFile := os.Args[1]
    config := getConfig(configFile)

    evalMap := map[string]bool {
        BASELINE_CONFIG_ID: true,
        EARDet_CONFIG_ID: false,
        RLFD_CONFIG_ID: false,
        CLEF_CONFIG_ID: false,
    }

    for _, detector_config_id := range config.RunConfig.DetectorsToEvaluate {
        evalMap[detector_config_id] = true
    }

    // evaluation config:
    maxPktNum := config.TrafficConfig.MaxPacketNum
    pcapFilename := config.TrafficConfig.PcapFile
    timesFilename := config.TrafficConfig.TimeFile
    txtTraceFilename := config.TrafficConfig.TxtTraceFile

    // link capacity 10Gbps = 1.25B/ns
    p := float64(config.TrafficConfig.LinkCapacity) / NANO_SEC_PER_SEC
    
    // flow spec:
    beta := float64(config.TrafficConfig.FlowSpecBeta)
    gamma := float64(config.TrafficConfig.FlowSpecGamma) / NANO_SEC_PER_SEC
    alpha := uint32(config.TrafficConfig.MaxPacketSize)

    // EARDet config
    ed_counter_num := uint32(
        config.TrafficConfig.LinkCapacity / config.EARDetConfig.GammaHigh - 1)
    // gamma_h := p / float64(ed_counter_num + 1)
    
    // low-bandwidth threshold is flow spec here
    ed_gamma_l := float64(config.EARDetConfig.GammaLow) / NANO_SEC_PER_SEC
    // low-bandwidth threshold is flow spec
    ed_beta_l := uint32(config.EARDetConfig.BetaLow)
    // high-bandwidth threshold
    ed_gamma_h :=float64(config.EARDetConfig.GammaHigh) / NANO_SEC_PER_SEC    
    
    // RLFD config
    // RLFD time length for each level
    rd_t_l := time.Duration(beta/gamma * config.RLFDConfig.TlFactor)
    rd_gamma := float64(config.RLFDConfig.Gamma) / NANO_SEC_PER_SEC
    rd_beta := uint32(config.RLFDConfig.Beta)

    var trace *caida.TraceData
    if pcapFilename != "" && timesFilename != "" {
        trace = caida.LoadPCAPFile(pcapFilename, timesFilename, maxPktNum)
    } else if txtTraceFilename != "" {
        trace = caida.LoadTxtTraceFile(txtTraceFilename, maxPktNum)
    } else {
        fmt.Println("Please provide a trace file either in pcap or txt")
        os.Exit(1)
    }

    //initialize detectors
    ed := eardet.NewConfigedEardetDtctr(
        ed_counter_num, alpha, ed_beta_l, ed_gamma_l, p)
    ed1 := eardet.NewConfigedEardetDtctr(
        ed_counter_num, alpha, ed_beta_l, ed_gamma_l, p)
    // TODO(hao): RLFD's setting could be wrong
    rd := rlfd.NewRlfdDtctr(rd_beta, rd_gamma, rd_t_l)
    // Twin-RLFD with T_c(2) set according to Theorem 5.6 in CLEF paper
    rd1 := rlfd.NewRlfdDtctr(rd_beta, rd_gamma, rd_t_l)
    rd2_t_l := time.Duration((2*float64(rd.GetDepth())*ed_gamma_h)/(config.CLEFConfig.AttackerFlowFactor*rd_gamma))*rd_t_l
    rd2 := rlfd.NewRlfdDtctr(rd_beta, rd_gamma, rd2_t_l)

    cdBlackList := cuckoo.NewCuckoo()
    cd := clef.NewClefDtctr(ed1, rd1, rd2, float64(rd_gamma), float64(rd_beta), config.CLEFConfig.MaxWatchlistSize, cdBlackList)
    //cd.SetCurrentTime(time.Now().Sub(time.Time{}))

    bdBlackList := cuckoo.NewCuckoo()
    bd := baseline.NewBaselineDtctr(beta, gamma, bdBlackList)

    sdBlacklist := cuckoo.NewCuckoo()
    sd := slidingwindow.NewSlidingWindowDtctr(beta, gamma, rd_t_l, sdBlacklist)

    ed.SetCurrentTime(trace.Packets[0].Duration)
    rd.SetCurrentTime(trace.Packets[0].Duration)

    fmt.Printf("\n-----------------------------------\n")
    fmt.Printf("\n=========Accuracy Tests============\n")
    fmt.Printf("\n-----------------------------------\n") 

    // output results
    fmt.Printf(
        "Evaluation over trace:\n" +
            "\tpcapFilename=%s\n" +
            "\ttimesFilename=%s\n",
        pcapFilename, timesFilename)
    fmt.Printf("Link capacity: p=%fB/ns\n", p)
    fmt.Printf("Flow spec: gamma=%f, beta=%f\n", gamma, beta)

    evaluateDetectorAccuracy(bd, ed, rd, cd, sd, trace) 
      

    fmt.Printf("\n--------------------------------------\n")
    fmt.Printf("\n=========Performance Tests============\n")
    fmt.Printf("\n--------------------------------------\n")

    if (evalMap[BASELINE_CONFIG_ID]) {
        evaluateDetectorPerformance(bd, BASELINE_CONFIG_ID, trace)
    }
    if (evalMap[CLEF_CONFIG_ID]) {
        evaluateDetectorPerformance(cd, CLEF_CONFIG_ID, trace)
    }
    if (evalMap[EARDet_CONFIG_ID]) {
        evaluateDetectorPerformance(ed, EARDet_CONFIG_ID, trace)
    }
    if (evalMap[RLFD_CONFIG_ID]) {
        evaluateDetectorPerformance(rd, RLFD_CONFIG_ID, trace)
    }

}


func evaluateDetectorAccuracy(bd *baseline.BaselineDtctr, ed *eardet.EardetDtctr,
                              rd *rlfd.RlfdDtctr, cd *clef.ClefDtctr,
                              sd *slidingwindow.SlidingWindowDtctr, trace *caida.TraceData) {

    //FP and FN
    edFP := 0
    edFN := 0
    rdFP := 0
    rdFN := 0
    cdFP := 0
    cdFN := 0

    //damage metric
    edOveruseDamage := uint32(0)
    edFPDamage := uint32(0)
    rdOveruseDamage := uint32(0)
    rdFPDamage := uint32(0)
    cdOveruseDamage := uint32(0)
    cdFPDamage := uint32(0)

    //blacklists
    blackListED := make(map[uint32]int)
    blackListRD := make(map[uint32]int)
    blackListCD := make(map[uint32]int)
    blackListBD := make(map[uint32]int)
    blackListSD := make(map[uint32]int)

    // Initialize hash function
    aesh := aeshash.NewAESHasher([]byte("ABCDEFGHIJKLMNOP"))
    fmt.Printf("Seed for hash function: %d\n", binary.LittleEndian.Uint32(aesh.GetSeed()))

    var flowID uint32
    var pkt *caida.CaidaPkt
    var resED, resRD, resBD, resCD, resSD bool

    // traverse packets in the trace
    for i := 0; i < len(trace.Packets); i++ {
        pkt = trace.Packets[i]
        flowID = aesh.Hash_uint32(&pkt.Id)
        
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

        // passing packet to CLEF
        if _, ok := blackListCD[flowID]; !ok {
            resCD = cd.Detect(flowID, pkt.Size, pkt.Duration)
        } else {
            resCD = true
        }

        // passing packet to Baseline Detector
        if _, ok := blackListBD[flowID]; !ok {
            // Use Sliding Window detector as baseline detector
            resBD = sd.Detect(flowID, pkt.Size, pkt.Duration)
        } else {
            resBD = true
        }

        if resED {blackListED[flowID]++}
        if resRD {blackListRD[flowID]++}
        if resCD {blackListCD[flowID]++}
        if resBD {blackListBD[flowID]++}
        if resSD {blackListSD[flowID]++}

        //damage metric
        if resBD {
            if !resED {edOveruseDamage += pkt.Size}
            if !resRD {rdOveruseDamage += pkt.Size}
            if !resCD {cdOveruseDamage += pkt.Size}
        } else {
            if resED {edFPDamage += pkt.Size}
            if resRD {rdFPDamage += pkt.Size}
            if resCD {cdFPDamage += pkt.Size}
        }
    }

    edTotalDamage := edFPDamage + edOveruseDamage
    rdTotalDamage := rdFPDamage + rdOveruseDamage
    cdTotalDamage := cdFPDamage + cdOveruseDamage


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
    for k, _ := range blackListCD {
        if _, ok := blackListBD[k]; !ok {
            cdFP++
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
        if _, ok := blackListCD[k]; !ok {
            cdFN++
        }
    }


    
    fmt.Printf("\n========Baseline========\n")
    fmt.Printf(
        "Config: beta=%f, gamma=%f\n", sd.GetBeta(), sd.GetGamma())
    fmt.Printf("Number of flows: %d\n", sd.NumFlows)
    fmt.Printf("Number of flows detected by baseline: %d\n", len(blackListBD))

    fmt.Printf("\n========EARDet========\n")
    fmt.Printf(
        "Config: alpha=%d, gamma_l=%f, beta_l=%d, " +
            "gamma_h=%f, beta_h=%d, beta_th=%d\n",
        ed.GetAlpha(), ed.GetGamma_l(), ed.GetBeta_l(),
        ed.GetGamma_h(), ed.GetBeta_h(), ed.GetBeta_th())
    fmt.Printf("Number of flows: %d\n", sd.NumFlows)
    fmt.Printf("Number of flows detected by baseline: %d\n", len(blackListBD))
    fmt.Printf("Number of flows detected by EARDet: %d\n", len(blackListED))
    fmt.Printf("FP (flows): %d FN (flows): %d, TP: %d\n", edFP, edFN, 
                len(blackListED)-edFP)
    fmt.Printf("overuseDamage: %dB, falsePositiveDamage: %dB, total: %dB (%.2f%%)\n",
        edOveruseDamage, edFPDamage, edTotalDamage, float64(edTotalDamage)/float64(cdTotalDamage)*100)
    
    fmt.Printf("\n========Single RLFD========\n")
    fmt.Printf("Config: t_l=%dns, th=%d, depth=%d, fanout=%d, " +
                "gamma=%fB/ns, beta=%dB\n",
        rd.GetT_l().Nanoseconds(), rd.GetTh(), rd.GetDepth(),
        rd.GetNumCountersPerNode(), rd.GetGamma(), rd.GetBeta())
    fmt.Printf("Number of flows: %d\n", sd.NumFlows)
    fmt.Printf("Number of flows detected by baseline: %d\n", len(blackListBD))
    fmt.Printf("Number of flows detected by RLFD: %d\n", len(blackListRD))
    fmt.Printf("FP (flows): %d FN (flows): %d, TP: %d\n", rdFP, rdFN,
                len(blackListRD)-rdFP)
    fmt.Printf("overuseDamage: %dB, falsePositiveDamage: %dB, total: %dB (%.2f%%)\n",
        rdOveruseDamage, rdFPDamage, rdTotalDamage, float64(rdTotalDamage)/float64(cdTotalDamage)*100)

    fmt.Printf("\n========CLEF========\n")
    fmt.Printf("Number of flows: %d\n", sd.NumFlows)
    fmt.Printf("Number of flows detected by baseline: %d\n", len(blackListBD))
    fmt.Printf("Number of flows detected by CLEF: %d\n", len(blackListCD))
    fmt.Printf("Number of flows in CLEF watchlist: %d\n", cd.GetWatchlistSize())
    fmt.Printf("FP (flows): %d FN (flows): %d, TP: %d\n", cdFP, cdFN,
                len(blackListCD)-cdFP)
    fmt.Printf("overuseDamage: %dB, falsePositiveDamage: %dB, total: %dB\n",
        cdOveruseDamage, cdFPDamage, cdTotalDamage)
    fmt.Printf("Subdetector Blocking: EARDet: %d, RLFD 1: %d, RLFD 2: %d\n",
                cd.EdBlocked, cd.Rd1Blocked, cd.Rd2Blocked)

}


func evaluateDetectorPerformance (dtctr Dtctr, dtctrName string, trace *caida.TraceData) {

    var flowID uint32
    var pkt *caida.CaidaPkt
    var res, manuallyUpdateBlacklist bool

    aesh := aeshash.NewAESHasher([]byte("ABCDEFGHIJKLMNOP"))

    blackList := dtctr.GetBlacklist()
    if (blackList == nil) {
        manuallyUpdateBlacklist = true
        blackList = cuckoo.NewCuckoo()
    }

    var consumedTime time.Duration
    startTime := time.Now()
    // traverse packets in the trace
    var i int
    for i = 0; i < len(trace.Packets); i++ {
        pkt = trace.Packets[i]
        flowID = aesh.Hash_uint32(&pkt.Id)

        // passing packet to detector
        if _, ok := blackList.LookUp(flowID); !ok {
            res = dtctr.Detect(flowID, pkt.Size, pkt.Duration)
        } else {
            res = true
        }

        if (res && manuallyUpdateBlacklist) {
            blackList.Insert(flowID, 0)
        }

    }
    endTime := time.Now()
    consumedTime = endTime.Sub(startTime)

    fmt.Println("Detector", dtctrName, "took", consumedTime, "for", i, "packets")

}