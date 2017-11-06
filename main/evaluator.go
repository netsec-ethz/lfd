package main

import (
    "fmt"
    // "os"
    // "bufio"
    "time"
    "os"
    "encoding/json"
    "io/ioutil"

    "github.com/hosslen/lfd/baseline"
    "github.com/hosslen/lfd/eardet"
    "github.com/hosslen/lfd/rlfd"
    "github.com/hosslen/lfd/murmur3"
    "github.com/hosslen/lfd/caida"
)

const (
    NANO_SEC_PER_SEC = float64(1000000000.0)
)

type Config struct {
    ExpName string `json:"exp_name"`
    TrafficConfig struct {
        LinkCapacity int `json:"link_capacity"`
        MaxPacketSize int `json:"max_pkt_size"`
        MaxPacketNum int `json:"max_pkt_num"`
        FlowSpecGamma int `json:"flow_spec_gamma"`
        FlowSpecBeta int `json:"flow_spec_beta"`
        PcapFile string `json:"pcap_file"`
        TimeFile string `json:"time_file"`
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

    // evaluation config:
    maxPktNum := config.TrafficConfig.MaxPacketNum
    pcapFilename := config.TrafficConfig.PcapFile
    timesFilename := config.TrafficConfig.TimeFile

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
    
    // RLFD config
    // RLFD time length for each level
    rd_t_l := time.Duration(beta/gamma * config.RLFDConfig.TlFactor)
    rd_gamma := float64(config.RLFDConfig.Gamma) / NANO_SEC_PER_SEC
    rd_beta := uint32(config.RLFDConfig.Beta)

    trace := caida.LoadPCAPFile(pcapFilename, timesFilename, maxPktNum)


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
        ed_counter_num, alpha, ed_beta_l, ed_gamma_l, p)
    // TODO(hao): RLFD's setting could be wrong
    rd := rlfd.NewRlfdDtctr(rd_beta, rd_gamma, rd_t_l)
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


    // output results
    fmt.Printf(
        "Evaluation over trace:\n" +
            "\tpcapFilename=%s\n" +
            "\ttimesFilename=%s\n",
        pcapFilename, timesFilename)
    fmt.Printf("Link capacity: p=%fB/ns\n", p)
    fmt.Printf("Flow spec: gamma=%f, beta=%f\n", gamma, beta)
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
    fmt.Printf("Config: t_l=%dns, th=%d, depth=%d, fanout=%d\n",
        rd.GetT_l().Nanoseconds(), rd.GetTh(), rd.GetDepth(),
        rd.GetNumCountersPerNode())
    fmt.Printf("Number of flows: %d\n", bd.NumFlows)
    fmt.Printf("Number of flows detected by baseline: %d\n", len(blackListBD))
    fmt.Printf("Number of flows detected by RLFD: %d\n", len(blackListRD))
    fmt.Printf("FP (flows): %d FN (flows): %d\n", rdFP, rdFN)
    fmt.Printf("overuseDamage: %dB, falsePositiveDamage: %dB\n",
        rdOveruseDamage, rdFPDamage)
}