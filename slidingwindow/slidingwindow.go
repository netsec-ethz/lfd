package slidingwindow

import (
    "time"
    "fmt"

    "github.com/hosslen/lfd/cuckoo"

)

var _ = fmt.Println

type SlidingWindowDtctr struct {
    //rate in B/ns at which a leaky bucket empties
    gamma float64
    //constant in equation TH(t) = gamma*t + beta
    beta float64
    // detection time interval
    t_l time.Duration
    //
    th uint32
    //for testing
    NumFlows int
    //map that maps flowIDs to leakyBuckets
    flowHistories map[uint32](map[float64]uint32)
    // blacklist
    blacklist *cuckoo.CuckooTable
}

//constructs a SlidingWindowDtctr and returns a pointer to it
func NewSlidingWindowDtctr(beta, gamma float64, t_l time.Duration, blacklist *cuckoo.CuckooTable) *SlidingWindowDtctr {
    sd := &SlidingWindowDtctr{}

    //initialize buckets
    sd.flowHistories = make(map[uint32](map[float64]uint32), 797557)

    //set parameters: TH(t) = gamma*t + beta 
    sd.gamma = gamma
    sd.beta = beta
    sd.t_l = t_l
    sd.th = uint32(gamma*float64(t_l) + beta)

    sd.blacklist = blacklist

    return sd
}

//method that detects large flows, returns true if a packet violates the threshold function TH(t) = gamma*t + beta
func (sd *SlidingWindowDtctr) Detect(flowID uint32, size uint32, t time.Duration) bool {

    floatTime := float64(t)

    if flowHistory, ok := sd.flowHistories[flowID]; !ok {
        sd.NumFlows += 1
        flowHistory := make(map[float64]uint32)
        flowHistory[floatTime] = size
        sd.flowHistories[flowID] = flowHistory
    } else {
        flowHistory[floatTime] = size
        var flowCounter uint32
        flowCounter = 0
        for ts, packetSize := range(flowHistory) {
            if (ts < floatTime - float64(sd.t_l)) {
                delete(flowHistory, ts)
            } else {
                flowCounter += packetSize
            }
        }
        if (flowCounter > sd.th) {
            return true
        }
    }

    return false;
}


func (sd *SlidingWindowDtctr) GetBlacklist() *cuckoo.CuckooTable {
    return sd.blacklist
}


func (sd *SlidingWindowDtctr) SetBlacklist(blacklist *cuckoo.CuckooTable) {
    sd.blacklist = blacklist
}


func (sd *SlidingWindowDtctr) GetGamma() float64 {
    return sd.gamma
}

func (sd *SlidingWindowDtctr) GetBeta() float64 {
    return sd.beta
}



