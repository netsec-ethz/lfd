package baseline

import (
    "time"
    "fmt"

    "github.com/hosslen/lfd/cuckoo"

)

var _ = fmt.Println

type leakyBucket struct {
    //moment in time when last packet for this flow was received
    timestamp time.Duration
    //how many bytes the bucket contains right now
    count float64
}

type BaselineDtctr struct {
    //rate in B/ns at which a leaky bucket empties
    gamma float64
    //constant in equation TH(t) = gamma*t + beta
    beta float64
    //for testing
    NumFlows int
    //map that maps flowIDs to leakyBuckets
    buckets map[uint32](*leakyBucket)
    // blacklist
    blacklist *cuckoo.CuckooTable
}

//constructs a BaselineDtctr and returns a pointer to it
func NewBaselineDtctr(beta, gamma float64, blacklist *cuckoo.CuckooTable) *BaselineDtctr {
    bd := &BaselineDtctr{}

    //initialize buckets
    bd.buckets = make(map[uint32](*leakyBucket), 797557)

    //set parameters: TH(t) = gamma*t + beta 
    bd.gamma = gamma
    bd.beta = beta

    bd.blacklist = blacklist

    return bd
}

//method that detects large flows, returns true if a packet violates the threshold function TH(t) = gamma*t + beta
func (bd *BaselineDtctr) Detect(flowID uint32, size uint32, t time.Duration) bool {

    //get the right bucket and initialize it if it isn't already
    bucket := bd.buckets[flowID]
    if bucket == nil {
        bucket = &leakyBucket{}
        bd.buckets[flowID] = bucket
        bd.NumFlows++
    } else {
        //if the bucket is not empty, decrement it according to the time passed since adding the last packet
        temp := float64(t - bucket.timestamp)*bd.gamma
        if bucket.count > temp {
            bucket.count -= temp
        } else {
            bucket.count = 0.0
        }
    }

    //increment bucket and set timestamp
    bucket.count += float64(size)
    bucket.timestamp = t

    //check if the bucket overflows
    if bucket.count > bd.beta {
        bd.blacklist.Insert(flowID, 0)
        return true;
    }

    return false;
}


func (bd *BaselineDtctr) GetBlacklist() *cuckoo.CuckooTable {
    return bd.blacklist
}


func (bd *BaselineDtctr) SetBlacklist(blacklist *cuckoo.CuckooTable) {
    bd.blacklist = blacklist
}


func (bd *BaselineDtctr) GetGamma() float64 {
    return bd.gamma
}

func (bd *BaselineDtctr) GetBeta() float64 {
    return bd.beta
}



