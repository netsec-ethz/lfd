package clef

import (
    "time"

    "github.com/hosslen/lfd/eardet"
    "github.com/hosslen/lfd/murmur3"
    "github.com/hosslen/lfd/rlfd"

    "github.com/hosslen/lfd/cuckoo"
)

type leakyBucket struct {
    //moment in time when flow was inserted into watchlist
    firstTimestamp time.Duration
    //moment in time when last packet for this flow was received
    lastTimestamp time.Duration
    //how many bytes the bucket contains right now
    count uint32
}

type pktTriple struct {
    flowID uint32
    size uint32
    t time.Duration
}

type ClefDtctr struct {

    //flow lists
    watchlist map[uint32](*leakyBucket)
    maxWatchlistSize uint32
    watchlistTimeout time.Duration
    blacklist *cuckoo.CuckooTable

    //flow specification
    beta float64
    gamma float64

    //detectors
    eardet *eardet.EardetDtctr
    rlfd1 *rlfd.RlfdDtctr
    rlfd2 *rlfd.RlfdDtctr

    //channels
    packetsForEardet chan pktTriple
    packetsForRlfd1 chan pktTriple
    packetsForRlfd2 chan pktTriple
    resultsEardet chan bool
    resultsRlfd1 chan bool
    resultsRlfd2 chan bool
}

func NewClefDtctr(eardet *eardet.EardetDtctr, rlfd1, rlfd2 *rlfd.RlfdDtctr, gamma, beta float64, maxWatchlistSize uint32) *ClefDtctr {
    cd := &ClefDtctr{}

    //set detectors
    cd.eardet = eardet
    cd.rlfd1 = rlfd1
    cd.rlfd2 = rlfd2

    //create channels
    cd.packetsForEardet = make(chan pktTriple, 3)
    cd.packetsForRlfd1 = make(chan pktTriple, 3)
    cd.packetsForRlfd2 = make(chan pktTriple, 3)

    cd.resultsEardet = make(chan bool, 3)
    cd.resultsRlfd1 = make(chan bool, 3)
    cd.resultsRlfd2 = make(chan bool, 3)

    cd.watchlist = make(map[uint32](*leakyBucket))
    cd.maxWatchlistSize = maxWatchlistSize
    cd.watchlistTimeout = rlfd1.Get_t_l()

    cd.blacklist = cuckoo.NewCuckoo()

    cd.gamma = gamma
    cd.beta = beta

    //start worker threads
    go eardetWorker(cd.eardet, cd.packetsForEardet, cd.resultsEardet)
    go rlfdWorker(cd.rlfd1, cd.packetsForRlfd1, cd.resultsRlfd1)
    go rlfdWorker(cd.rlfd2, cd.packetsForRlfd2, cd.resultsRlfd2)

    return cd
}

func CleanUpClefDtctr(dtctr *ClefDtctr) {
    //close channels
    close(dtctr.packetsForEardet)
    close(dtctr.packetsForRlfd1)
    close(dtctr.packetsForRlfd2)
    close(dtctr.resultsEardet)
    close(dtctr.resultsRlfd1)
    close(dtctr.resultsRlfd2)
}

func (cd *ClefDtctr) SetCurrentTime(now time.Duration) {
    cd.eardet.SetCurrentTime(now)
    cd.rlfd1.SetCurrentTime(now)
    cd.rlfd2.SetCurrentTime(now)
}

func (cd *ClefDtctr) cleanupWatchlist(t time.Duration) {
    for flowID, _ := range cd.watchlist {
        if (t - cd.watchlist[flowID].firstTimestamp > cd.watchlistTimeout) {
            delete(cd.watchlist, flowID)
        }
    }

}


func (cd *ClefDtctr) Detect(id *[16]byte, size uint32, t time.Duration) bool {

    //calculate murmur3 hash
    flowID := murmur3.Murmur3_32_caida(id)

    //check blacklist
    if _, ok := cd.blacklist.LookUp(flowID); ok {
        return true
    }

    //create pktTriple
    pkt := pktTriple{flowID, size, t}

    //check watchlist
    flowBucket, ok := cd.watchlist[flowID]

    // If a flow is already in the watchlist, update its leaky bucket or purge it if expired
    if ok {
        if (t - flowBucket.firstTimestamp > cd.watchlistTimeout) {
            delete(cd.watchlist, flowID)
        } else {
            flowBucket.count += size
            legitimateTraffic := uint32(float64(t-flowBucket.lastTimestamp) * cd.gamma)
            if (flowBucket.count > legitimateTraffic){
                flowBucket.count -= legitimateTraffic
            } else {
                flowBucket.count = 0
            }
            flowBucket.lastTimestamp = t

            if (float64(flowBucket.count) > cd.beta) {
                cd.blacklist.Insert(flowID, 0)
                return true
            }
        }
    }

    //stuff pkt in channels
    cd.packetsForEardet <- pkt
    cd.packetsForRlfd1 <- pkt
    cd.packetsForRlfd2 <- pkt

    //get results
    detected := false
    for i := 0; i < 3; i++ {
        select {
            case r := <-cd.resultsEardet:
                detected = detected || r
            case r := <-cd.resultsRlfd1:
                detected = detected || r
            case r := <-cd.resultsRlfd2:
                detected = detected || r
        }
    }

    // Insert flow into watchlist
    if detected && !ok {
        // If we have to insert a flow into the watchlist and there is too little space,
        //  let's see if there are expired flow entries in the watchlist
        if (uint32(len(cd.watchlist)) > cd.maxWatchlistSize) {
            cd.cleanupWatchlist(t)
        }
        // TODO: what if still not enough space?
        cd.watchlist[flowID] = &leakyBucket{firstTimestamp: t}
    }

    return false
    
}

func eardetWorker(dtctr *eardet.EardetDtctr, packets <-chan pktTriple, results chan<- bool) {
    for p := range packets {
        results <- dtctr.Detect(p.flowID, p.size, p.t)
    }
}

func rlfdWorker(dtctr *rlfd.RlfdDtctr, packets <-chan pktTriple, results chan<- bool) {
    for p := range packets {
        results <- dtctr.Detect(p.flowID, p.size, p.t)
    }
}
