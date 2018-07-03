package clef

import (
    "time"

    "fmt"

    "github.com/hosslen/lfd/eardet"
    "github.com/hosslen/lfd/rlfd"
    "github.com/hosslen/lfd/cuckoo"
)

var _ = fmt.Println

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

    EdBlocked uint32
    Rd1Blocked uint32
    Rd2Blocked uint32

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

func NewClefDtctr(eardet *eardet.EardetDtctr,
                  rlfd1, rlfd2 *rlfd.RlfdDtctr,
                  gamma, beta float64,
                  maxWatchlistSize uint32,
                  blacklist *cuckoo.CuckooTable) *ClefDtctr {
    cd := &ClefDtctr{}

    //set detectors
    cd.eardet = eardet
    cd.rlfd1 = rlfd1
    cd.rlfd2 = rlfd2

    cd.watchlist = make(map[uint32](*leakyBucket))
    cd.maxWatchlistSize = maxWatchlistSize
    cd.watchlistTimeout = rlfd1.GetT_l()

    cd.blacklist = blacklist

    cd.gamma = gamma
    cd.beta = beta

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

func (cd *ClefDtctr) Detect(flowID uint32, size uint32, t time.Duration) bool {

    //check watchlist
    flowBucket, inWatchlist := cd.watchlist[flowID]

    // If a flow is already in the watchlist, update its leaky bucket or purge it if expired
    if inWatchlist {
        if (t - flowBucket.firstTimestamp > cd.watchlistTimeout) {
            delete(cd.watchlist, flowID)
        } else {
            //fmt.Println("Update leaky bucket for flow...")
            flowBucket.count += size
            legitimateTraffic := uint32(float64(t-flowBucket.lastTimestamp) * cd.gamma)
            if (flowBucket.count > legitimateTraffic){
                flowBucket.count -= legitimateTraffic
            } else {
                flowBucket.count = 0
            }
            flowBucket.lastTimestamp = t
            //fmt.Println("Update .")

            if (float64(flowBucket.count) > cd.beta) {
                return true
            }
        }
    }

    //get results
    detected := cd.eardet.Detect(flowID, size, t) || cd.rlfd1.Detect(flowID, size, t) || cd.rlfd2.Detect(flowID, size, t)

    // Insert flow into watchlist
    if detected && !inWatchlist {
        // If we have to insert a flow into the watchlist and there is too little space,
        //  let's see if there are expired flow entries in the watchlist
        if (uint32(len(cd.watchlist)) > cd.maxWatchlistSize) {
            cd.cleanupWatchlist(t)
        }
        //cd.watchlist[flowID] = &leakyBucket{firstTimestamp: t}
        return true
    }

    return false
    
}

func (cd *ClefDtctr) GetBlacklist() *cuckoo.CuckooTable {
    return cd.blacklist
}

func (cd *ClefDtctr) SetBlacklist(blacklist *cuckoo.CuckooTable) {
    cd.blacklist = blacklist
}

func (cd *ClefDtctr) GetWatchlistSize() uint32 {
    return uint32(len(cd.watchlist))
}