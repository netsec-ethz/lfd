package clef

import (
	"time"

	"github.com/hosslen/lfd/eardet"
	"github.com/hosslen/lfd/murmur3"
	"github.com/hosslen/lfd/rlfd"
)

type pktTriple struct {
	flowID uint32
	size uint32
	t time.Duration
}

type ClefDtctr struct {
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

func NewClefDtctr(eardet *eardet.EardetDtctr, rlfd1, rlfd2 *rlfd.RlfdDtctr) *ClefDtctr {
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


func (cd *ClefDtctr) Detect(id *[16]byte, size uint32, t time.Duration) bool {
	//TODO: Change this
	//calculate murmur3 hash
	flowID := murmur3.Murmur3_32_caida(id)

	//create pktTriple
	pkt := pktTriple{flowID, size, t}

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

	return detected
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
