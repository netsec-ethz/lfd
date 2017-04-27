package caida

import (
	// "fmt"
	"testing"
	"time"

	"github.com/hosslen/shadow_lfd/eardet"
	"github.com/hosslen/shadow_lfd/murmur3"
)

var res bool

func BenchmarkDetectorWithTrace(b *testing.B) {
	//10Gbps = 1.25B/ns
	detector := eardet.NewEardetDtctr(500, 1000, 1.25)
	var tt time.Duration
	var offset time.Duration
	var flowID uint32
	var pkt *caidaPkt
	populatePackets()
	murmur3.ResetSeed()
	startTime := packets[0].duration
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkt = packets[i % numPkts]
		flowID = murmur3.Murmur3_32_caida(&pkt.id)
		tt = offset + pkt.duration - startTime
		if i % numPkts == (numPkts - 1) {
			offset += (pkt.duration - startTime)
		}
		res = detector.Detect(flowID, pkt.size, tt)
	}

}