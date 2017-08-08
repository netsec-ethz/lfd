// the RLFD (Recursive Large-Flow Detection) detector
package rlfd

import (
	"time"
	"fmt"
	// "github.com/hosslen/lfd/murmur3"
)

var _ = fmt.Println

const (
	//number of counters in a virtual counter node
	m = uint32(8)
	//s = log2(m)
	s = uint32(3)
	//must hold: s * d < 32
	//depth of the virtual counter tree
	d = uint32(7)
	//must hold: d >= roundUp(logm(n)) (n = number of flows)
)

type counter struct {
	flowID uint32
	count uint32
	//indicates if count is current or from last phase
	reset bool
}

type RlfdDtctr struct {
	counters [m]counter
	//threshold for counters, th_rlfd = gamma*t_l + beta must hold
	th_rlfd uint32
	//time spent on one level in ns
	t_l time.Duration

	//level we are on now
	level uint32
	//to track the maximum counter
	maxIndex uint8
	maxVal uint32
	//time
	now time.Duration
	//indicates what counter.reset should be right now, if it is not, count is considered to be zero
	reset bool
	numCountersReseted uint32
	//to check if a flowID hashed into a loaded virtual counter
	bitmaskIndex uint32
	bitmaskPath uint32
	path uint32
}

//returns a pointer to a new rlfdDtctr
func NewRlfdDtctr(beta, gamma uint32, t_l time.Duration) *RlfdDtctr {
	rd := &RlfdDtctr{}

	rd.t_l = t_l
	rd.th_rlfd = gamma*uint32(t_l) + beta
	rd.level = 0
	rd.bitmaskIndex = ((1 << s) - 1) << (32 - s) //(2^s - 1) << (32 - s)
	rd.bitmaskPath = 0
	rd.path = 0
	rd.reset = true

	return rd
}

func (rd *RlfdDtctr) SetCurrentTime(t time.Duration) {
	rd.now = t
}

func (rd *RlfdDtctr) Detect(flowID uint32, size uint32, t time.Duration) bool {
	//check if we advance one level
	diff := t - rd.now
	if (diff > rd.t_l) {
		rd.now += rd.t_l*(diff / rd.t_l)
		if (rd.level == d - 1) {
			rd.bitmaskIndex = 0xe0000000
			rd.bitmaskPath = 0
			rd.level = 0
			rd.path = 0
			// murmur3.ResetSeed()
		} else {
			temp1 := 29 - (rd.level * 3)
			temp2 := uint32(0x7 << temp1)
			rd.bitmaskIndex >>= 3
			rd.bitmaskPath = rd.bitmaskPath | temp2
			rd.level++
			rd.path = rd.path | (uint32(rd.maxIndex) << temp1)
		}
		rd.maxVal = 0
		if rd.numCountersReseted < m {
			for i := uint32(0); i < m; i++ {
				rd.counters[i].reset = rd.reset
			}
		}
		rd.numCountersReseted = 0
		rd.reset = !rd.reset
	}

	//is the right virtual counter loaded?
	if (flowID & rd.bitmaskPath) == rd.path {
		index := uint8((flowID & rd.bitmaskIndex) >> (29 - (3 * rd.level)))
		c := &rd.counters[index]

		//are we on the lowest level?
		if rd.level == d - 1 {
			//do cuckoo hashing
			var alt bool
			altIndex := (flowID & 0x38) >> 3
			if (c.flowID == flowID && c.reset == rd.reset) {
				c.count += size
			} else if c2 := &rd.counters[altIndex]; c2.flowID == flowID && c2.reset == rd.reset {
				c2.count += size
				alt = true
			} else if c.reset != rd.reset {
				c.count = size
				c.flowID = flowID
				c.reset = rd.reset
				rd.numCountersReseted++
			} else if c2 := &rd.counters[((c.flowID & 0x38) >> 3)]; c2.reset != rd.reset {
				c2.count = c.count
				c2.flowID = c.flowID
				c2.reset = rd.reset
				rd.numCountersReseted++
				c.count = size
				c.flowID = flowID
			} else {
				return false
			}

			//check threshold
			if size > rd.th_rlfd {
				return true
			} else if c.count > rd.th_rlfd && !alt {
				return true
			} else if rd.counters[altIndex].count > rd.th_rlfd {
				return true
			}
		//we are not on the lowest level
		} else {
			if c.reset != rd.reset {
				c.count = size
				c.reset = rd.reset
				rd.numCountersReseted++
			} else {
				c.count += size
			}
			//reset max if necessary
			if (c.count > rd.maxVal) {
				rd.maxIndex = index
				rd.maxVal = c.count
			}
		}
	}
	return false
}



