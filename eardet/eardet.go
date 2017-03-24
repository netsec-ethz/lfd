// Copyright 2016 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// the EARDet detector
package eardet

import (
	"time"
)

const (
	//the number of counters in use (must be >1)
	numCounters uint64 = 100
	maxuint64 uint64 = 18446744073709551615
)

type counter struct {
	flowID uint64
	//count is always <= beta_th + alpha
	count uint64
}

type eardetDtctr struct {
	//the link capacity in Byte/nanosec
	linkCap float64
	//maximum packet size
	alpha uint64
	//counter threshold
	beta_th uint64

	//bucktes
	counters [numCounters]counter
	//points to a bucket with count <= the counts of all other buckets
	minCounter *counter

	//count with this value is regarded as being zero
	floor uint64
	//the maximum value floor is allowed to take without triggering resetFloor
	maxFloor uint64

	virtualID uint64
	maxVirtualPacketSize uint64

	//nanoseconds passed since a start time
	currentTime time.Duration
}

//constructor
func NewEardetDtctr(alpha uint64, beta_th uint64, linkCap float64) *eardetDtctr {
	ed := &eardetDtctr{}

	ed.alpha = alpha
	ed.beta_th = beta_th
	ed.linkCap = linkCap

	//set minCounter to the first element of counters (all are initialized to 0 anyway)
	ed.minCounter = &ed.counters[0]
	//set maxFloor
	ed.maxFloor = maxuint64 - ed.beta_th - ed.alpha
	//set maxVirtualPacketSize
	ed.maxVirtualPacketSize = ed.beta_th - 1

	return ed
}

//check packet
func (ed *eardetDtctr) Detect(flowID uint64, size uint64, t time.Duration) bool {
	//advance currentTime
	oldTime := ed.currentTime
	ed.currentTime = t + time.Duration(float64(size)/ed.linkCap)

	//insert virtual traffic
	virtualTrafficSize := uint64(float64(t - oldTime)*ed.linkCap) + 1
	for virtualTrafficSize >= ed.maxVirtualPacketSize {
		virtualTrafficSize -= ed.maxVirtualPacketSize
		ed.processPkt(ed.virtualID, ed.maxVirtualPacketSize)
		ed.virtualID++
	}
	if virtualTrafficSize > 0 {
		ed.processPkt(ed.virtualID, virtualTrafficSize)
		ed.virtualID++
	}

	//add real packet
	return ed.processPkt(flowID, size)
}

//add the packet to counters
//Note: The assumption is no packet from an already blacklisted flow is passed as argument to this function.
//If this assumption does not hold, a count might overflow.
func (ed *eardetDtctr) processPkt(flowID uint64, size uint64) bool {
	//get the flow id modulo numCounters
	index := flowID % numCounters
	c := &ed.counters[index]
	tries := 0
	var e, old_c *counter = nil, nil

	//check if one of the two candidate buckets already belongs to this flow
	for tries < 2 {
		//if yes, increment the count
		if c.flowID == flowID {
			c.count += size
			if c == ed.minCounter {
				ed.resetMin()
			}
			//check if the threshold is reached
			if c.count > ed.beta_th {
				return true
			}
			return false
		//check if the bucket is empty and if it's the first empty bucket we encounter, store
		} else if c.count == ed.floor && e == nil {
			e = c
		}
		tries++
		if tries == 1 {
			old_c = c
			c = &ed.counters[(index + 1) % numCounters] //TODO: Maybe change this
		}
	}


	//check if we have found an empty bucket
	if e != nil {
		e.flowID = flowID
		e.count = ed.floor + size
		if e == ed.minCounter {
			ed.resetMin()
		}
		//check if the threshold is reached
		if e.count > ed.beta_th {
			return true
		}
		return false
	}

	//if we have not found any bucket, decrement the counts in all buckets
	m := min(size, ed.minCounter.count - ed.floor)
	if ed.maxFloor - ed.floor < m{
		ed.resetFloor()
	}
	ed.floor += m
	ed.beta_th += m //adjust threshold

	//check again if bucket is zero, insert if yes
	if old_c.count == ed.floor {
		old_c.flowID = flowID
		old_c.count = ed.floor + (size - m)
		if old_c.count > ed.beta_th {
			return true
		}
	} else if c.count == ed.floor {
		c.flowID = flowID
		c.count = ed.floor + (size - m)
		if c.count > ed.beta_th {
			return true
		}
	}
	return false
}

//calling this function will reset ed.minCounter
func (ed *eardetDtctr) resetMin() {
	c := &ed.counters[0]
	m := c.count
	for i := uint64(0); i < numCounters; i++ {
		if ed.counters[i].count < m {
			c = &ed.counters[i]
			m = ed.counters[i].count
		}
	}
	ed.minCounter = c
}

//resets the floor to zero
func (ed *eardetDtctr) resetFloor() {
	for i := uint64(0); i < numCounters; i++ {
		ed.counters[i].count -= ed.floor
	}
	ed.beta_th -= ed.floor
	ed.floor = 0
}

func min(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}










