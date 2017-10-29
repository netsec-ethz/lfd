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
    // "fmt"
    "time"
)

//TODO:
//Take care of carry-over
//Change the way we find the new minimum

const (
    //the number of counters in use (must be > 1)
    // numCounters uint32 = 128
    maxuint32 uint32 = 4294967295
)

type counter struct {
    flowID uint32
    //count is always <= threshold + alpha
    count uint32
}

type EardetDtctr struct {
    //the link capacity in Byte/nanosec
    linkCap float64
    //maximum packet size
    alpha uint32
    //counter threshold relative to zero
    beta_th uint32

    beta_l uint32
    gamma_l float64
    beta_h uint32
    gamma_h float64

    //bucktes
    counters []counter
    //points to a bucket with count <= the counts of all other buckets
    minCounter *counter
    //the maximum value of count
    maxValue uint32
    //count == floor is regarded as being zero
    floor uint32
    //threshold for counters that is relative to floor
    threshold uint32
    //num counters in EARDet
    numCounters uint32

    virtualID uint32
    maxVirtualPacketSize uint32

    //nanoseconds passed since start of interval
    currentTime time.Duration
}

//constructors
// Deprecate this constructor: because this constructor
// does not translate flow spec to detector setting
func NewEardetDtctr(
    numCounters uint32, alpha uint32, beta_th uint32,
    linkCap float64) *EardetDtctr {
    ed := &EardetDtctr{}
    ed.counters = make([]counter, numCounters)

    ed.alpha = alpha
    ed.beta_th = beta_th
    ed.threshold = beta_th
    ed.linkCap = linkCap
    ed.numCounters = numCounters

    //set minCounter to the last element of counters (all are initialized to 0 anyway)
    ed.minCounter = &ed.counters[numCounters - 1]
    ed.maxValue = 0
    //set maxVirtualPacketSize
    ed.maxVirtualPacketSize = ed.beta_th - 1

    return ed
}

// beta_th = ((beta_l + (gamma_l * (alpha + beta_l)) / (linkCapacity / (numOfCounters + 1) - gamma_l)) + 1;
// beta_h = 2 * beta_th + alpha;
func NewConfigedEardetDtctr(numCounters uint32, alpha uint32, beta_l uint32,
    gamma_l float64, linkCap float64) *EardetDtctr{
    ed := &EardetDtctr{}
    ed.counters = make([]counter, numCounters)

    ed.alpha = alpha
    gamma_h := linkCap / float64(numCounters + 1)
    ed.beta_th = uint32(float64(beta_l) + 
        (gamma_l * float64(alpha + beta_l) / gamma_h - gamma_l) + 1.0)
    ed.threshold = ed.beta_th
    ed.linkCap = linkCap
    ed.numCounters = numCounters
    ed.beta_l = beta_l
    ed.gamma_l = gamma_l
    ed.beta_h = 2 * ed.beta_th + alpha
    ed.gamma_h = gamma_h

    //set minCounter to the last element of counters (all are initialized to 0 anyway)
    ed.minCounter = &ed.counters[numCounters - 1]
    ed.maxValue = 0
    //set maxVirtualPacketSize
    ed.maxVirtualPacketSize = ed.beta_th - 1

    return ed
}

func (ed *EardetDtctr) GetAlpha() uint32 {
    return ed.alpha
}

func (ed *EardetDtctr) GetBeta_th() uint32 {
    return ed.beta_th
}

func (ed *EardetDtctr) GetBeta_l() uint32 {
    return ed.beta_l
}

func (ed *EardetDtctr) GetGamma_l() float64 {
    return ed.gamma_l
}

func (ed *EardetDtctr) GetBeta_h() uint32 {
    return ed.beta_h
}

func (ed *EardetDtctr) GetGamma_h() float64 {
    return ed.gamma_h
}

func (ed *EardetDtctr) GetNumCounters() uint32 {
    return ed.numCounters
}

//if the first packets timestamp is not equal to zero, use this
func (ed *EardetDtctr) SetCurrentTime(now time.Duration) {
    ed.currentTime = now
}

//check packet
func (ed *EardetDtctr) Detect(flowID uint32, size uint32, t time.Duration) bool {

    if (ed.currentTime < t) {
        //advance currentTime
        oldTime := ed.currentTime
        //TODO: deal with the carry
        ed.currentTime = t + time.Duration(float64(size)/ed.linkCap)
        
        //calculate virtual traffic size
        //TODO: deal with the carry
        virtualTrafficSize := uint32(float64(t - oldTime)*ed.linkCap) + 1
        if virtualTrafficSize > ed.maxValue * ed.numCounters {
            ed.floor = ed.maxValue
            ed.threshold = ed.floor + ed.beta_th
        }

        //insert virtual traffic
        for virtualTrafficSize >= ed.maxVirtualPacketSize {
            virtualTrafficSize -= ed.maxVirtualPacketSize
            ed.processPkt(ed.virtualID, ed.maxVirtualPacketSize)
            ed.virtualID++
        }
        if virtualTrafficSize > 0 {
            ed.processPkt(ed.virtualID, virtualTrafficSize)
            ed.virtualID++
        }
    }

    //insert packet
    return ed.processPkt(flowID, size)
}

//add the packet to counters
//Note: The assumption is no packet from an already blacklisted flow is passed as argument to this function.
//If this assumption does not hold, a counter might overflow.
func (ed *EardetDtctr) processPkt(flowID uint32, size uint32) bool {
    //get the first bucket
    index := (flowID & 0xFFFF) % ed.numCounters
    c := &ed.counters[index]

    tries := 0
    var e, old_c *counter = nil, nil

    //check if one of the two candidate buckets already belongs to this flow
    for tries < 2 {
        //if yes, increment the counter of that bucket
        if c.flowID == flowID {
            c.count += size
            if c == ed.minCounter {
                ed.resetMin()
            }
            if c.count > ed.maxValue {
                ed.maxValue = c.count
            }
            if c.count > ed.threshold {
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
            c = &ed.counters[((flowID & 0xFFFF0000) >> 16) % ed.numCounters]
        }
    }

    //check if it is possible to displace any of the counters blocking our
    //two candidate buckets old_c and c
    if e == nil {
        s := &ed.counters[(old_c.flowID & 0xFFFF) % ed.numCounters]
        if s.count == ed.floor {
            s.flowID = old_c.flowID
            s.count = old_c.count
            e = old_c
        } else if s = &ed.counters[((old_c.flowID & 0xFFFF0000) >> 16) % ed.numCounters]; s.count == ed.floor {
            s.flowID = old_c.flowID
            s.count = old_c.count
            e = old_c
        } else if s = &ed.counters[(c.flowID & 0xFFFF) % ed.numCounters]; s.count == ed.floor {
            s.flowID = c.flowID
            s.count = c.count
            e = c
        } else if s = &ed.counters[((c.flowID & 0xFFFF0000) >> 16) % ed.numCounters]; s.count == ed.floor {
            s.flowID = c.flowID
            s.count = c.count
            e = c
        }
        if e != nil {
            e.count = ed.floor
            ed.minCounter = e
        }
    }

    //check if we have found a (now) empty bucket
    if e != nil {
        e.flowID = flowID
        e.count = ed.floor + size
        if e == ed.minCounter {
            ed.resetMin()
        }
        if e.count > ed.maxValue {
            ed.maxValue = e.count
        }
        //check if the threshold is reached
        if e.count > ed.threshold {
            return true
        }
        return false
    }

    //if we have not found any bucket, decrement the counts in all buckets
    m := min(size, ed.minCounter.count - ed.floor)
    ed.floor += m
    ed.threshold += m //adjust threshold

    //check again if bucket is zero, insert if yes
    if old_c.count == ed.floor {
        old_c.flowID = flowID
        old_c.count = ed.floor + (size - m)
        if old_c == ed.minCounter {
            ed.resetMin()
        }
        if old_c.count > ed.threshold {
            return true
        }
    } else if c.count == ed.floor {
        c.flowID = flowID
        c.count = ed.floor + (size - m)
        if c == ed.minCounter {
            ed.resetMin()
        }
        if c.count > ed.threshold {
            return true
        }
    }
    return false
}

//calling this function will reset ed.minCounter
//TODO: Change this
func (ed *EardetDtctr) resetMin() {
    c := &ed.counters[0]
    m := c.count
    for i := uint32(0); i < ed.numCounters; i++ {
        if ed.counters[i].count < m {
            c = &ed.counters[i]
            m = ed.counters[i].count
        }
    }
    ed.minCounter = c
}

//resets the floor to zero
func (ed *EardetDtctr) resetFloor() {
    for i := uint32(0); i < ed.numCounters; i++ {
        ed.counters[i].count -= ed.floor
    }
    ed.threshold = ed.beta_th
    ed.floor = 0
}

func min(a, b uint32) uint32 {
    if a < b {
        return a
    }
    return b
}










