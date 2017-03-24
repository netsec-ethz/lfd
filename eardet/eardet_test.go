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

// this file contains unit tests and benchmarks to test the eardet detector
package eardet

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

var (
	//to facilitate getting a duration for a packet
	zeroTime = time.Unix(0, 0)
)

//test the min function
func TestMin(t *testing.T) {
	var tests = []struct{
		a uint64
		b uint64
		want uint64
	}{
		{1, 2, 1},
		{2, 1, 1},
		{2, 2, 2},
	}
	for _, test := range tests {
		if got := min(test.a, test.b); got != test.want {
			t.Errorf("min(%d, %d) = %d", test.a, test.b, got)
		}
	}
}

//test that resetFloor works correctly
func TestResetFloor(t *testing.T) {
	var tests = []struct{
		alpha uint64
		beta_th uint64
		floor uint64
	}{
		{100, 200 + numCounters, 200},
		{100, 100 + numCounters, 0},
	}
	for _, test := range tests {
		//set up
		ed := NewEardetDtctr(test.alpha, test.beta_th, 0)
		ed.floor = test.floor
		//fill buckets to simulate a raised floor
		for i := uint64(0); i < numCounters; i++ {
			ed.counters[i].count = ed.floor + i
		}
		//test that minCounter is set properly
		if ed.minCounter != &ed.counters[0] {
			t.Errorf("resetFloor failed: minCounter is %p but should be %p.", ed.minCounter, &ed.counters[0])
		}
		//test that buckets were properly decremented
		temp := ed.minCounter
		ed.resetFloor()
		for i := uint64(0); i < numCounters; i++ {
			if ed.counters[i].count != i {
				t.Errorf("resetFloor failed: Bucket %d should be %d but is %d.",
				 i, i, ed.counters[i].count)
				break
			}
		}
		//test that floor is zero
		if ed.floor != 0 {
			t.Errorf("resetFloor failed: floor is %d but should be %d.", ed.floor, 0)
		}
		//test that minCounter does not change
		if temp != ed.minCounter {
			t.Errorf("resetFloor failed: minCounter has changed from %p to %p.", temp, ed.minCounter)
		}
	}
}

//test that minCounter is reset properly if resetMin is called
func TestResetMin(t *testing.T) {
	alpha_test := uint64(500)
	beta_th_test := uint64(1000)
	ed := NewEardetDtctr(alpha_test, beta_th_test, 0)
	//fill buckets
	for i := uint64(0); i < numCounters; i++ {
		ed.counters[i].count = 150
	}
	//test with last bucket containing the smallest count
	ed.counters[(numCounters - 1) % numCounters].count = 100
	ed.resetMin()
	if ed.minCounter != &ed.counters[numCounters - 1 % numCounters] {
		t.Errorf("resetMin failed: ed.minCounter=%p, should be %p",
		 ed.minCounter, &ed.counters[(numCounters - 1) % numCounters])
	}
	//test with random bucket containing the smallest count
	source := rand.NewSource(time.Now().UnixNano())
	r := rand.New(source)
	randNum := uint64(r.Uint32()) << 32 + uint64(r.Uint32())
	ed.counters[randNum % numCounters].count = 50
	ed.resetMin()
	if ed.minCounter != &ed.counters[randNum % numCounters] {
		t.Errorf("resetMin failed: ed.minCounter=%p, should be %p",
		 ed.minCounter, &ed.counters[randNum % numCounters])
	}
	//test with first bucket containing the smallest count
	ed.counters[0].count = 25
	ed.resetMin()
	if ed.minCounter != &ed.counters[0] {
		t.Errorf("resetMin failed: ed.minCounter=%p, should be %p",
		 ed.minCounter, &ed.counters[0])
	}
}

//test if minCounter is reset after inserting one packet (resetMin is called)
func TestMinCounterIsResetAfterPacketInsertion(t *testing.T) {
	alpha_test := uint64(500)
	beta_th_test := uint64(1000)
	ed := NewEardetDtctr(alpha_test, beta_th_test, 0)
	//insert a packet
	ed.processPkt(0, 100)
	if ed.minCounter != &ed.counters[1 % numCounters] {
		t.Errorf("resetMin failed: ed.minCounter=%p, should be %p",
		 ed.minCounter, &ed.counters[1 % numCounters])
	}
	//insert another packet
	ed.processPkt(1, 200)
	if ed.minCounter != &ed.counters[2 % numCounters] {
		t.Errorf("resetMin failed: ed.minCounter=%p, should be %p",
		 ed.minCounter, &ed.counters[2 % numCounters])
	}
	// printAllBuckets(ed)
}

//insert a packet into the first matching bucket, count of that bucket is zero
func TestProcessPktInsertNewFlowInZeroBucket(t *testing.T) {
	alpha_test := uint64(500)
	beta_th_test := uint64(5000)
	ed := NewEardetDtctr(alpha_test, beta_th_test, 0)
	//insert a packet into the first bucket
	res := ed.processPkt(0, 200)
	if res {
		t.Errorf("processPkt failed: Packet(0, 200) wrongly detected.")
	}
	if ed.counters[0].count != 200 {
		t.Errorf("processPkt failed: Packet(0, 200) not correctly inserted.")
	}
	if b, i := allOtherBucketsAreZero(ed, 0); !b {
		t.Errorf("processPkt failed: Bucket %d is not zero.", i)
	}
}

//insert a packet into the first matching bucket, the bucket count has already been incremented
func TestProcessPktInsertFlowInAlreadyIncrementedBucket(t *testing.T) {
	alpha_test := uint64(500)
	beta_th_test := uint64(5000)
	ed := NewEardetDtctr(alpha_test, beta_th_test, 0)
	flowid1 := uint64(6)
	//insert a packet with flow id 6
	res0 := ed.processPkt(flowid1, 500)
	res1 := ed.processPkt(flowid1, 600)
	if res0 {
		t.Errorf("processPkt failed: Packet(%d, 500) wrongly detected.", flowid1)
	} 
	if res1 {
		t.Errorf("processPkt failed: Packet(%d, 600) wrongly detected.", flowid1)
	}
	if ed.counters[6 % numCounters].count != 1100 {
		t.Errorf("processPkt failed: Packet(6, 500) or Packet(6, 600) not correctly inserted.")
	}
	if b, i := allOtherBucketsAreZero(ed, 6); !b {
		t.Errorf("processPkt failed: Bucket %d is not zero.", i)
	}
}

//insert a packet into the second matching bucket, the first matching bucket is already taken by another flow
func TestProcessPktInsertFlowInAlternateBucket(t *testing.T) {
	alpha_test := uint64(500)
	beta_th_test := uint64(5000)
	flowid1 := uint64(0)
	flowid2 := uint64(numCounters)
	ed := NewEardetDtctr(alpha_test, beta_th_test, 0)
	//insert first packet
	res0 := ed.processPkt(flowid1, 500)
	//insert second packet
	res1 := ed.processPkt(flowid2, 600)
	if res0 {
		t.Errorf("processPkt failed: Packet(%d, 500) wrongly detected.", flowid1)
	} 
	if res1 {
		t.Errorf("processPkt failed: Packet(%d, 600) wrongly detected.", flowid2)
	}
	if ed.counters[(flowid2 + 1) % numCounters].count != 600 {
		t.Errorf("processPkt failed: Packet(%d, 600) not correctly inserted.", flowid2 + 1)
	}
}

//both matching buckets are already taken by other flows, here floor is not raised
func TestInsertionFails(t *testing.T) {
	alpha_test := uint64(500)
	beta_th_test := uint64(5000)
	flowid1 := uint64(0)
	flowid2 := uint64(numCounters)
	flowid3 := uint64(2*numCounters)
	ed := NewEardetDtctr(alpha_test, beta_th_test, 0)
	//insert first and second packet
	ed.processPkt(flowid1, 500)
	ed.processPkt(flowid2, 600)
	// printAllBuckets(ed)
	res := ed.processPkt(flowid3, 300)
	if res {
		t.Errorf("processPkt failed: Packet(%d, 300) wrongly detected.", flowid3)
	} 
	if ed.floor != 0 && numCounters > 2 {
		t.Errorf("processPkt failed: floor not properly set, is %d should be %d.", ed.floor, 0)
	}
	if ed.counters[flowid1 % numCounters].count != 500 {
		t.Errorf("processPkt failed: Packet(%d, 500) not correctly inserted.", flowid1)
	}
	if ed.counters[(flowid1 + 1) % numCounters].count != 600 {
		t.Errorf("processPkt failed: Packet(%d, 600) not correctly inserted.", flowid2)
	}
	// printAllBuckets(ed)
}

//both matching buckets are already taken by other flows, here floor is raised
func TestInsertionFailsFloorIsRaised(t *testing.T) {
	alpha_test := uint64(500)
	beta_th_test := uint64(5000)
	flowid1 := uint64(numCounters + 1)
	ed := NewEardetDtctr(alpha_test, beta_th_test, 0)

	//insert packets
	for i := uint64(0); i < numCounters; i++ {
		ed.processPkt(i, alpha_test + i)
		// fmt.Printf("minCounter set to bucket with flowid %d\n", ed.minCounter.flowID)
	}
	res := ed.processPkt(flowid1, 600)
	// fmt.Printf("minCounter set to bucket with flowid %d\n", ed.minCounter.flowID)

	if res {
		t.Errorf("processPkt failed: Packet(%d, 600) wrongly detected.", flowid1)
	} 
	if ed.floor != alpha_test {
		t.Errorf("processPkt failed: floor not properly set, is %d should be %d.", ed.floor, alpha_test)
	}
	if ed.minCounter != &ed.counters[0] {
		t.Errorf("processPkt failed: ed.minCounter=%p, should be %p",
		 ed.minCounter, &ed.counters[0])
	}
	// printAllBuckets(ed)
}

//Insert a packet into an empty bucket, test if it is detected as too big
func TestProcessPktInsertAfterFloorRaised1(t *testing.T) {
	alpha_test := uint64(500)
	beta_th_test := uint64(5000)
	ed := NewEardetDtctr(alpha_test, beta_th_test, 0)
	flowid1 := uint64(numCounters + 1)
	size1 := uint64(50001)
	//insert packet
	if !ed.processPkt(flowid1, size1) {
		t.Errorf("processPkt failed: Returns false, should return true.")
	}
}

//Insert a packet into an already partly filled bucket, test if it is detected
func TestProcessPktInsertAfterFloorRaised2(t *testing.T) {
	alpha_test := uint64(500)
	beta_th_test := uint64(5000)
	ed := NewEardetDtctr(alpha_test, beta_th_test, 0)
	flowid1 := uint64(numCounters + 1)
	size1 := uint64(2501)
	//insert packet
	if ed.processPkt(flowid1, size1) {
		t.Errorf("processPkt failed: Returns true, should return false.")
	}
	if !ed.processPkt(flowid1, size1) {
		t.Errorf("processPkt failed: Returns false, should return true.")
	}
}

//test that if floor raises high enough, resetFloor is actually triggered
func TestResetFloorIsTriggered(t *testing.T) {
	alpha_test := uint64(500)
	beta_th_test := uint64(5000)
	ed := NewEardetDtctr(alpha_test, beta_th_test, 0)
	ed.floor = ed.maxFloor
	for i := uint64(0); i < numCounters; i++ {
		ed.counters[i].flowID = i
		ed.counters[i].count = ed.floor + ed.beta_th
	}
	flowid1 := uint64(numCounters)
	size1 := ed.alpha
	ed.processPkt(flowid1, size1)
	if ed.floor != ed.alpha {
		t.Errorf("processPkt failed: ResetFloor was not properly triggered.")
	}
}

//test that after raising the floor the rest of a packet is inserted correctly in the first matching bucket
func TestInsertAfterRaisingFloor1(t *testing.T) {
	alpha_test := uint64(500)
	beta_th_test := uint64(5000)
	ed := NewEardetDtctr(alpha_test, beta_th_test, 0)
	//insert a packet into every bucket
	for i := uint64(0); i <numCounters; i++ {
		ed.processPkt(i, 100)
	}
	//insert another packet
	res := ed.processPkt(numCounters, 5200)
	// printAllBuckets(ed)
	if !res {
		t.Errorf("processPkt failed: returns false, should return true")
	}
	if ed.counters[0].count != 5200 {
		t.Errorf("processPkt failed: count of bucket 0 is %d, should be %d.", ed.counters[0].count, 5200)
	}
	if ed.floor != 100 {
		t.Errorf("processPkt Failed: floor should be 100, but is %d.", ed.floor)
	}
}

//test that after raising the floor the rest of a packet is inserted correctly in the second matching bucket
func TestInsertAfterRaisingFloor2(t *testing.T) {
	alpha_test := uint64(500)
	beta_th_test := uint64(5000)
	ed := NewEardetDtctr(alpha_test, beta_th_test, 0)
	//insert a packet into every bucket
	for i := uint64(0); i <numCounters; i++ {
		ed.processPkt(i, 100)
	}
	//insert another packet
	ed.processPkt(0, 100)
	res := ed.processPkt(numCounters, 5200)
	// printAllBuckets(ed)
	if !res {
		t.Errorf("processPkt failed: returns false, should return true")
	}
	if ed.counters[(numCounters + 1) % numCounters].count != 5200 {
		t.Errorf("processPkt failed: count of bucket 0 is %d, should be %d.", ed.counters[(numCounters + 1) % numCounters].count, 5200)
	}
	if ed.floor != 100 {
		t.Errorf("processPkt Failed: floor should be 100, but is %d.", ed.floor)
	}
	// printAllBuckets(ed)
}

//this function should insert one virtual traffic packet before the real packet
func TestDetectBasicInsert(t *testing.T) {
	ed := NewEardetDtctr(500, 5000, 0.03)
	ed.Detect(numCounters, 300, 600)
	if ed.counters[0].count != 19 {
		t.Errorf("Virtual traffic should increment bucket 0 to 19 but has to %d", ed.counters[0].count)
	}
	if ed.counters[1 % numCounters].count != 300 {
		t.Errorf("Real packet should increment bucket 1 to 300 but has to %d", 
			ed.counters[1 % numCounters].count)
	}
	// printAllBuckets(ed)
}

//this function should insert multiple virtual traffic packets before the real packet
func TestDetectInsertMultiple(t *testing.T) {
	ed := NewEardetDtctr(500, 1000, 0.03)
	ed.Detect(numCounters, 300, 60000)
	if ed.counters[0].count != 999 {
		t.Errorf("Virtual traffic should increment bucket 0 to 999 but has to %d", ed.counters[0].count)
	}
	if ed.floor != 0 {
		t.Errorf("floor should be 0 but is %d.", 
			ed.floor)
	}
	// printAllBuckets(ed)
}

func TestOverflow(t *testing.T) {
	num := maxuint64
	num++
	if num != 0 {
		t.Errorf("%d + 1 does not overflow as I thought it would.", maxuint64)
	}
	
}

func allOtherBucketsAreZero(ed *eardetDtctr, flowid uint64) (bool, uint64) {
	for i := uint64(0); i < numCounters; i++ {
		if ed.counters[i].count != 0 && i != (flowid % numCounters) {
			return false, i
		}
	}
	return true, 0
}

func printAllBuckets(ed *eardetDtctr) {
	for i := uint64(0); i < numCounters; i++ {
		fmt.Printf("%d: id=%d count=%d\n", i, ed.counters[i].flowID, ed.counters[i].count)
	}
}

func BenchmarkProcessPktInsertBasic(b *testing.B) {
	alpha_test := uint64(500)
	beta_th_test := uint64(5000)
	ed := NewEardetDtctr(alpha_test, beta_th_test, 0)
	source := rand.NewSource(time.Now().UnixNano())
	r := rand.New(source)
	var randID uint64
	var randSize int	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		randID = uint64(r.Uint32()) << 32 + uint64(r.Uint32())
		randSize = rand.Intn(500)
		ed.processPkt(randID, uint64(randSize))	
	}
}

func BenchmarkDetectInsertBasic(b *testing.B) {
	alpha_test := uint64(500)
	beta_th_test := uint64(5000)
	ed := NewEardetDtctr(alpha_test, beta_th_test, 0)
	source := rand.NewSource(time.Now().UnixNano())
	r := rand.New(source)
	var randID uint64
	var randSize int	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		randID = uint64(r.Uint32()) << 32 + uint64(r.Uint32())
		randSize = rand.Intn(500)
		ed.Detect(randID, uint64(randSize), time.Now().Sub(zeroTime))	
	}
}



