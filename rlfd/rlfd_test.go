package rlfd

import (
    "math/rand"
    "testing"
    "time"

    "fmt"
)

const max = uint32(4294967295)

var (
    beta = uint32(500)
    gamma = uint32(200)
    t_l = time.Duration(500)
    _ = fmt.Println
)

//insert a simple package
func TestBasicInsert(t *testing.T) {
    detector := NewRlfdDtctr(beta, gamma, t_l)
    flowID := rand.Uint32()
    size := uint32(500)
    timestamp := time.Duration(0)
    detector.Detect(flowID, size, timestamp)
    index := (flowID & (((1 << s) - 1) << (32 - s))) >> (32 - s)
    // fmt.Println((flowID & (((1 << s) - 1) << (32 - s))))
    if detector.level != 0 {
        t.Errorf("Detect failed: level is %d, should be 0.\n", detector.level)
    }
    if detector.counters[index].count != size {
        t.Errorf("Detect failed: count is %d, should be %d.\n", detector.counters[index].count, size)
    }
    if !detector.counters[index].reset {
        t.Errorf("Detect failed: reset is %t, should be true.\n", detector.counters[index].reset)
    }
    // fmt.Println(detector.counters)
}

//test if level is raised correctly
func TestLevelRaising(t *testing.T) {
    detector := NewRlfdDtctr(beta, gamma, t_l)
    flowID := rand.Uint32() & ((^uint32(0)) >> s)
    size := uint32(500)
    timestamp := t_l + 1
    oldLevel := detector.level
    detector.Detect(flowID, size, timestamp)
    index := (flowID & (((1 << s) - 1) << (32 - 2*s))) >> (32 - 2*s)
    if detector.level != oldLevel + 1 {
        t.Errorf("Detect failed: level is %d, should be %d.\n", detector.level, oldLevel + 1)
    }
    if detector.counters[index].count != size {
        t.Errorf("Detect failed: count is %d, should be %d.\n", detector.counters[index].count, size)
    }
    if detector.counters[index].reset {
        t.Errorf("Detect failed: reset is %t, should be true.\n", detector.counters[index].reset)
    }
    if detector.now != t_l {
        t.Errorf("Detect failed: t_l is %d, should be %d.\n", detector.t_l, t_l)
    }
    // fmt.Println(detector.counters)
}

//insert two simple packages
func TestInsertTwo(t *testing.T) {
    detector := NewRlfdDtctr(beta, gamma, t_l)
    flowID := uint32(0x20000000)
    size := uint32(500)
    timestamp := time.Duration(0)
    detector.Detect(flowID, size, timestamp)
    detector.Detect(flowID, size, timestamp + 1)
    index := (flowID & (((1 << s) - 1) << (32 - s))) >> (32 - s)
    if detector.level != 0 {
        t.Errorf("Detect failed: level is %d, should be 0.\n", detector.level)
    }
    if detector.counters[index].count != 2*size {
        t.Errorf("Detect failed: count is %d, should be %d.\n", detector.counters[index].count, 2*size)
    }
    if !detector.counters[index].reset {
        t.Errorf("Detect failed: reset is %t, should be true.\n", detector.counters[index].reset)
    }
    //fmt.Println(detector.counters)
}


func TestSetPathCorrectly(t *testing.T) {
    detector := NewRlfdDtctr(beta, gamma, t_l)
    flowIDs := [7]uint32{0x20000000, 0x28000000, 0x29800000, 0x29C00000, 0x29CA0000, 0x29CB8000, 0x29CBB800}
    sizes := [7]uint32{100, 200, 300, 400, 500, 600, 700}
    timestamps := [7]time.Duration{0, t_l + 1, 2*t_l + 1, 3*t_l + 1, 4*t_l + 1, 5*t_l + 1, 6*t_l + 1}
    expectedPaths := [7]uint32{0x0, 0x20000000, 0x28000000, 0x29800000, 0x29c00000, 0x29ca0000, 0x29cb8000}
    for i := 0; i < 7; i++ {
        detector.Detect(flowIDs[i], sizes[i], timestamps[i])
        if detector.path != expectedPaths[i] {
            t.Errorf("Detect failed: path is not set correctly, should be 0x%x but is 0x%x.\n", 
                expectedPaths[i], detector.path)
        }
        if uint32(i) != detector.level {
            t.Errorf("Detect failed: level is not set correctly, should be %d but is %d.\n",
                i, detector.level)
        }
        // fmt.Println(detector.counters)
    }
}

func TestSameFlowOverManyLevelsAlwaysSameBucket(t *testing.T) {
    detector := NewRlfdDtctr(beta, gamma, t_l)
    flowID := uint32(0x24924800)
    size := uint32(100)
    timestamps := [7]time.Duration{0, t_l + 1, 2*t_l + 1, 3*t_l + 1, 4*t_l + 1, 5*t_l + 1, 6*t_l + 1}
    expectedPaths := [7]uint32{0x0, 0x20000000, 0x24000000, 0x24800000, 0x24900000, 0x24920000, 0x24924000}
    for i := 0; i < 7; i++ {
        detector.Detect(flowID, size, timestamps[i])
        if detector.path != expectedPaths[i] {
            t.Errorf("Detect failed: path is not set correctly, should be 0x%x but is 0x%x.\n", 
                expectedPaths[i], detector.path)
        }
        if uint32(i) != detector.level {
            t.Errorf("Detect failed: level is not set correctly, should be %d but is %d.\n",
                i, detector.level)
        }
        if detector.counters[1 % m].count != size {
            t.Errorf("Detect failed: count is not set correctly, should be %d but is %d.\n",
             size, detector.counters[1 % m].count)
        }
        if detector.counters[1 % m].reset != detector.reset {
            t.Errorf("Detect failed: reset is not set correctly, should be %t but is %t.\n",
             detector.reset, detector.counters[1 % m].reset)
        }
    }
    if detector.counters[1 % m].flowID != flowID {
        t.Errorf("Detect failed: flowID is not set correctly, should be %d but is %d.\n",
         flowID, detector.counters[1 % m].flowID)
    }
}

func TestDetectFlow(t *testing.T) {
    detector := NewRlfdDtctr(beta, gamma, t_l)
    flowID := uint32(0x24924800)
    size := uint32(100600)
    timestamps := [7]time.Duration{0, t_l + 1, 2*t_l + 1, 3*t_l + 1, 4*t_l + 1, 5*t_l + 1, 6*t_l + 1}
    expectedPaths := [7]uint32{0x0, 0x20000000, 0x24000000, 0x24800000, 0x24900000, 0x24920000, 0x24924000}
    var res bool
    for i := 0; i < 7; i++ {
        res = detector.Detect(flowID, size, timestamps[i])
        if i < 6 && res {
            t.Errorf("Detect failed: returns %t but should return %t.\n",
             res, false)
        }
        if i == 6 && !res {
            t.Errorf("Detect failed: returns %t but should return %t.\n",
             res, true)
        }
        if detector.path != expectedPaths[i] {
            t.Errorf("Detect failed: path is not set correctly, should be 0x%x but is 0x%x.\n", 
                expectedPaths[i], detector.path)
        }
        if uint32(i) != detector.level {
            t.Errorf("Detect failed: level is not set correctly, should be %d but is %d.\n",
                i, detector.level)
        }
        if detector.counters[1 % m].count != size {
            t.Errorf("Detect failed: count is not set correctly, should be %d but is %d.\n",
             size, detector.counters[1 % m].count)
        }
        if detector.counters[1 % m].reset != detector.reset {
            t.Errorf("Detect failed: reset is not set correctly, should be %t but is %t.\n",
             detector.reset, detector.counters[1 % m].reset)
        }
    }
    if detector.counters[1 % m].flowID != flowID {
        t.Errorf("Detect failed: flowID is not set correctly, should be %d but is %d.\n",
         flowID, detector.counters[1 % m].flowID)
    }
    // fmt.Println(detector.counters)
    // fmt.Println(detector.th_rlfd)
}

func TestTime(t *testing.T) {
    now := 7*t_l + 5
    detector := NewRlfdDtctr(beta, gamma, t_l)
    detector.SetCurrentTime(now)
    detector.Detect(0, 0, now + 2*t_l + 1)
    detector.Detect(0, 0, now + 2*t_l + 2)
    if detector.level != 1 {
        t.Errorf("Detect failed: level is not set correctly, should be %d but is %d.\n",
            1, detector.level)
    }
}






