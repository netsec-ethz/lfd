package baseline

import (
    // "fmt"
    "testing"
    "time"
)

func insertPacket(t *testing.T, bd *BaselineDtctr, flowID uint32, size uint32, timestamp time.Duration) bool {
    res := bd.Detect(flowID, size, timestamp)

    b := bd.buckets[flowID]
    if b == nil {
        t.Errorf("Detect: Packet(%d, %d, %d) not correctly inserted, corresponding bucket is nil.\n",
            flowID, size, timestamp)
    }

    if b.count < float64(size)  || b.timestamp != timestamp {
        t.Errorf("Detect: Packet(%d, %d, %d) not correctly inserted, b.count=%f, b.timestamp=%d.\n",
            flowID, size, timestamp, b.count, b.timestamp)
    }
    return res
}

//insert a packet and test that it is present in the map
func TestDetectBasicInsert(t *testing.T) {
    detector := NewBaselineDtctr(1000.0, 5.0)
    insertPacket(t, detector, 0, 100, 0)
}

//insert two packets for the same flowID and test that count is properly decremented/ incremented
func TestDetectMultiInsert(t *testing.T) {
    detector := NewBaselineDtctr(1000.0, 5.0)
    insertPacket(t, detector, 0, 100, 0)
    insertPacket(t, detector, 0, 200, 1)
    b := detector.buckets[0]
    if b.count != 295.0 {
        t.Errorf("Detect: Packet(0, 200, 1) not correctly inserted, b.count=%f, b.timestamp=%d.\n",
            b.count, b.timestamp)
    }
}

//insert a packet that triggers detection
func TestDetectDetection(t *testing.T) {
    detector := NewBaselineDtctr(1000.0, 5.0)
    if res := insertPacket(t, detector, 1, 2000, 0); !res {
        t.Errorf("Detect: Packet(1, 2000, 0) is not detected, should be.")
    }
}



