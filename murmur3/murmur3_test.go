// tests and benchmarks for the murmur3 package
package murmur3

import (
	"math/rand"
	"testing"
	"time"
	"unsafe"

	spaolacciMurmur "github.com/spaolacci/murmur3"
	zhangMurmur "github.com/zhangxinngang/murmur"
)

var r uint32 = 0

func TestMurmur_32CorrectDeterministic(t *testing.T) {
	var tests = []struct{
		input [8]byte
	}{
		{[8]byte{0, 0, 0, 0, 0, 0, 0, 0}},
		{[8]byte{1, 0, 0, 0, 0, 0, 0, 0}},
		{[8]byte{2, 3, 2, 255, 2, 3, 2, 3}},
		{[8]byte{3, 0, 3, 0, 3, 0, 3, 0}},
		{[8]byte{0, 0, 0, 4, 5, 0, 0, 0}},
		{[8]byte{9, 0, 8, 0, 7, 0, 6, 0}},
		{[8]byte{7, 6, 5, 4, 3, 2, 1, 0}},
		{[8]byte{255, 255, 255, 255, 255, 255, 255, 255}},
	}
	setSeed(0) //since the spaolacci implementation always uses seed = 0
	for i := 0; i < len(tests); i++ {
		res := Murmur3_32(&(tests[i].input))
		exp := spaolacciMurmur.Sum32((tests[i].input)[:])
		if res != exp {
			t.Errorf("murmur3 failed: Got 0x%x, expected 0x%x\n", res, exp)
		}
	}
}

func TestMurmur_32CorrectRandom(t *testing.T) {
	tests := makeInput(100)
	setSeed(0) //since the spaolacci implementation always uses seed = 0
	for i := 0; i < len(tests); i++ {
		res := Murmur3_32(&tests[i])
		exp := spaolacciMurmur.Sum32(tests[i][:])
		if res != exp {
			t.Errorf("murmur3(0x%x) failed: Got 0x%x, expected 0x%x\n", *((* uint64)(unsafe.Pointer(&tests[i]))), res, exp)
		}
	}
}

//make random input for the benchmarks
func makeInput(n int) [][8]byte {
	s := make([][8]byte, n)
	source := rand.NewSource(time.Now().UnixNano())
	r := rand.New(source)
	randNum := uint64(0)
	for i := 0; i < n; i++ {
		randNum = uint64(r.Uint32()) << 32 + uint64(r.Uint32())
		s[i] = *((* [8]byte)(unsafe.Pointer(&randNum)))
	}
	return s
}

func BenchmarkZhangMurmur(b *testing.B) {
	// key := [8]byte{1, 0, 0, 0, 0, 6, 0, 0}
	// k := key[:]
	input := makeInput(b.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r = zhangMurmur.Murmur3(input[i][:])
	}
}

func BenchmarkSpaolacciMurmur(b *testing.B) {
	// key := [8]byte{1, 0, 0, 0, 0, 6, 0, 0}
	// k := key[:]
	input := makeInput(b.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r = spaolacciMurmur.Sum32(input[i][:])
	}
}

func BenchmarkMyMurmur(b *testing.B) {
	// key := [8]byte{1, 0, 0, 0, 0, 6, 0, 0}
	// k := &key
	ResetSeed()
	input := makeInput(b.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r = Murmur3_32(&input[i])
	}
}