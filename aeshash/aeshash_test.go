package aeshash

import (
	"testing"
	"fmt"
	"crypto/rand"
	"time"

	"github.com/hosslen/lfd/murmur3"
)


//-----------------------------------------------------------
// Test whether AESHasher computes an expected hash value
func TestAESHasher(t *testing.T) {
	seed := []byte("ABCDEFGHIJKLMNOP")
	aesh := NewAESHasher(seed)
	input := [16]byte{}
	copy(input[:], []byte("Hello World!"))
	output := aesh.Hash_uint32(&input)
	if (output != 3635243428) {
		t.Errorf("Wrong hash value.")
	}
	fmt.Printf("Hash value: '%d'\n", output)
}


//-----------------------------------------------------------
// Compare the runtimes of the Murmur3 hash implementation
//  and the AES hashing implementation
func TestComparisonWithMurmur3(t *testing.T) {

	// Generate seed
	seed := make([]byte, 16)
	_, err := rand.Read(seed)
	aesh := NewAESHasher(seed)
	if (err != nil) {
		fmt.Print("Error: ")
		fmt.Println(err)
		return
	}

	// Prepare inputs
	const n_inputs = 1000000
	inputs := [n_inputs](*[16]byte){}
	for i := 0; i < n_inputs; i++ {
		inputs[i] = &([16]byte{})
		_, err := rand.Read((*(inputs[i]))[:])
		if (err != nil) {
			fmt.Println(err)
			break
		}
	}

	var start time.Time
	var elapsed time.Duration

	// Measure Murmur3
	start = time.Now()
	for i := 0; i < n_inputs; i++ {
		murmur3.Murmur3_32_caida(inputs[i])
	}
	elapsed = time.Since(start)
	fmt.Printf("Average time per operation for Murmur3: %.2fns\n", float64(elapsed)/float64(n_inputs))

	// Measure AESHasher
	start = time.Now()
	for i := 0; i < n_inputs; i++ {
		aesh.Hash_uint32(inputs[i])
	}
	elapsed = time.Since(start)
	fmt.Printf("Average time per operation for AESHasher: %.2fns\n", float64(elapsed)/float64(n_inputs))

}
