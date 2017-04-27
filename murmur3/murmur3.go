// this package contains an implementation of murmur3 (the 32 bits version)
package murmur3

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"unsafe"
)

var seed uint32 = 0

// resets the seed of the hashfunction, uses the pseudo random generator of crypto/rand
func ResetSeed() {
	s := make([]byte, 4)
	_, err := rand.Read(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
	}
	seed = binary.LittleEndian.Uint32(s)
}

func setSeed(s uint32) {
	seed = s
}

//based on pseudo code from https://en.wikipedia.org/wiki/MurmurHash
func Murmur3_32(key *[8]byte) uint32 {
	arrayPointer := (*[2]uint32)(unsafe.Pointer(key))
	hash := seed
	var k uint32
	for i := 0; i < 2; i++ {
		k = (*arrayPointer)[i]

		k *= 0xcc9e2d51
		k = (k << 15) | (k >> 17)
		k *= 0x1b873593

		hash ^= k
		hash = (hash << 13) | (hash >> 19)
		hash *= 5
		hash += 0xe6546b64
	}

	//here we would deal with the remaining bytes
	//there are none in this case

	hash ^= 8

	hash ^= (hash >> 16)
	hash *= 0x85ebca6b
	hash ^= (hash >> 13)
	hash *= 0xc2b2ae35
	hash ^= (hash >> 16)

	return hash
}

//for the caida packet traces
func Murmur3_32_caida(key *[12]byte) uint32 {
	arrayPointer := (*[3]uint32)(unsafe.Pointer(key))
	hash := seed
	var k uint32
	for i := 0; i < 3; i++ {
		k = (*arrayPointer)[i]

		k *= 0xcc9e2d51
		k = (k << 15) | (k >> 17)
		k *= 0x1b873593

		hash ^= k
		hash = (hash << 13) | (hash >> 19)
		hash *= 5
		hash += 0xe6546b64
	}

	//here we would deal with the remaining bytes
	//there are none in this case

	hash ^= 8

	hash ^= (hash >> 16)
	hash *= 0x85ebca6b
	hash ^= (hash >> 13)
	hash *= 0xc2b2ae35
	hash ^= (hash >> 16)

	return hash
}