// This package leverages the AES block cipher for hashing
package aeshash

import (
    "crypto/aes"
    "crypto/cipher"
    "encoding/binary"
)

//---------------------------------------------------
// Wrapper object for AES hashing
type AESHasher struct {
    seed []byte
    hasher cipher.Block
    output []byte
}

//---------------------------------------------------
// Object Instantiation
func NewAESHasher(seed []byte) *AESHasher {
    aesh := &AESHasher{}
    aesh.SetSeed(seed)
    return aesh
}

//---------------------------------------------------
// (Re)set seed
func (aesh *AESHasher) SetSeed(seed []byte) {

    aesh.seed = make([]byte, len(seed))
    copy(aesh.seed, seed)

    var err error
    aesh.hasher, err = aes.NewCipher(aesh.seed)
    if (err != nil) { panic(err) }

    aesh.output = make([]byte, len(seed))

}

//---------------------------------------------------
// Get seed
func (aesh *AESHasher) GetSeed() []byte {
    return aesh.seed
}

//---------------------------------------------------
// Use AES encryption as a hash function on an input
func (aesh *AESHasher) Hash_uint32(input *[16]byte) uint32 {
    aesh.hasher.Encrypt(aesh.output, (*input)[:])
    return binary.LittleEndian.Uint32(aesh.output)

}

//---------------------------------------------------
// Use AES encryption as a hash function on an input
func (aesh *AESHasher) Hash_uint64(input *[16]byte) uint64 {
    aesh.hasher.Encrypt(aesh.output, (*input)[:])
    return binary.LittleEndian.Uint64(aesh.output)

}