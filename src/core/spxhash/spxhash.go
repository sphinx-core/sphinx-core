package spxhash

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/sha3"
)

// SphinxHash is a structure that encapsulates the combination and hashing logic
type SphinxHash struct {
	bitSize int
	data    []byte
}

const (
	prime32 = 0x9e3779b9         // Example prime constant for 32-bit hash
	prime64 = 0x9e3779b97f4a7c15 // Example prime constant for 64-bit hash
)

// NewSphinxHash creates a new SphinxHash with a specific bit size for the hash
func NewSphinxHash(bitSize int) *SphinxHash {
	return &SphinxHash{
		bitSize: bitSize,
		data:    nil,
	}
}

// Write adds data to the hash
func (s *SphinxHash) Write(p []byte) (n int, err error) {
	s.data = append(s.data, p...)
	return len(p), nil
}

// Sum appends the current hash to b and returns the resulting slice
func (s *SphinxHash) Sum(b []byte) []byte {
	hash := s.hashData(s.data)
	return append(b, hash...)
}

// Size returns the number of bytes in the hash
func (s *SphinxHash) Size() int {
	switch s.bitSize {
	case 128:
		return 16
	case 256:
		return 32
	case 384:
		return 48
	case 512:
		return 64
	default:
		return 32
	}
}

// BlockSize returns the hash block size (dummy implementation)
func (s *SphinxHash) BlockSize() int {
	return 1
}

// hashData calculates the combined hash of data using multiple hash functions based on the bit size
func (s *SphinxHash) hashData(data []byte) []byte {
	var sha2Hash []byte
	var shakeHash []byte
	var combinedHash []byte

	// Generate SHA2 and SHAKE hashes based on the bit size
	switch s.bitSize {
	case 128:
		// Use SHAKE128 to generate a 128-bit hash
		shake := sha3.NewShake128()
		shake.Write(data)
		shakeHash = make([]byte, 16) // 128 bits = 16 bytes
		shake.Read(shakeHash)
		return shakeHash
	case 256:
		// Use SHA-256 to generate a 256-bit hash
		hash := sha256.Sum256(data) // Returns [32]byte
		sha2Hash = hash[:]
		// Use SHAKE256 to generate a 256-bit hash for added security
		shake := sha3.NewShake256()
		shake.Write(data)
		shakeHash = make([]byte, 32) // 256 bits = 32 bytes
		shake.Read(shakeHash)
		// Combine SHA-2 and SHAKE hashes
		combinedHash = s.sphinxHash(sha2Hash, shakeHash, prime32)
		return s.sphinxHash(combinedHash, combinedHash, prime32) // Double hashing for extra security
	case 384:
		// Use SHA-384 to generate a 384-bit hash
		hash := sha512.Sum384(data) // Returns [48]byte
		sha2Hash = hash[:]
		// Use SHAKE256 to generate a 384-bit hash for added security
		shake := sha3.NewShake256()
		shake.Write(data)
		shakeHash = make([]byte, 48) // 384 bits = 48 bytes
		shake.Read(shakeHash)
		// Combine SHA-2 and SHAKE hashes
		combinedHash = s.sphinxHash(sha2Hash, shakeHash, prime64)
		return s.sphinxHash(combinedHash, combinedHash, prime64) // Double hashing for extra security
	case 512:
		// Use SHA-512 to generate a 512-bit hash
		hash := sha512.Sum512(data) // Returns [64]byte
		sha2Hash = hash[:]
		// Use SHAKE256 to generate a 512-bit hash for added security
		shake := sha3.NewShake256()
		shake.Write(data)
		shakeHash = make([]byte, 64) // 512 bits = 64 bytes
		shake.Read(shakeHash)
		// Combine SHA-2 and SHAKE hashes
		combinedHash = s.sphinxHash(sha2Hash, shakeHash, prime64)
		return s.sphinxHash(combinedHash, combinedHash, prime64) // Double hashing for extra security
	default:
		// Default to 256-bit SHAKE256 if no bit size matches
		shake := sha3.NewShake256()
		shake.Write(data)
		shakeHash = make([]byte, 32) // 256 bits = 32 bytes
		shake.Read(shakeHash)
		return shakeHash
	}
}

// sphinxHash combines two byte slices (hash1 and hash2) using a prime constant.
// It ensures constant-time operation to mitigate timing attacks by avoiding any data-dependent branches.
func (s *SphinxHash) sphinxHash(hash1, hash2 []byte, primeConstant uint64) []byte {
	// Ensure that both hash slices are of the same length, as we combine corresponding bytes.
	if len(hash1) != len(hash2) {
		panic("hash1 and hash2 must have the same length")
	}

	// Introduce a random factor for added entropy in the hash combination.
	// This random value is generated securely using crypto/rand.
	randomFactor, err := secureRandomUint64() // Generate a secure random uint64 value
	if err != nil {
		panic("failed to generate random factor")
	}

	// Create a slice to hold the final combined hash. The length matches that of hash1 (and hash2).
	sphinxHash := make([]byte, len(hash1))

	// Iterate over each byte of the input hashes and combine them.
	for i := 0; i < len(hash1); i++ {
		// Convert each byte from hash1 and hash2 to uint64 for arithmetic operations.
		h1 := uint64(hash1[i]) // First byte from hash1
		h2 := uint64(hash2[i]) // Corresponding byte from hash2

		// Combine the two hash values with constant-time operations:
		// 1. Multiply h1 by 3 to spread out the bits and increase the mixing effect.
		// 2. Add h2 (second hash) to the result.
		// 3. Add the secure random factor for unpredictability.
		combined := h1*3 + h2 + randomFactor

		// XOR the combined result with the prime constant to further mix the bits and add complexity.
		sphinxHash[i] = byte(combined ^ primeConstant)
	}

	// Return the final combined hash as a byte slice.
	return sphinxHash
}

// Add the new exported method
func (s *SphinxHash) GetHash(data []byte) []byte {
	return s.hashData(data)
}

// secureRandomUint64 generates a secure random uint64 value
func secureRandomUint64() (uint64, error) {
	b := make([]byte, 8)
	_, err := rand.Read(b)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b), nil
}

func main() {
	// Example data to hash
	data := []byte("Hello world!")

	// Print the original data
	fmt.Printf("Original Data: %s\n", data)

	// Create a new SphinxHash object with the chosen bit size
	sphinx := NewSphinxHash(256) // Change this to 128, 256, 384, or 512

	// Hash the data using the SphinxHash object
	sphinxHash := sphinx.hashData(data)

	// Print the combined hash
	fmt.Printf("Sphinx Hash (%d-bit) %d bytes: %x\n", sphinx.bitSize, len(sphinxHash), sphinxHash)
}
