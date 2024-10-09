// MIT License
//
// Copyright (c) 2024 sphinx-core
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package spxhash

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"sync"

	"golang.org/x/crypto/sha3"
)

// References
// https://crypto.stackexchange.com/questions/270/guarding-against-cryptanalytic-breakthroughs-combining-multiple-hash-functions/328#328
// https://stackoverflow.com/questions/5889238/why-is-xor-the-default-way-to-combine-hashes

// SphinxHash is a structure that encapsulates the combination and hashing logic.
type SphinxHash struct {
	bitSize int               // Specifies the bit size of the hash (128, 256, 384, 512)
	data    []byte            // Holds the input data to be hashed
	cache   map[string][]byte // Cache to store previously computed hashes
	mutex   sync.Mutex        // Mutex to protect access to the cache
}

// Define prime constants for hash calculations.
const (
	prime32 = 0x9e3779b9         // Example prime constant for 32-bit hash
	prime64 = 0x9e3779b97f4a7c15 // Example prime constant for 64-bit hash
)

// NewSphinxHash creates a new SphinxHash with a specific bit size for the hash.
func NewSphinxHash(bitSize int) *SphinxHash {
	s := &SphinxHash{
		bitSize: bitSize,
		data:    nil,                     // Initialize data to nil
		cache:   make(map[string][]byte), // Initialize cache
	}

	// Example input data (you can modify this as needed)
	inputData := []byte("sample input data")

	// Perform hash calculations using the provided input data
	chainedHash := s.ChainedHash(inputData)

	_ = chainedHash // Store or print as needed

	return s
}

// Write adds data to the hash.
func (s *SphinxHash) Write(p []byte) (n int, err error) {
	s.data = append(s.data, p...) // Append new data to the existing data
	return len(p), nil            // Return the number of bytes written
}

// Sum appends the current hash to b and returns the resulting slice.
func (s *SphinxHash) Sum(b []byte) []byte {
	hash := s.GetHash(s.data) // Compute the hash of the current data
	return append(b, hash...) // Append the hash to the provided byte slice
}

// Size returns the number of bytes in the hash based on the bit size.
func (s *SphinxHash) Size() int {
	switch s.bitSize {
	case 128:
		return 16 // 128 bits = 16 bytes
	case 256:
		return 32 // 256 bits = 32 bytes
	case 384:
		return 48 // 384 bits = 48 bytes
	case 512:
		return 64 // 512 bits = 64 bytes
	default:
		return 32 // Default to 256 bits
	}
}

// BlockSize returns the hash block size based on the current bit size configuration.
func (s *SphinxHash) BlockSize() int {
	switch s.bitSize {
	case 128:
		return 168 // For SHAKE128
	case 256:
		return 64 // For SHA-256
	case 384:
		return 128 // For SHA-384
	case 512:
		return 128 // For SHA-512
	default:
		return 64 // Defaulting to SHA-256 block size
	}
}

// hashData calculates the combined hash of data using multiple hash functions based on the bit size.
func (s *SphinxHash) hashData(data []byte) []byte {
	var sha2Hash []byte

	// Generate SHA2 and SHAKE hashes based on the bit size
	switch s.bitSize {
	case 128:
		shake := sha3.NewShake128()   // Create a new SHAKE128 instance
		shake.Write(data)             // Write the input data to the SHAKE instance
		shakeHash := make([]byte, 16) // 128 bits = 16 bytes
		shake.Read(shakeHash)         // Read the generated hash
		return shakeHash              // Return the 128-bit hash
	case 256:
		hash := sha256.Sum256(data)                      // Compute the SHA-256 hash
		sha2Hash = hash[:]                               // Convert the array to a slice
		return s.sphinxHash(sha2Hash, sha2Hash, prime32) // Combine the hash
	case 384:
		hash := sha512.Sum384(data)                      // Compute the SHA-384 hash
		sha2Hash = hash[:]                               // Convert the array to a slice
		return s.sphinxHash(sha2Hash, sha2Hash, prime64) // Combine the hash
	case 512:
		hash := sha512.Sum512(data)                      // Compute the SHA-512 hash
		sha2Hash = hash[:]                               // Convert the array to a slice
		return s.sphinxHash(sha2Hash, sha2Hash, prime64) // Combine the hash
	default:
		shake := sha3.NewShake256()   // Create a new SHAKE256 instance
		shake.Write(data)             // Write the input data to the SHAKE instance
		shakeHash := make([]byte, 32) // 256 bits = 32 bytes
		shake.Read(shakeHash)         // Read the generated hash
		return shakeHash              // Return the 256-bit hash
	}
}

// sphinxHash combines two byte slices (hash1 and hash2) using a prime constant and applies structured combinations.
func (s *SphinxHash) sphinxHash(hash1, hash2 []byte, primeConstant uint64) []byte {
	if len(hash1) != len(hash2) {
		panic("hash1 and hash2 must have the same length") // Ensure both hashes are of the same length
	}

	randomFactor, err := secureRandomUint64() // Generate a secure random uint64 value
	if err != nil {
		panic("failed to generate random factor") // Panic if random factor generation fails
	}

	sphinxHash := make([]byte, len(hash1)) // Create a slice for the final combined hash

	// Iterate over each byte of the input hashes and combine them using structured combinations.
	for i := 0; i < len(hash1); i++ {
		h1 := uint64(hash1[i]) // Convert the byte from hash1 to uint64
		h2 := uint64(hash2[i]) // Convert the byte from hash2 to uint64

		// Structured combination formula:
		// combined = (h1 * 3 + h2 + randomFactor) ^ primeConstant
		combined := (h1*3 + h2 + randomFactor) ^ primeConstant // Combine and apply the prime constant
		sphinxHash[i] = byte(combined)                         // Store the combined result as a byte
	}

	return sphinxHash // Return the final combined hash
}

// GetHash generates the hash for the given data, using cache for previously computed results.
func (s *SphinxHash) GetHash(data []byte) []byte {
	// Convert data to string for cache key (consider better hashing if data is large or complex)
	cacheKey := string(data)

	s.mutex.Lock() // Lock the mutex to protect access to the cache
	if cachedHash, exists := s.cache[cacheKey]; exists {
		s.mutex.Unlock()  // Unlock the mutex if we found the cached hash
		return cachedHash // Return the cached hash
	}
	s.mutex.Unlock() // Unlock the mutex if cache miss

	// If not found in cache, compute the hash
	hash := s.hashData(data)

	// Store the computed hash in cache
	s.mutex.Lock() // Lock the mutex again to write to cache
	s.cache[cacheKey] = hash
	s.mutex.Unlock() // Unlock the mutex after updating the cache

	return hash // Return the newly computed hash
}

// secureRandomUint64 generates a secure random uint64 value.
func secureRandomUint64() (uint64, error) {
	b := make([]byte, 8)   // Create a byte slice to hold 8 bytes (64 bits)
	_, err := rand.Read(b) // Read random bytes into the slice
	if err != nil {
		return 0, err // Return error if random generation fails
	}

	return binary.BigEndian.Uint64(b), nil // Convert bytes to uint64 and return
}

// ChainedHash computes a combined hash of the input data using both SHA-256 and SHAKE-256.
func (s *SphinxHash) ChainedHash(data []byte) []byte {
	// Calculate H1 by applying the SHA-256 hash function to the input data.
	h1 := sha256.Sum256(data)

	// Calculate H2 using the SHAKE-256 hash function.
	shake := sha3.NewShake256()
	shake.Write(data)
	h2 := make([]byte, 32) // Prepare a byte slice for SHAKE-256 output.
	shake.Read(h2)         // Read the output from the SHAKE-256 instance into h2.

	// Initialize a byte slice for the combined hash.
	combinedHash := make([]byte, 32)

	// Combine the two hash results (H1 and H2).
	h1Int := byteArrayToUint64(h1[:]) // Convert the SHA-256 hash to uint64.
	h2Int := byteArrayToUint64(h2)    // Convert the SHAKE-256 hash to uint64.

	// Combine H1 and H2 using XOR and return the result.
	for i := 0; i < len(combinedHash); i++ {
		combinedHash[i] = byte(h1Int ^ h2Int) // Combine using XOR.
	}

	return combinedHash // Return the final combined hash.
}

// byteArrayToUint64 converts a byte array to a uint64 integer.
func byteArrayToUint64(data []byte) uint64 {
	if len(data) < 8 {
		panic("byteArrayToUint64: data length less than 8") // Ensure sufficient length
	}
	return binary.BigEndian.Uint64(data[:8]) // Convert first 8 bytes to uint64
}
