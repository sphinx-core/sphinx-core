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
	"encoding/binary"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/sha3"
)

// SIPS-0001 https://github.com/sphinx-core/sips/wiki/SIPS-0001

// LRUCache is a struct for the LRU cache implementation.
type LRUCache struct {
	capacity int              // Maximum capacity of the cache
	mu       sync.Mutex       // Mutex for concurrent access
	cache    map[uint64]*Node // Maps keys to their corresponding nodes in the cache
	head     *Node            // Pointer to the most recently used node
	tail     *Node            // Pointer to the least recently used node
}

// Node is a doubly linked list node for the LRU cache.
type Node struct {
	key   uint64 // Unique key for the node
	value []byte // Value associated with the key
	prev  *Node  // Pointer to the previous node in the list
	next  *Node  // Pointer to the next node in the list
}

// NewLRUCache initializes a new LRU cache.
func NewLRUCache(capacity int) *LRUCache {
	return &LRUCache{
		capacity: capacity,               // Set the cache capacity
		cache:    make(map[uint64]*Node), // Initialize the cache map
	}
}

// Get retrieves a value from the cache.
func (l *LRUCache) Get(key uint64) ([]byte, bool) {
	l.mu.Lock()         // Lock the cache for concurrent access
	defer l.mu.Unlock() // Ensure the lock is released after the function completes

	if node, found := l.cache[key]; found {
		l.moveToFront(node) // Move accessed node to the front (most recently used)
		return node.value, true
	}
	return nil, false // Return nil if key is not found
}

// Put inserts a value into the cache.
func (l *LRUCache) Put(key uint64, value []byte) {
	l.mu.Lock()         // Lock the cache for concurrent access
	defer l.mu.Unlock() // Ensure the lock is released after the function completes

	if node, found := l.cache[key]; found {
		node.value = value  // Update the value if the key already exists
		l.moveToFront(node) // Move the updated node to the front
		return
	}

	// Create a new node if the key is not found
	node := &Node{key: key, value: value}
	l.cache[key] = node // Add new node to the cache

	// If the cache is empty, set head and tail to the new node
	if l.head == nil {
		l.head = node
		l.tail = node
	} else {
		node.next = l.head // Insert new node at the front of the linked list
		l.head.prev = node
		l.head = node
	}

	// Evict the least recently used item if cache exceeds capacity
	if len(l.cache) > l.capacity {
		l.evict() // Call eviction method to remove the least recently used item
	}
}

// evict removes the least recently used item from the cache.
func (l *LRUCache) evict() {
	if l.tail == nil {
		return // Do nothing if the cache is empty
	}
	delete(l.cache, l.tail.key) // Remove the least recently used key from the cache
	l.tail = l.tail.prev        // Move the tail pointer to the previous node
	if l.tail != nil {
		l.tail.next = nil // Set the next pointer of the new tail to nil
	}
}

// moveToFront moves a node to the front of the linked list.
func (l *LRUCache) moveToFront(node *Node) {
	if node == l.head {
		return // No need to move if the node is already at the front
	}
	if node.prev != nil {
		node.prev.next = node.next // Bypass the node in the linked list
	}
	if node.next != nil {
		node.next.prev = node.prev // Bypass the node in the linked list
	}
	if node == l.tail {
		l.tail = node.prev // Update the tail if the node being moved is the tail
	}
	node.prev = nil
	node.next = l.head // Move the node to the front
	l.head.prev = node
	l.head = node
}

// SphinxHash implements hashing based on SIP-0001 draft.
type SphinxHash struct {
	bitSize      int       // Specifies the bit size of the hash (128, 256, 384, 512)
	data         []byte    // Holds the input data to be hashed
	salt         []byte    // Salt for hashing
	cache        *LRUCache // Cache to store previously computed hashes
	maxCacheSize int       // Maximum cache size
}

// Define prime constants for hash calculations.
const (
	prime32     = 0x9e3779b9         // Example prime constant for 32-bit hash
	prime64     = 0x9e3779b97f4a7c15 // Example prime constant for 64-bit hash
	saltSize    = 16                 // Size of salt in bytes
	memory      = 64 * 1024          // Memory cost (in KB) for Argon2
	iterations  = 4                  // Number of iterations for Argon2
	parallelism = 6                  // Number of parallel threads for Argon2
)

// NewSphinxHash creates a new SphinxHash with a specific bit size for the hash.
func NewSphinxHash(bitSize int, maxCacheSize int) *SphinxHash {
	return &SphinxHash{
		bitSize:      bitSize,
		data:         nil,
		salt:         generateRandomSalt(),      // Generate random salt
		cache:        NewLRUCache(maxCacheSize), // Initialize LRU cache
		maxCacheSize: maxCacheSize,              // Set maximum cache size
	}
}

// generateRandomSalt creates a new random salt.
func generateRandomSalt() []byte {
	salt := make([]byte, saltSize)
	_, err := rand.Read(salt)
	if err != nil {
		panic("failed to generate random salt") // Panic if random salt generation fails
	}
	return salt
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
	case 256:
		return 136 // For SHAKE256 or SHA-256 (you can adjust based on SHAKE256 preference)
	case 384:
		return 128 // For SHA-384
	case 512:
		return 128 // For SHA-512
	default:
		return 64 // Defaulting to SHA-256 block size for unspecified sizes
	}
}

// hashData calculates the combined hash of data using multiple hash functions based on the bit size.
// It computes SHA-256 and SHAKE256 based on the stretched key and combines them using SphinxHash.
func (s *SphinxHash) hashData(data []byte) []byte {
	var sha2Hash []byte

	// Combine data with salt for Argon2id
	combined := append(data, s.salt...)                                                 // Combine data and salt
	stretchedKey := argon2.IDKey(combined, s.salt, iterations, memory, parallelism, 64) // Key stretching with Argon2id

	// Step 1: Compute SHA-256
	hash := sha256.Sum256(stretchedKey) // Compute the SHA-256 hash
	sha2Hash = hash[:]                  // Convert the array to a slice

	// Step 2: Compute SHAKE256
	shake := sha3.NewShake256()
	shake.Write(stretchedKey)     // Use stretched key for SHAKE256 as well
	shakeHash := make([]byte, 32) // 256 bits = 32 bytes
	shake.Read(shakeHash)

	// Step 3: Combine the hashes using SphinxHash
	return s.sphinxHash(sha2Hash, shakeHash, prime32) // Combine SHA-256 and SHAKE256 results
}

// sphinxHash combines two byte slices (hash1 and hash2) using a prime constant and applies structured combinations.
// It utilizes chaining (H∘(x) = H0(H1(x))) and concatenation (H|(x) = H0(x)|H1(x)) of hash functions to enhance pre-image and collision resistance.
func (s *SphinxHash) sphinxHash(hash1, hash2 []byte, primeConstant uint64) []byte {
	// Check that both hash inputs have the same length; if not, panic with an error message.
	if len(hash1) != len(hash2) {
		panic("hash1 and hash2 must have the same length") // Ensures both hashes are of the same length for consistent processing
	}

	// Step 1: Hash the input hashes to protect against pre-images.
	// Chaining: H∘(x) = H0(H1(x))
	// Hashing hash1 first
	chainHash1 := sha256.Sum256(hash1)

	// Hashing hash2 first
	chainHash2 := sha256.Sum256(hash2)

	// Step 2: Initialize the output slice for the SphinxHash, with the combined length of the chained hashes.
	sphinxHash := make([]byte, len(chainHash1)) // Using the length of chainHash1 for initialization

	// Step 3: Structured combination using a modified approach.
	// Apply the improved combining method: hash(a)*3 + hash(b).
	for i := range chainHash1 {
		sphinxHash[i] = chainHash1[i]*3 + chainHash2[i]
	}

	// Step 4: Further manipulate the resulting hash using the prime constant for additional mixing.
	// This step enhances the entropy and security of the resulting hash.
	// The manipulation is done in chunks of 8 bytes (uint64) for efficiency,
	// as processing 64-bit values is typically faster on modern architectures.
	for i := 0; i < len(sphinxHash)/8; i++ {
		offset := i * 8 // Calculate the offset for each 8-byte chunk

		// Check if the offset plus 8 bytes is within the bounds of the hash slice.
		// This prevents out-of-bounds access when working with the final hash.
		if offset+8 <= len(sphinxHash) {
			// Read the current 64-bit segment of the hash using binary little-endian format.
			// This ensures that the byte order is interpreted correctly for the system's architecture.
			val := binary.LittleEndian.Uint64(sphinxHash[offset : offset+8])

			// Add the prime constant to the current value.
			// This mixing step adds additional entropy to the hash,
			// making it less predictable and improving collision resistance.
			val += primeConstant

			// Write the updated value back to the original slice,
			// ensuring that the modified 64-bit value replaces the old value
			// at the same offset in the hash.
			binary.LittleEndian.PutUint64(sphinxHash[offset:offset+8], val)
		}
	}

	// Return the final combined SphinxHash, which now contains the result of the structured combination.
	return sphinxHash // Output the computed SphinxHash
}

// GetHash retrieves or calculates the hash of the given data.
func (s *SphinxHash) GetHash(data []byte) []byte {
	hashKey := binary.LittleEndian.Uint64(data[:8]) // Generate a unique key for caching
	if cachedValue, found := s.cache.Get(hashKey); found {
		return cachedValue // Return cached value if found
	}

	hash := s.hashData(data)   // Calculate the hash if not found in cache
	s.cache.Put(hashKey, hash) // Store the calculated hash in the cache

	return hash // Return the calculated hash
}
