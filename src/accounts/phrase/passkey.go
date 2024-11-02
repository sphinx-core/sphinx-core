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

package seed

import (
	"crypto/rand"
	"encoding/base32"
	"fmt"

	spxhash "github.com/sphinx-core/sphinx-core/src/core/spxhash/hash"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ripemd160"
)

// Example of Login Flow
// Here's a simplified approach to a login process:

// During Registration:
// Generate a random salt and nonce.
// Use the passphrase to generate the passkey.
// Store the salt, nonce, and Base32-encoded truncated passkey.

// During Login:
// Retrieve the stored salt and nonce.
// Use the entered passphrase, stored salt, and nonce to regenerate the passkey.
// Truncate the regenerated hash (if you decide to keep truncation).
// Compare the truncated hash to the stored truncated hash.

// Define constants for the sizes used in the seed generation process
const (
	// EntropySize determines the length of entropy to be generated
	EntropySize = 16 // 128 bits for 12-word mnemonic
	SaltSize    = 16 // 128 bits salt size
	PasskeySize = 32 // Set this to 32 bytes for a 256-bit output
	NonceSize   = 8  // 64 bits nonce size, adjustable as needed

	// Argon2 parameters for password hashing
	// Argon memory standard that is required minimum 15MiB memory in allocation
	memory      = 64 * 1024 // Memory cost set to 64 KiB (64 * 1024 bytes)
	iterations  = 2         // Number of iterations for Argon2id set to 2
	parallelism = 1         // Degree of parallelism set to 1
	tagSize     = 32        // Tag size set to 256 bits (32 bytes)
)

// GenerateSalt generates a cryptographically secure random salt.
func GenerateSalt() ([]byte, error) {
	// Create a byte slice for the salt
	salt := make([]byte, SaltSize)
	// Fill the slice with random bytes
	_, err := rand.Read(salt)
	if err != nil {
		// Return an error if salt generation fails
		return nil, fmt.Errorf("error generating salt: %v", err)
	}
	// Return the generated salt
	return salt, nil
}

// GenerateNonce generates a cryptographically secure random nonce.
func GenerateNonce() ([]byte, error) {
	// Create a byte slice for the nonce
	nonce := make([]byte, NonceSize)
	// Fill the slice with random bytes
	_, err := rand.Read(nonce)
	if err != nil {
		// Return an error if nonce generation fails
		return nil, fmt.Errorf("error generating nonce: %v", err)
	}
	// Return the generated nonce
	return nonce, nil
}

// GenerateEntropy generates secure random entropy for private key generation.
func GenerateEntropy() ([]byte, error) {
	// Create a byte slice for entropy
	entropy := make([]byte, EntropySize)
	// Fill the slice with random bytes
	_, err := rand.Read(entropy)
	if err != nil {
		// Return an error if entropy generation fails
		return nil, fmt.Errorf("error generating entropy: %v", err)
	}
	// Return the raw entropy for BIP-39
	return entropy, nil
}

// GeneratePassphrase generates a BIP-39 passphrase from entropy.
func GeneratePassphrase(entropy []byte) (string, error) {
	// Create a new mnemonic (passphrase) from the provided entropy
	passphrase, err := bip39.NewMnemonic(entropy)
	if err != nil {
		// Return an error if passphrase generation fails
		return "", fmt.Errorf("error generating passphrase: %v", err)
	}
	// Return the generated passphrase
	return passphrase, nil
}

// GeneratePasskey generates a passkey using Argon2 and a random salt plus nonce.
func GeneratePasskey(passphrase string) ([]byte, error) {
	// Convert the input key material (passphrase) to a byte slice
	ikm := []byte(passphrase)
	// Generate a random salt
	salt, err := GenerateSalt()
	if err != nil {
		// Return an error if salt generation fails
		return nil, fmt.Errorf("error generating salt: %v", err)
	}
	// Generate a random nonce
	nonce, err := GenerateNonce()
	if err != nil {
		// Return an error if nonce generation fails
		return nil, fmt.Errorf("error generating nonce: %v", err)
	}
	// Combine the salt and nonce
	combinedSalt := append(salt, nonce...)
	// Generate a passkey using Argon2 with the combined salt
	passkey := argon2.IDKey(ikm, combinedSalt, iterations, memory, parallelism, PasskeySize)
	// Return the generated passkey
	return passkey, nil
}

// HashPasskey hashes the passkey using double SphinxHash and then applies RIPEMD-160.
func HashPasskey(passkey []byte) ([]byte, error) {
	// First SphinxHash instance
	sphinx1 := spxhash.NewSphinxHash(256)
	if _, err := sphinx1.Write(passkey); err != nil {
		return nil, fmt.Errorf("error writing passkey data to first SphinxHash: %v", err)
	}
	// Finalize the first hash computation
	firstHash := sphinx1.Sum(nil)

	// Second SphinxHash instance for double hashing
	sphinx2 := spxhash.NewSphinxHash(256)
	if _, err := sphinx2.Write(firstHash); err != nil {
		return nil, fmt.Errorf("error writing first hash to second SphinxHash: %v", err)
	}
	// Finalize the second hash computation
	doubleHash := sphinx2.Sum(nil)

	// Apply RIPEMD-160 to the double-hashed output
	hashRIPEMD160 := ripemd160.New()
	if _, err := hashRIPEMD160.Write(doubleHash); err != nil {
		return nil, fmt.Errorf("error hashing with RIPEMD-160: %v", err)
	}

	return hashRIPEMD160.Sum(nil), nil // Return the final hashed output
}

// EncodeBase32 encodes the data in Base32 without padding.
func EncodeBase32(data []byte) string {
	// Encode the data in Base32 format without any padding
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
}

// GenerateKeys generates a passphrase and a hashed, Base32-encoded passkey.
func GenerateKeys() (passphrase string, base32Passkey string, hashedPasskey []byte, err error) {
	// Generate entropy for the mnemonic
	entropy, err := GenerateEntropy()
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to generate entropy: %v", err)
	}

	// Generate passphrase from entropy
	passphrase, err = GeneratePassphrase(entropy)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to generate passphrase: %v", err)
	}

	// Generate passkey from the passphrase
	passkey, err := GeneratePasskey(passphrase)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to generate passkey: %v", err)
	}

	// Hash the generated passkey
	hashedPasskey, err = HashPasskey(passkey)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to hash passkey: %v", err)
	}

	// Truncate to the first 10 bytes
	truncatedHashedPasskey := hashedPasskey[:10]

	// Encode the truncated hash in Base32
	base32Passkey = EncodeBase32(truncatedHashedPasskey)

	// Return the generated passphrase, Base32-encoded passkey, and hashed passkey
	return passphrase, base32Passkey, hashedPasskey, nil
}
