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
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"io"

	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ripemd160"
)

const (
	// Change the entropy size for a 12-word mnemonic
	EntropySize = 16 // 128 bits for 12-word mnemonic
	SaltSize    = 16 // 128 bits salt size
	PasskeySize = 64 // 512 bits output passkey length
)

// GenerateEntropy generates secure random entropy for private key generation.
func GenerateEntropy() ([]byte, error) {
	entropy := make([]byte, EntropySize)
	_, err := rand.Read(entropy)
	if err != nil {
		return nil, fmt.Errorf("error generating entropy: %v", err)
	}
	return entropy, nil // Return the raw entropy for BIP-39
}

// GeneratePassphrase generates a BIP-39 passphrase from entropy.
func GeneratePassphrase(entropy []byte) (string, error) {
	// Directly use the entropy to generate the mnemonic
	passphrase, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("error generating passphrase: %v", err)
	}
	return passphrase, nil
}

// GenerateSalt generates a cryptographically secure random salt.
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("error generating salt: %v", err)
	}
	return salt, nil
}

// GeneratePasskey generates a passkey using a passphrase with HKDF (HMAC-based Key Derivation Function) and a random salt.
func GeneratePasskey(passphrase string) ([]byte, error) {
	// Use the passphrase as input key material
	ikm := []byte(passphrase)

	// Generate a random salt
	salt, err := GenerateSalt()
	if err != nil {
		return nil, fmt.Errorf("error generating salt: %v", err)
	}

	// HKDF with SHA-256 to derive a passkey using the generated salt
	hkdf := hkdf.New(sha256.New, ikm, salt, nil)
	passkey := make([]byte, PasskeySize)

	// Read the derived passkey from the HKDF output
	_, err = io.ReadFull(hkdf, passkey)
	if err != nil {
		return nil, fmt.Errorf("error generating passkey using HKDF: %v", err)
	}
	return passkey, nil
}

// HashPasskey hashes the passkey using SHA-256 and then applies RIPEMD-160.
func HashPasskey(passkey []byte) ([]byte, error) {
	// First hash the passkey using SHA-256
	hashSHA256 := sha256.Sum256(passkey)

	// Then hash the SHA-256 result using RIPEMD-160
	hashRIPEMD160 := ripemd160.New()
	_, err := hashRIPEMD160.Write(hashSHA256[:])
	if err != nil {
		return nil, fmt.Errorf("error hashing with RIPEMD-160: %v", err)
	}

	// Return the final RIPEMD-160 hash
	return hashRIPEMD160.Sum(nil), nil
}

// EncodeBase32 encodes the data in Base32 with padding.
func EncodeBase32(data []byte) string {
	return base32.StdEncoding.EncodeToString(data)
}

// GeneratePassphraseAndPasskey generates a passphrase and a hashed, Base32-encoded passkey.
func GenerateKeys() (passphrase string, base32Passkey string, err error) {
	// Generate entropy
	entropy, err := GenerateEntropy()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate entropy: %v", err)
	}

	// Generate passphrase
	passphrase, err = GeneratePassphrase(entropy)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate passphrase: %v", err)
	}

	// Generate passkey using HKDF and random salt
	passkey, err := GeneratePasskey(passphrase)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate passkey: %v", err)
	}

	// Hash the passkey using SHA-256 followed by RIPEMD-160
	hashedPasskey, err := HashPasskey(passkey)
	if err != nil {
		return "", "", fmt.Errorf("failed to hash passkey: %v", err)
	}

	// Encode the hashed passkey in Base32
	base32Passkey = EncodeBase32(hashedPasskey)

	return passphrase, base32Passkey, nil
}
