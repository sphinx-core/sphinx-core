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

package crypter

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
)

const (
	WALLET_CRYPTO_KEY_SIZE   = 32               // AES-256: 256-bit (32 bytes) key size
	WALLET_CRYPTO_IV_SIZE    = 16               // Size of IV: 16 bytes (fixed for AES)
	WALLET_CRYPTO_NONCE_SIZE = 12               // AES GCM: 12-byte nonce (used as IV)
	AES_BLOCKSIZE            = 16               // AES block size: 16 bytes (128 bits, fixed for AES)
	CSHA512OutputSize        = 64               // SHA-512 output size: 64 bytes
	AES_GCM_TAG_SIZE         = 16               // GCM authentication tag size: 16 bytes
	AES_GCM_OVERHEAD         = AES_GCM_TAG_SIZE // Overhead for GCM: size of the authentication tag
)

// MasterKey represents the master key structure.
type MasterKey struct {
	VchCryptedKey                []byte `json:"vchCryptedKey"`
	VchSalt                      []byte `json:"vchSalt"`
	NDerivationMethod            uint32 `json:"nDerivationMethod"`
	NDeriveIterations            uint32 `json:"nDeriveIterations"`
	VchOtherDerivationParameters []byte `json:"vchOtherDerivationParameters"`
}

// CCrypter handles AES encryption and decryption with key and IV.
type CCrypter struct {
	vchKey  []byte
	vchIV   []byte
	fKeySet bool
}

// NewMasterKey creates a new instance of MasterKey with default values.
func NewMasterKey() *MasterKey {
	return &MasterKey{
		NDeriveIterations:            25000,    // Default iterations
		NDerivationMethod:            0,        // Default method (0 = EVP_sha512)
		VchOtherDerivationParameters: []byte{}, // Empty default
	}
}

// Serialize serializes the MasterKey into a byte slice.
func (mk *MasterKey) Serialize() ([]byte, error) {
	return json.Marshal(mk)
}

// Deserialize populates the MasterKey from a byte slice.
func (mk *MasterKey) Deserialize(data []byte) error {
	return json.Unmarshal(data, mk)
}

// Uint256 represents a 256-bit integer.
type Uint256 struct {
	bigInt *big.Int
}

// NewUint256 creates a new Uint256 from a byte slice.
func NewUint256(b []byte) *Uint256 {
	u := new(Uint256)
	u.bigInt = new(big.Int).SetBytes(b)
	return u
}

// ToBytes converts Uint256 to byte slice.
func (u *Uint256) ToBytes() []byte {
	return u.bigInt.Bytes()
}

// BytesToUint256 converts byte slice to Uint256.
// Convert a byte slice to Uint256
func BytesToUint256(b []byte) *Uint256 {
	u := new(Uint256)
	u.bigInt = new(big.Int).SetBytes(b)
	return u
}

func NewCrypter(masterKey []byte) (*CCrypter, error) {
	cKeyCrypter := &CCrypter{}
	if !cKeyCrypter.SetKey(masterKey, nil) {
		return nil, errors.New("failed to set key")
	}
	return cKeyCrypter, nil
}

// Key Derivation Formula: K = SHA-512^count(keyData + salt)
func (c *CCrypter) BytesToKeySHA512AES(salt, keyData []byte, count int) ([]byte, []byte, error) {
	if count <= 0 || keyData == nil || salt == nil {
		return nil, nil, errors.New("invalid parameters")
	}

	hash := sha512.New()
	buf := make([]byte, CSHA512OutputSize)

	// First hash step: H0 = SHA-512(keyData + salt)
	hash.Write(keyData)
	hash.Write(salt)
	copy(buf, hash.Sum(nil))

	// Repeat hashing (key stretching): Hn = SHA-512(Hn-1)
	for i := 1; i < count; i++ {
		hash.Reset()
		hash.Write(buf)
		copy(buf, hash.Sum(nil))
	}

	// Split the final buffer into key and IV: key = first 32 bytes, IV = next 16 bytes
	if len(buf) < WALLET_CRYPTO_KEY_SIZE+WALLET_CRYPTO_IV_SIZE {
		return nil, nil, errors.New("buffer too small")
	}
	key := buf[:WALLET_CRYPTO_KEY_SIZE]                                              // First 32 bytes for key
	iv := buf[WALLET_CRYPTO_KEY_SIZE : WALLET_CRYPTO_KEY_SIZE+WALLET_CRYPTO_IV_SIZE] // Next 16 bytes for IV

	// Zero out sensitive data from memory
	memoryCleanse(buf)

	return key, iv, nil
}

// SetKeyFromPassphrase derives and sets encryption key from a passphrase.
func (c *CCrypter) SetKeyFromPassphrase(keyData, salt []byte, rounds uint) bool {
	if rounds < 1 || len(salt) != WALLET_CRYPTO_IV_SIZE {
		log.Printf("Invalid rounds or salt length: rounds=%d, salt length=%d", rounds, len(salt))
		return false
	}

	key, iv, err := c.BytesToKeySHA512AES(salt, keyData, int(rounds))
	if err != nil {
		log.Printf("Error deriving key and IV: %v", err)
		return false
	}

	if len(key) != WALLET_CRYPTO_KEY_SIZE || len(iv) != WALLET_CRYPTO_IV_SIZE {
		log.Printf("Derived key or IV length mismatch: key length=%d, iv length=%d", len(key), len(iv))
		memoryCleanse(key)
		memoryCleanse(iv)
		return false
	}

	c.vchKey = key
	c.vchIV = iv
	c.fKeySet = true
	return true
}

// SetKey sets encryption key and IV directly.
func (c *CCrypter) SetKey(newKey, newIV []byte) bool {
	if len(newKey) != WALLET_CRYPTO_KEY_SIZE || len(newIV) != WALLET_CRYPTO_IV_SIZE {
		return false
	}

	c.vchKey = make([]byte, WALLET_CRYPTO_KEY_SIZE)
	c.vchIV = make([]byte, WALLET_CRYPTO_IV_SIZE)
	copy(c.vchKey, newKey)
	copy(c.vchIV, newIV)

	c.fKeySet = true
	return true
}

// Encrypt: Encrypts the plaintext using AES-256-GCM.
func (c *CCrypter) Encrypt(plaintext []byte) ([]byte, error) {
	if !c.fKeySet {
		return nil, errors.New("key not set")
	}

	// Generate a new IV
	iv := make([]byte, WALLET_CRYPTO_NONCE_SIZE) // Correct nonce size
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	// Create AES cipher block with the derived key
	block, err := aes.NewCipher(c.vchKey)
	if err != nil {
		return nil, err
	}

	// Create GCM cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Encrypt the plaintext
	ciphertext := gcm.Seal(nil, iv, plaintext, nil)

	// Prepend the IV to the ciphertext
	result := append(iv, ciphertext...)

	return result, nil
}

// Decrypt: Decrypts the ciphertext using AES-256-GCM.
func (c *CCrypter) Decrypt(ciphertext []byte) ([]byte, error) {
	if !c.fKeySet {
		return nil, errors.New("key not set")
	}

	if len(ciphertext) < WALLET_CRYPTO_NONCE_SIZE+AES_GCM_TAG_SIZE { // Check for the correct size
		return nil, errors.New("ciphertext too short")
	}

	// Extract IV from the beginning of the ciphertext
	iv := ciphertext[:WALLET_CRYPTO_NONCE_SIZE] // Correct nonce size
	ciphertext = ciphertext[WALLET_CRYPTO_NONCE_SIZE:]

	// Create AES cipher block with the derived key
	block, err := aes.NewCipher(c.vchKey)
	if err != nil {
		return nil, err
	}

	// Create GCM cipher
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Decrypt the ciphertext
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// EncryptSecret: Encrypts the given plaintext using a master key and an IV (Uint256).
func EncryptSecret(masterKey []byte, plaintext []byte, iv *Uint256) ([]byte, error) {
	// Initialize the crypter
	cKeyCrypter := &CCrypter{}

	// Generate a random salt if you need to derive the key
	salt, err := GenerateRandomBytes(WALLET_CRYPTO_IV_SIZE) // Use IV size for salt
	if err != nil {
		return nil, err
	}

	// Set the encryption key for AES using the derived method
	if !cKeyCrypter.SetKeyFromPassphrase(masterKey, salt, 10000) { // Use 10,000 rounds as an example
		return nil, errors.New("failed to set key")
	}

	// Encrypt the secret using AES-256-GCM with the provided key and IV
	ciphertext, err := cKeyCrypter.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// DecryptSecret: Decrypts the ciphertext using a master key and an IV (Uint256).
func DecryptSecret(masterKey []byte, ciphertext []byte, iv *Uint256) ([]byte, error) {
	// Initialize the crypter with the key and IV
	cKeyCrypter := &CCrypter{}

	// Attempt to derive the key and IV from the master key and salt
	salt, err := GenerateRandomBytes(WALLET_CRYPTO_IV_SIZE) // Ensure you have the same salt used for encryption
	if err != nil {
		return nil, err
	}

	// Set the decryption key for AES using the derived method
	if !cKeyCrypter.SetKeyFromPassphrase(masterKey, salt, 10000) { // Use the same parameters as during encryption
		return nil, errors.New("failed to set key")
	}

	// Decrypt the ciphertext using AES-256-GCM with the provided key and IV
	plaintext, err := cKeyCrypter.Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// DecryptKey: Decrypts a crypted secret using a master key and IV derived from the public key.
func DecryptKey(masterKey []byte, cryptedSecret []byte, pubKey []byte) ([]byte, error) {
	// Convert pubKey to Uint256 (used as the IV)
	iv := BytesToUint256(pubKey)

	// Decrypt the secret using the master key and derived IV
	secret, err := DecryptSecret(masterKey, cryptedSecret, iv)
	if err != nil {
		return nil, err
	}

	if len(secret) != 32 {
		return nil, errors.New("decrypted secret size mismatch")
	}

	// Verify that the decrypted secret matches the public key
	if !VerifyPubKey(secret, pubKey) {
		return nil, errors.New("decrypted key mismatch with public key")
	}

	return secret, nil
}

// MemoryCleanse: Zero out sensitive data from memory
func memoryCleanse(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// VerifyPubKey: Dummy verification for now
func VerifyPubKey(secret, pubKey []byte) bool {
	// Dummy implementation, assumes pubKey derived from secret
	return bytes.Equal(secret, pubKey)
}

// Modify GenerateRandomBytes to accept an appropriate size for IV and Key
func GenerateRandomBytes(size int) ([]byte, error) {
	if size <= 0 {
		return nil, errors.New("size must be greater than 0")
	}
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func main() {
	mk := NewMasterKey()
	mk.VchCryptedKey = []byte("example_crypted_key")
	mk.VchSalt = []byte("example_salt")

	// Print before serialization
	fmt.Printf("MasterKey before serialization: %+v\n", mk)

	// Serialize
	serialized, err := mk.Serialize()
	if err != nil {
		log.Fatalf("Error during serialization: %v", err)
	}
	fmt.Printf("Serialized MasterKey: %s\n", string(serialized))

	// Deserialize
	newMk := NewMasterKey()
	if err := newMk.Deserialize(serialized); err != nil {
		log.Fatalf("Error during deserialization: %v", err)
	}
	fmt.Printf("MasterKey after deserialization: %+v\n", newMk)

	// Create a new CCrypter instance
	crypt := &CCrypter{}

	// Generate random key data and salt
	keyData, err := GenerateRandomBytes(WALLET_CRYPTO_KEY_SIZE)
	if err != nil {
		log.Fatalf("Failed to generate key data: %v", err)
	}
	salt, err := GenerateRandomBytes(WALLET_CRYPTO_IV_SIZE) // Ensure salt size is correct
	if err != nil {
		log.Fatalf("Failed to generate salt: %v", err)
	}

	// Log generated values for debugging
	fmt.Printf("Generated keyData: %x\n", keyData)
	fmt.Printf("Generated salt: %x\n", salt)

	// Set the key using the key data and salt
	if !crypt.SetKeyFromPassphrase(keyData, salt, 1000) {
		log.Fatalf("Failed to set key from passphrase")
	}

	// Define some plaintext
	plaintext := []byte("Hello, this is a secret message!")

	// Encrypt the plaintext
	ciphertext, err := crypt.Encrypt(plaintext)
	if err != nil {
		log.Fatalf("Failed to encrypt plaintext: %v", err)
	}
	fmt.Printf("Ciphertext: %x\n", ciphertext)

	// Decrypt the ciphertext
	decryptedText, err := crypt.Decrypt(ciphertext)
	if err != nil {
		log.Fatalf("Failed to decrypt ciphertext: %v", err)
	}
	fmt.Printf("Decrypted text: %s\n", decryptedText)

	// Create a Uint256 IV (must be 16 bytes for AES)
	ivBytes, err := GenerateRandomBytes(WALLET_CRYPTO_IV_SIZE) // 16 bytes
	if err != nil {
		log.Fatalf("Failed to generate IV: %v", err)
	}
	iv := BytesToUint256(ivBytes)

	// Encrypt a secret
	secret := []byte("This is a secret key!")
	encryptedSecret, err := EncryptSecret(keyData, secret, iv)
	if err != nil {
		log.Fatalf("Failed to encrypt secret: %v", err)
	}
	fmt.Printf("Encrypted secret: %x\n", encryptedSecret)

	// Decrypt the secret
	decryptedSecret, err := DecryptSecret(keyData, encryptedSecret, iv)
	if err != nil {
		log.Fatalf("Failed to decrypt secret: %v", err)
	}
	fmt.Printf("Decrypted secret: %s\n", decryptedSecret)
}
