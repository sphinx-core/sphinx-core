package main

import (
	"fmt"
	"log" // Added log package for logging errors

	"github.com/sphinx-core/sphinx-core/src/core/wallet" // Corrected the import path
)

func main() {
	mk := wallet.NewMasterKey() // Added 'wallet.' before NewMasterKey to properly reference the function
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
	newMk := wallet.NewMasterKey() // Added 'wallet.' here as well
	if err := newMk.Deserialize(serialized); err != nil {
		log.Fatalf("Error during deserialization: %v", err)
	}
	fmt.Printf("MasterKey after deserialization: %+v\n", newMk)

	// Create a new CCrypter instance
	crypt := &wallet.CCrypter{} // Added 'wallet.' to reference the correct struct

	// Generate random key data and salt
	keyData, err := wallet.GenerateRandomBytes(wallet.WALLET_CRYPTO_KEY_SIZE)
	if err != nil {
		log.Fatalf("Failed to generate key data: %v", err)
	}
	salt, err := wallet.GenerateRandomBytes(wallet.WALLET_CRYPTO_IV_SIZE) // Ensure salt size is correct
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
	ivBytes, err := wallet.GenerateRandomBytes(wallet.WALLET_CRYPTO_IV_SIZE) // 16 bytes
	if err != nil {
		log.Fatalf("Failed to generate IV: %v", err)
	}
	iv := wallet.BytesToUint256(ivBytes)

	// Encrypt a secret
	secret := []byte("This is a secret key!")
	encryptedSecret, err := wallet.EncryptSecret(keyData, secret, iv)
	if err != nil {
		log.Fatalf("Failed to encrypt secret: %v", err)
	}
	fmt.Printf("Encrypted secret: %x\n", encryptedSecret)

	// Decrypt the secret
	decryptedSecret, err := wallet.DecryptSecret(keyData, encryptedSecret, iv)
	if err != nil {
		log.Fatalf("Failed to decrypt secret: %v", err)
	}
	fmt.Printf("Decrypted secret: %s\n", decryptedSecret)
}
