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

package main

import (
	"bytes"
	"fmt"
	"log"
	"os"

	key "github.com/sphinx-core/sphinx-core/src/core/sphincs/key/backend"
	"github.com/sphinx-core/sphinx-core/src/core/wallet/crypter"
	"github.com/syndtr/goleveldb/leveldb"
)

func main() {
	// Create the keystore directory
	err := os.MkdirAll("keystore", os.ModePerm)
	if err != nil {
		log.Fatal("Failed to create keystore directory:", err)
	}

	// Open LevelDB in the keystore directory
	db, err := leveldb.OpenFile("keystore/sphinkeys", nil)
	if err != nil {
		log.Fatal("Failed to open LevelDB:", err)
	}
	defer db.Close()

	// Initialize KeyManager for generating keys
	keyManager, err := key.NewKeyManager()
	if err != nil {
		log.Fatal("Failed to initialize KeyManager:", err)
	}

	// Generate keys
	sk, pk, err := keyManager.GenerateKey()
	if err != nil {
		log.Fatal("Failed to generate keys:", err)
	}

	// Serialize the secret key to bytes
	skBytes, err := sk.SerializeSK()
	if err != nil {
		log.Fatal("Failed to serialize SK:", err)
	}
	fmt.Printf("Secret Key (SK): %x\n", skBytes)
	fmt.Printf("Size of Serialized SK: %d bytes\n", len(skBytes))

	// Serialize the public key to bytes
	pkBytes, err := pk.SerializePK()
	if err != nil {
		log.Fatal("Failed to serialize PK:", err)
	}
	fmt.Printf("Public Key (PK): %x\n", pkBytes)
	fmt.Printf("Size of Serialized PK: %d bytes\n", len(pkBytes))

	// Encrypt the secret key using crypter
	crypt := &crypter.CCrypter{}
	keyData, err := crypter.GenerateRandomBytes(crypter.WALLET_CRYPTO_KEY_SIZE)
	if err != nil {
		log.Fatalf("Failed to generate key data: %v", err)
	}
	salt, err := crypter.GenerateRandomBytes(crypter.WALLET_CRYPTO_IV_SIZE)
	if err != nil {
		log.Fatalf("Failed to generate salt: %v", err)
	}

	// Set key from passphrase
	if !crypt.SetKeyFromPassphrase(keyData, salt, 1000) {
		log.Fatalf("Failed to set key from passphrase")
	}

	// Encrypt the serialized secret key
	encryptedSecretKey, err := crypt.Encrypt(skBytes)
	if err != nil {
		log.Fatalf("Failed to encrypt secret key: %v", err)
	}
	fmt.Printf("Encrypted Secret Key: %x\n", encryptedSecretKey)

	// Save the encrypted secret key to a .dat file
	err = saveToFile("keystore/secretkey.dat", encryptedSecretKey)
	if err != nil {
		log.Fatalf("Failed to save secret key to file: %v", err)
	}
	fmt.Println("Encrypted Secret Key saved to keystore/secretkey.dat")

	// Optional: Decrypt the encrypted secret key to verify encryption
	decryptedSecretKey, err := crypt.Decrypt(encryptedSecretKey)
	if err != nil {
		log.Fatalf("Failed to decrypt secret key: %v", err)
	}
	fmt.Printf("Decrypted Secret Key: %x\n", decryptedSecretKey)

	// Deserialize the decrypted key to verify the integrity
	deserializedSK, deserializedPK, err := keyManager.DeserializeKeyPair(decryptedSecretKey, pkBytes)
	if err != nil {
		log.Fatalf("Failed to deserialize secret key: %v", err)
	}

	// Verify that the deserialized secret key matches the original
	deserializedSKBytes, err := deserializedSK.SerializeSK()
	if err != nil {
		log.Fatalf("Failed to serialize deserialized SK: %v", err)
	}
	deserializedPKBytes, err := deserializedPK.SerializePK()
	if err != nil {
		log.Fatalf("Failed to serialize deserialized PK: %v", err)
	}

	if bytes.Equal(deserializedSKBytes, skBytes) && bytes.Equal(deserializedPKBytes, pkBytes) {
		fmt.Println("Deserialized keys match the original keys!")
	} else {
		fmt.Println("Deserialized keys do NOT match the original keys.")
	}
}

// saveToFile saves the given data to a file with the provided file path
func saveToFile(filePath string, data []byte) error {
	// Create and open the file
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write data to the file
	_, err = file.Write(data)
	return err
}
