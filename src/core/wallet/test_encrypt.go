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

	seed "github.com/sphinx-core/sphinx-core/src/accounts/phrase"
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

	// Generate passphrase and Base32-encoded passkey from seed package
	passphrase, base32Passkey, err := seed.GenerateKeys()
	if err != nil {
		log.Fatalf("Failed to generate keys from seed: %v", err)
	}
	fmt.Printf("Passphrase: %s\n", passphrase)
	fmt.Printf("Passkey: %s\n", base32Passkey)

	// Hash the Base32-encoded passkey to generate hashedPasskey
	hashedPasskey, err := seed.HashPasskey([]byte(base32Passkey))
	if err != nil {
		log.Fatalf("Failed to hash passkey: %v", err)
	}

	// Encrypt the secret key using crypter and hashedPasskey as encryption key
	crypt := &crypter.CCrypter{}
	salt, err := crypter.GenerateRandomBytes(crypter.WALLET_CRYPTO_IV_SIZE)
	if err != nil {
		log.Fatalf("Failed to generate salt: %v", err)
	}

	// Set key from hashedPasskey for encryption
	if !crypt.SetKeyFromPassphrase(hashedPasskey, salt, 1000) {
		log.Fatalf("Failed to set key from hashed passkey")
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

	// Encrypt the hashed passkey
	encryptedHashedPasskey, err := crypt.Encrypt(hashedPasskey)
	if err != nil {
		log.Fatalf("Failed to encrypt hashed passkey: %v", err)
	}
	fmt.Printf("Encrypted Hashed Passkey: %x\n", encryptedHashedPasskey)

	// Save the encrypted hashed passkey to a .dat file
	err = saveToFile("keystore/hashedpasskey.dat", encryptedHashedPasskey)
	if err != nil {
		log.Fatalf("Failed to save hashed passkey to file: %v", err)
	}

	// Optional: Decrypt the encrypted secret key using hashed passkey
	decryptCrypt := &crypter.CCrypter{}
	if !decryptCrypt.SetKeyFromPassphrase(hashedPasskey, salt, 1000) {
		log.Fatalf("Failed to set key from hashed passkey for decryption")
	}

	// Decrypt the encrypted secret key
	decryptedSecretKey, err := decryptCrypt.Decrypt(encryptedSecretKey)
	if err != nil {
		log.Fatalf("Failed to decrypt secret key: %v", err)
	}
	fmt.Printf("Decrypted Secret Key: %x\n", decryptedSecretKey)

	// Verify that the deserialized secret key matches the original
	deserializedSK, deserializedPK, err := keyManager.DeserializeKeyPair(decryptedSecretKey, pkBytes)
	if err != nil {
		log.Fatalf("Failed to deserialize secret key: %v", err)
	}

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
		fmt.Println("Deserialized keys do not match the original keys.")
	}

	// Optional: Decrypt the encrypted hashed passkey
	decryptedHashedPasskey, err := decryptCrypt.Decrypt(encryptedHashedPasskey)
	if err != nil {
		log.Fatalf("Failed to decrypt hashed passkey: %v", err)
	}
	// Print the hashed passkey before encryption
	fmt.Printf("Hashed Passkey (before encryption): %x\n", hashedPasskey)

	// After decryption, compare with the original hashed passkey
	fmt.Printf("Decrypted Hashed Passkey: %x\n", decryptedHashedPasskey)

}

// saveToFile saves data to the specified file path
func saveToFile(filepath string, data []byte) error {
	file, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %v", filepath, err)
	}
	defer file.Close()

	_, err = file.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write data to file %s: %v", filepath, err)
	}
	return nil
}
