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

// saveToFile saves the provided data to a specified file path.
func saveToFile(filepath string, data []byte) error {
	// Create a new file at the specified filepath.
	file, err := os.Create(filepath)
	if err != nil {
		// Return an error if file creation fails.
		return fmt.Errorf("failed to create file %s: %v", filepath, err)
	}
	defer file.Close() // Ensure the file is closed after this function completes.

	// Write the data byte slice to the file.
	_, err = file.Write(data)
	if err != nil {
		// Return an error if writing data to the file fails.
		return fmt.Errorf("failed to write data to file %s: %v", filepath, err)
	}
	return nil // Return nil if successful.
}

func main() {
	// Create a directory named "keystore" to store generated keys.
	err := os.MkdirAll("keystore", os.ModePerm)
	if err != nil {
		// Log fatal error if the directory creation fails.
		log.Fatal("Failed to create keystore directory:", err)
	}

	// Open a LevelDB database in the "keystore" directory.
	db, err := leveldb.OpenFile("keystore/sphinkeys", nil)
	if err != nil {
		// Log fatal error if the database opening fails.
		log.Fatal("Failed to open LevelDB:", err)
	}
	defer db.Close() // Ensure the database is closed after this function completes.

	// Initialize a KeyManager to generate cryptographic keys.
	keyManager, err := key.NewKeyManager()
	if err != nil {
		// Log fatal error if KeyManager initialization fails.
		log.Fatal("Failed to initialize KeyManager:", err)
	}

	// Generate a SPHINCS+ secret key (SK) and public key (PK).
	sk, pk, err := keyManager.GenerateKey()
	if err != nil {
		// Log fatal error if key generation fails.
		log.Fatal("Failed to generate keys:", err)
	}

	// Serialize the secret key to a byte slice.
	skBytes, err := sk.SerializeSK()
	if err != nil {
		// Log fatal error if serialization fails.
		log.Fatal("Failed to serialize SK:", err)
	}
	// Print the secret key in hexadecimal format.
	fmt.Printf("Secret Key (SK): %x\n", skBytes)
	// Print the size of the serialized secret key.
	fmt.Printf("Size of Serialized SK: %d bytes\n", len(skBytes))

	// Serialize the public key to a byte slice.
	pkBytes, err := pk.SerializePK()
	if err != nil {
		// Log fatal error if serialization fails.
		log.Fatal("Failed to serialize PK:", err)
	}
	// Print the public key in hexadecimal format.
	fmt.Printf("Public Key (PK): %x\n", pkBytes)
	// Print the size of the serialized public key.
	fmt.Printf("Size of Serialized PK: %d bytes\n", len(pkBytes))

	// Generate a passphrase and a Base32-encoded passkey using the seed package.
	passphrase, base32Passkey, hashedPasskey, err := seed.GenerateKeys()
	if err != nil {
		// Log fatal error if key generation from seed fails.
		log.Fatalf("Failed to generate keys from seed: %v", err)
	}
	// Print the generated passphrase.
	fmt.Printf("Passphrase: %s\n", passphrase)
	// Print the Base32-encoded passkey.
	fmt.Printf("Passkey (Base32): %s\n", base32Passkey)
	// Print the hashed passkey in hexadecimal format.
	fmt.Printf("Hashed Passkey (hex): %x\n", hashedPasskey)

	// Create a new instance of the crypter for encryption.
	crypt := &crypter.CCrypter{}
	// Generate random bytes to use as a salt for encryption.
	salt, err := crypter.GenerateRandomBytes(crypter.WALLET_CRYPTO_IV_SIZE)
	if err != nil {
		// Log fatal error if random bytes generation fails.
		log.Fatalf("Failed to generate salt: %v", err)
	}

	// Set the encryption key using the hashed passkey and the generated salt.
	if !crypt.SetKeyFromPassphrase(hashedPasskey, salt, 1000) {
		// Log fatal error if setting the key fails.
		log.Fatalf("Failed to set key from hashed passkey")
	}

	// Encrypt the serialized secret key using the crypt instance.
	encryptedSecretKey, err := crypt.Encrypt(skBytes)
	if err != nil {
		// Log fatal error if encryption fails.
		log.Fatalf("Failed to encrypt secret key: %v", err)
	}
	// Print the encrypted secret key in hexadecimal format.
	fmt.Printf("Encrypted Secret Key: %x\n", encryptedSecretKey)

	// Save the encrypted secret key to a .dat file in the keystore.
	err = saveToFile("keystore/secretkey.dat", encryptedSecretKey)
	if err != nil {
		// Log fatal error if saving the secret key fails.
		log.Fatalf("Failed to save secret key to file: %v", err)
	}

	// Encrypt the hashed passkey using the same crypter instance.
	encryptedHashedPasskey, err := crypt.Encrypt(hashedPasskey) // Use hashedPasskey directly as a byte slice
	if err != nil {
		// Log fatal error if encryption fails.
		log.Fatalf("Failed to encrypt hashed passkey: %v", err)
	}
	// Print the encrypted hashed passkey in hexadecimal format.
	fmt.Printf("Encrypted Hashed Passkey: %x\n", encryptedHashedPasskey)

	// Save the encrypted hashed passkey to a .dat file in the keystore.
	err = saveToFile("keystore/hashedpasskey.dat", encryptedHashedPasskey)
	if err != nil {
		// Log fatal error if saving the hashed passkey fails.
		log.Fatalf("Failed to save hashed passkey to file: %v", err)
	}

	// Optional: Decrypt the encrypted secret key using the hashed passkey.
	decryptCrypt := &crypter.CCrypter{}
	// Set the key for decryption using the hashed passkey and the same salt.
	if !decryptCrypt.SetKeyFromPassphrase(hashedPasskey, salt, 1000) {
		// Log fatal error if setting the key for decryption fails.
		log.Fatalf("Failed to set key from hashed passkey for decryption")
	}

	// Decrypt the encrypted secret key.
	decryptedSecretKey, err := decryptCrypt.Decrypt(encryptedSecretKey)
	if err != nil {
		// Log fatal error if decryption fails.
		log.Fatalf("Failed to decrypt secret key: %v", err)
	}
	// Print the decrypted secret key in hexadecimal format.
	fmt.Printf("Decrypted Secret Key: %x\n", decryptedSecretKey)

	// Verify that the deserialized secret key matches the original secret key.
	deserializedSK, deserializedPK, err := keyManager.DeserializeKeyPair(decryptedSecretKey, pkBytes)
	if err != nil {
		// Log fatal error if deserialization fails.
		log.Fatalf("Failed to deserialize secret key: %v", err)
	}

	// Serialize the deserialized secret key to verify against the original.
	deserializedSKBytes, err := deserializedSK.SerializeSK()
	if err != nil {
		// Log fatal error if serialization of deserialized SK fails.
		log.Fatalf("Failed to serialize deserialized SK: %v", err)
	}
	// Serialize the deserialized public key to verify against the original.
	deserializedPKBytes, err := deserializedPK.SerializePK()
	if err != nil {
		// Log fatal error if serialization of deserialized PK fails.
		log.Fatalf("Failed to serialize deserialized PK: %v", err)
	}

	// Compare the deserialized keys with the original keys.
	if bytes.Equal(deserializedSKBytes, skBytes) && bytes.Equal(deserializedPKBytes, pkBytes) {
		// Print success message if the deserialized keys match the originals.
		fmt.Println("Deserialized keys match the original keys!")
	} else {
		// Print failure message if the deserialized keys do not match.
		fmt.Println("Deserialized keys do not match the original keys.")
	}

	// Optional: Decrypt the encrypted hashed passkey.
	decryptedHashedPasskey, err := decryptCrypt.Decrypt(encryptedHashedPasskey)
	if err != nil {
		// Log fatal error if decryption fails.
		log.Fatalf("Failed to decrypt hashed passkey: %v", err)
	}
	// Print the hashed passkey before encryption for reference.
	fmt.Printf("Hashed Passkey (encrypted): %x\n", hashedPasskey)

	// After decryption, compare the decrypted hashed passkey with the original.
	fmt.Printf("Decrypted Hashed Passkey: %s\n", decryptedHashedPasskey)
}
