package main

import (
	"fmt"
	"log"

	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/sphinx-core/sphinx-core/src/core/sign"
	"github.com/sphinx-core/sphinx-core/src/core/wallet/crypter"
	"github.com/syndtr/goleveldb/leveldb"
)

func main() {
	// Initialize SPHINCS+ parameters
	params := parameters.GetSha256128f() // Example: Choose appropriate parameter set
	db, err := leveldb.OpenFile("path_to_your_db", nil)
	if err != nil {
		log.Fatalf("Failed to open LevelDB: %v", err)
	}
	defer db.Close()

	// Initialize the SphincsManager
	sphincsManager := sign.NewSphincsManager(db)

	// Generate secret and public keys using the sign package
	secretKey, publicKey := sphincsManager.GenerateKeys(params)
	fmt.Println("Generated SPHINCS+ Keys!")

	// Serialize the secret key to bytes
	secretKeyBytes, err := sphincsManager.SerializeSK(secretKey)
	if err != nil {
		log.Fatalf("Error serializing secret key: %v", err)
	}

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
	encryptedSecretKey, err := crypt.Encrypt(secretKeyBytes)
	if err != nil {
		log.Fatalf("Failed to encrypt secret key: %v", err)
	}
	fmt.Printf("Encrypted Secret Key: %x\n", encryptedSecretKey)

	// Optional: Decrypt the encrypted secret key to verify encryption
	decryptedSecretKey, err := crypt.Decrypt(encryptedSecretKey)
	if err != nil {
		log.Fatalf("Failed to decrypt secret key: %v", err)
	}
	fmt.Printf("Decrypted Secret Key: %x\n", decryptedSecretKey)

	// Deserialize the decrypted key to verify the integrity
	deserializedSecretKey, err := sphincsManager.DeserializeSK(params, decryptedSecretKey)
	if err != nil {
		log.Fatalf("Failed to deserialize secret key: %v", err)
	}
	fmt.Println("Deserialized Secret Key matches original!")
}
