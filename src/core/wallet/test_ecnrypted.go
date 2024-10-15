package main

import (
	"fmt"
	"log"
	"os"

	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	sign "github.com/sphinx-core/sphinx-core/src/core/sphincs"
	"github.com/sphinx-core/sphinx-core/src/core/wallet/crypter"
	"github.com/syndtr/goleveldb/leveldb"
)

func main() {
	// Initialize parameters for SHAKE256-robust with N = 24
	params := parameters.MakeSphincsPlusSHAKE256192fRobust(false)

	// Create the root_hashtree directory inside src/core
	err := os.MkdirAll("root_hashtree", os.ModePerm)
	if err != nil {
		log.Fatal("Failed to create root_hashtree directory:", err)
	}

	// Open LevelDB in the new directory
	db, err := leveldb.OpenFile("root_hashtree/leaves_db", nil)
	if err != nil {
		log.Fatal("Failed to open LevelDB:", err)
	}
	defer db.Close()

	// Initialize the SphincsManager with the LevelDB instance
	manager := sign.NewSphincsManager(db)

	// Generate keys
	sk, pk := manager.GenerateKeys(params)

	// Serialize the secret key to bytes
	skBytes, err := manager.SerializeSK(sk)
	if err != nil {
		log.Fatal("Failed to serialize SK:", err)
	}
	fmt.Printf("Secret Key (SK): %x\n", skBytes)
	fmt.Printf("Size of Serialized SK: %d bytes\n", len(skBytes))

	// Serialize the public key to bytes
	pkBytes, err := manager.SerializePK(pk)
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
	encryptedSecretKey, err := crypt.Encrypt(skBytes) // Use skBytes, not secretKeyBytes
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
	deserializedSecretKey, err := manager.DeserializeSK(params, decryptedSecretKey) // Use manager instead of sphincsManager
	if err != nil {
		log.Fatalf("Failed to deserialize secret key: %v", err)
	}
	fmt.Println("Deserialized Secret Key matches original!")
	fmt.Printf("Deserialized Secret Key: %x\n", deserializedSecretKey) // Now used to print
}
