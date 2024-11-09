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
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,q
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	"github.com/sphinx-core/sphinx-core/src/core/hashtree"
	key "github.com/sphinx-core/sphinx-core/src/core/sphincs/key/backend"
	sign "github.com/sphinx-core/sphinx-core/src/core/sphincs/sign/backend"

	"github.com/syndtr/goleveldb/leveldb"
)

func main() {
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

	// Initialize the KeyManager with default SPHINCS+ parameters.
	km, err := key.NewKeyManager()
	if err != nil {
		log.Fatalf("Error initializing KeyManager: %v", err)
	}

	// Generate a new SPHINCS key pair.
	sk, pk, err := km.GenerateKey()
	if err != nil {
		log.Fatalf("Error generating keys: %v", err)
	}
	fmt.Println("Keys generated successfully!")

	// Serialize the key pair.
	skBytes, pkBytes, err := km.SerializeKeyPair(sk, pk)
	if err != nil {
		log.Fatalf("Error serializing key pair: %v", err)
	}
	fmt.Printf("Serialized private key: %x\n", skBytes)
	fmt.Printf("Serialized public key: %x\n", pkBytes)

	// Deserialize the key pair.
	deserializedSK, deserializedPK, err := km.DeserializeKeyPair(skBytes, pkBytes)
	if err != nil {
		log.Fatalf("Error deserializing key pair: %v", err)
	}
	fmt.Println("Keys deserialized successfully!")

	// Sign a message with the deserialized keys
	// Sign a message with the deserialized keys
	message := []byte("Hello, world!")

	// Convert deserializedSK to *sphincs.SPHINCS_SK
	spxSK := &sphincs.SPHINCS_SK{
		SKseed: deserializedSK.SKseed,
		SKprf:  deserializedSK.SKprf,
		PKseed: deserializedSK.PKseed,
		PKroot: deserializedSK.PKroot,
	}

	sig, merkleRoot, err := manager.SignMessage(km.Params, message, spxSK)

	// Serialize the signature to bytes
	sigBytes, err := manager.SerializeSignature(sig)
	if err != nil {
		log.Fatal("Failed to serialize signature:", err)
	}
	fmt.Printf("Signature: %x\n", sigBytes)
	fmt.Printf("Size of Serialized Signature: %d bytes\n", len(sigBytes))

	// Print Merkle Tree root hash and size
	fmt.Printf("Merkle Tree Root Hash: %x\n", merkleRoot.Hash)
	fmt.Printf("Size of Merkle Tree Root Hash: %d bytes\n", len(merkleRoot.Hash))

	// Save Merkle root hash to a file in the new directory
	err = hashtree.SaveRootHashToFile(merkleRoot, "root_hashtree/merkle_root_hash.bin")
	if err != nil {
		log.Fatal("Failed to save root hash to file:", err)
	}

	// Load Merkle root hash from the file
	loadedHash, err := hashtree.LoadRootHashFromFile("root_hashtree/merkle_root_hash.bin")
	if err != nil {
		log.Fatal("Failed to load root hash from file:", err)
	}
	fmt.Printf("Loaded Merkle Tree Root Hash: %x\n", loadedHash)

	// Save leaves to LevelDB
	leaves := [][]byte{sigBytes} // Example usage
	err = hashtree.SaveLeavesToDB(db, leaves)
	if err != nil {
		log.Fatal("Failed to save leaves to DB:", err)
	}

	// Generate random data for the tree
	randomData, err := hashtree.GenerateRandomData(16)
	if err != nil {
		log.Fatal("Failed to generate random data:", err)
	}
	fmt.Printf("Random Data: %x\n", randomData)

	// Print root hash from the Merkle tree
	hashtree.PrintRootHash(merkleRoot)

	// Verify the signature and print the original message
	isValid := manager.VerifySignature(km.Params, message, sig, deserializedPK, merkleRoot)
	fmt.Printf("Signature valid: %v\n", isValid)
	if isValid {
		fmt.Printf("Original Message: %s\n", message)
	}
}
