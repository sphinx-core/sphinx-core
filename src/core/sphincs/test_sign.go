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

	"github.com/ChyKusuma/sign"
	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/sphinx-core/sphinx-core/src/core/hashtree"
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

	// Sign a message
	message := []byte("Hello, world!")
	sig, merkleRoot, err := manager.SignMessage(params, message, sk)
	if err != nil {
		log.Fatal("Failed to sign message:", err)
	}

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

	// Call generateRandomData to make it used
	randomData, err := hashtree.GenerateRandomData(16)
	if err != nil {
		log.Fatal("Failed to generate random data:", err)
	}
	fmt.Printf("Random Data: %x\n", randomData)

	// Call printRootHash to make it used
	hashtree.PrintRootHash(merkleRoot)

	// Verify the signature and print the original message
	isValid := manager.VerifySignature(params, message, sig, pk, merkleRoot)
	fmt.Printf("Signature valid: %v\n", isValid)
	if isValid {
		fmt.Printf("Original Message: %s\n", message)
	}
}
