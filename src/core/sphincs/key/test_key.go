package main

import (
	"bytes"
	"fmt"
	"log"

	"github.com/sphinx-core/sphinx-core/src/core/sphincs/key"
)

func main() {
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

	// Output the deserialized keys to confirm they match the original.
	fmt.Printf("Deserialized private key: SKseed: %x, SKprf: %x, PKseed: %x, PKroot: %x\n",
		deserializedSK.SKseed, deserializedSK.SKprf, deserializedSK.PKseed, deserializedSK.PKroot)

	fmt.Printf("Deserialized public key: PKseed: %x, PKroot: %x\n",
		deserializedPK.PKseed, deserializedPK.PKroot)

	// Confirm the deserialized keys match the original keys using bytes.Equal
	if !bytes.Equal(deserializedSK.SKseed, sk.SKseed) || !bytes.Equal(deserializedSK.SKprf, sk.SKprf) ||
		!bytes.Equal(deserializedSK.PKseed, sk.PKseed) || !bytes.Equal(deserializedSK.PKroot, sk.PKroot) {
		log.Fatal("Deserialized private key does not match original!")
	}

	if !bytes.Equal(deserializedPK.PKseed, pk.PKseed) || !bytes.Equal(deserializedPK.PKroot, pk.PKroot) {
		log.Fatal("Deserialized public key does not match original!")
	}

	fmt.Println("Deserialization check passed! The keys match.")
}
