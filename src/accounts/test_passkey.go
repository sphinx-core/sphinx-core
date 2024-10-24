package main

import (
	"fmt"
	"log"

	seed "github.com/sphinx-core/sphinx-core/src/accounts/phrase"
)

func main() {
	// Generate passphrase and passkey
	passphrase, base32Passkey, err := seed.GeneratePassphraseAndPasskey()
	if err != nil {
		log.Fatalf("Error generating passphrase and passkey: %v", err)
	}

	// Print the generated passphrase and Base32-encoded passkey
	fmt.Printf("Passphrase: %s\n", passphrase)
	fmt.Printf("Passkey: %s\n", base32Passkey)
}
