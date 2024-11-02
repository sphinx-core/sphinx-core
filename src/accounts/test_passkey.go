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
	"fmt"
	"log"

	seed "github.com/sphinx-core/sphinx-core/src/accounts/phrase"
)

func main() {
	// Generate passphrase and passkey, including hashed passkey
	passphrase, base32Passkey, hashedPasskey, err := seed.GenerateKeys()
	if err != nil {
		log.Fatalf("Error generating passphrase and passkey: %v", err)
	}

	// Print the generated passphrase, Base32-encoded passkey, and hashed passkey
	fmt.Printf("Passphrase: %s\n", passphrase)
	fmt.Printf("Base32Passkey: %s\n", base32Passkey)
	fmt.Printf("Hashed Passkey: %x\n", hashedPasskey)
}
