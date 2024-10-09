package main

import (
	"fmt"

	"github.com/sphinx-core/sphinx-core/src/core/spxhash"
)

func main() {
	// Example data to hash
	data := []byte("Hello world!")

	// Print the original data
	fmt.Printf("Original Data: %s\n", data)

	// Create a new SphinxHash object with the chosen bit size
	sphinx := spxhash.NewSphinxHash(256) // Change this to 128, 256, 384, or 512

	// Hash the data using the SphinxHash object
	sphinxHash := sphinx.GetHash(data)

	// Print the combined hash
	fmt.Printf("Sphinx Hash (%d-bit) %d bytes: %x\n", sphinx.Size()*8, len(sphinxHash), sphinxHash)
}
