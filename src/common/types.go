package common

import (
	spxhash "github.com/sphinx-core/sphinx-core/src/core/spxhash/hash"
)

// Hash is a simplified function that can be used to call SphinxHash from the spxhash package.
func Hash(bitSize int, data []byte) []byte {
	// Create a new SphinxHash instance
	sphinxHash := spxhash.NewSphinxHash(bitSize, data)

	// Use the GetHash function to retrieve the hash for the data
	return sphinxHash.GetHash(data)
}
