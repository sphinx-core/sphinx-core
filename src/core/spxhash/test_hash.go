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

	spxhash "github.com/sphinx-core/sphinx-core/src/core/spxhash/hash"
)

func main() {
	// Example data to hash
	data := []byte("Hello world!")

	// Print the original data
	fmt.Printf("Original Data: %s\n", data)

	// Create a new SphinxHash object with the chosen bit size and cache size
	sphinx := spxhash.NewSphinxHash(256, 100) // Set max cache size to 100

	// Hash the data using the SphinxHash object
	sphinxHash := sphinx.GetHash(data)

	// Print the combined hash
	fmt.Printf("Sphinx Hash (%d-bit) %d bytes: %x\n", sphinx.Size()*8, len(sphinxHash), sphinxHash)
}
