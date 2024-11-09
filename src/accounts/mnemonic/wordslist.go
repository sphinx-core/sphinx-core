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

package sips3

import (
	"crypto/rand"
	"errors"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
)

// LoadWords loads the words from the given URL into a slice.
func LoadWordsFromURL(url string) ([]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	words := []string{}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Split words by newline and trim any excess whitespace
	for _, word := range strings.Split(string(body), "\n") {
		words = append(words, strings.TrimSpace(word))
	}

	return words, nil
}

// GeneratePassphrase generates a passphrase with the specified number of words.
func GeneratePassphrase(words []string, wordCount int) (string, error) {
	if len(words) == 0 {
		return "", errors.New("word list is empty")
	}

	var passphrase []string
	for i := 0; i < wordCount; i++ {
		randIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(words))))
		if err != nil {
			return "", err
		}
		passphrase = append(passphrase, words[randIndex.Int64()])
	}
	return strings.Join(passphrase, " "), nil
}

// NewMnemonic generates a mnemonic phrase with a given entropy level.
func NewMnemonic(entropy int) (string, error) {
	// GitHub raw URL for mnemonic.txt file
	url := "https://raw.githubusercontent.com/sphinx-core/sips/main/.github/workflows/sips0003/mnemonic.txt"

	// Determine word count based on entropy (e.g., 128 bits of entropy = 12 words)
	wordCount := entropy / 11 // Adjust based on desired entropy to word ratio

	words, err := LoadWordsFromURL(url)
	if err != nil {
		return "", err
	}

	return GeneratePassphrase(words, wordCount)
}
