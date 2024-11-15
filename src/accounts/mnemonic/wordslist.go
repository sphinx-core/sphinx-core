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
	"crypto/sha256"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"sync"
)

// A global map to store hashed passphrases for duplicate checking.
// In production, consider replacing this with a database for persistence and scalability.
var passphraseHashes = map[string]struct{}{}

// Mutex to synchronize access to the shared map to prevent race conditions.
var mu sync.Mutex

// LoadWordsFromURL fetches a list of words from the provided URL and returns them as a slice of strings.
// Each word is trimmed of whitespace and newlines are used as separators.
func LoadWordsFromURL(url string) ([]string, error) {
	// Make an HTTP GET request to fetch the word list
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch words from URL: %w", err)
	}
	defer resp.Body.Close() // Ensure response body is closed to avoid resource leaks

	// Read the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Split the content into individual words and trim whitespace
	var words []string
	for _, word := range strings.Split(string(body), "\n") {
		trimmedWord := strings.TrimSpace(word)
		if trimmedWord != "" {
			words = append(words, trimmedWord)
		}
	}

	return words, nil
}

// GeneratePassphrase creates a secure passphrase consisting of a specified number of words.
// It appends a cryptographic nonce to the passphrase to ensure uniqueness.
func GeneratePassphrase(words []string, wordCount int) (string, string, error) {
	// Ensure the word list is not empty
	if len(words) == 0 {
		return "", "", errors.New("word list is empty")
	}

	// Build the passphrase by randomly selecting words from the list
	var passphrase []string
	for i := 0; i < wordCount; i++ {
		// Generate a secure random index for selecting a word
		randIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(words))))
		if err != nil {
			return "", "", fmt.Errorf("failed to generate random index: %w", err)
		}
		passphrase = append(passphrase, words[randIndex.Int64()])
	}

	// Join the selected words into a single string
	passphraseStr := strings.Join(passphrase, " ")

	// Generate a random nonce (128-bit value encoded as a hexadecimal string)
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	nonceStr := fmt.Sprintf("%x", nonce)

	// Combine the nonce and passphrase with a delimiter
	// Using a delimiter ensures that the nonce and passphrase are distinctly separated.
	// Without a delimiter, there could be ambiguity if the nonce and passphrase
	// have overlapping characters, leading to potential hash collisions.
	// Example: nonce="abc", passphrase="def" results in "abcdef".
	// Another combination, nonce="ab", passphrase="cdef", also results in "abcdef".
	// Adding a delimiter (e.g., "|") makes the combined string unambiguous.
	dataToHash := nonceStr + "|" + passphraseStr
	hash := sha256.Sum256([]byte(dataToHash))
	hashStr := fmt.Sprintf("%x", hash)

	// Synchronize access to the shared map to prevent race conditions
	mu.Lock()
	defer mu.Unlock()

	// Check if the hash is already present in the map (duplicate detection)
	if _, exists := passphraseHashes[hashStr]; exists {
		return "", "", errors.New("duplicate passphrase detected, regenerate")
	}

	// Store the hash in the map to avoid future duplicates
	passphraseHashes[hashStr] = struct{}{}

	// Return the generated passphrase and its associated nonce
	return passphraseStr, nonceStr, nil
}

// NewMnemonic generates a mnemonic phrase using a given entropy level.
// It fetches a word list from a remote URL and ensures the mnemonic's uniqueness.
func NewMnemonic(entropy int) (string, string, error) {
	// URL for the word list (can be replaced with a local file or another source)
	url := "https://raw.githubusercontent.com/sphinx-core/sips/main/.github/workflows/sips0003/mnemonic.txt"

	// Calculate the number of words required for the mnemonic based on entropy
	// Each word represents approximately 11 bits of entropy.
	wordCount := (entropy + 10) / 11

	// Load the word list from the specified URL
	words, err := LoadWordsFromURL(url)
	if err != nil {
		return "", "", fmt.Errorf("failed to load words: %w", err)
	}

	// Generate a unique passphrase with the specified word count
	passphrase, nonce, err := GeneratePassphrase(words, wordCount)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate passphrase: %w", err)
	}

	return passphrase, nonce, nil
}
