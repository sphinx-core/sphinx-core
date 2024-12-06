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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Argon2 parameters
// Argon memory standard is required minimum 15MiB (15 * 1024 * 1024) memory in allocation
const (
	memory      = 64 * 1024 // Memory cost set to 64 KiB (64 * 1024 bytes) is for demonstration purpose
	iterations  = 2         // Number of iterations for Argon2id set to 2
	parallelism = 1         // Degree of parallelism set to 1
	tagSize     = 32        // Tag size set to 256 bits (32 bytes)
)

var (
	mu               sync.Mutex              // Ensures thread-safe access to shared resources
	passphraseHashes = map[string]struct{}{} // Stores hashes of generated passphrases (used database in production)
)

// GitHubFile represents the structure of file information returned by GitHub's API
type GitHubFile struct {
	Name string `json:"name"` // Name of the file
	Path string `json:"path"` // Path to the file in the repository
	Type string `json:"type"` // Type of the file (e.g., file, directory)
}

// Base URL for accessing the repository directory on GitHub (HTTP version)
const baseURL = "http://api.github.com/repos/sphinx-core/sips/contents/.github/workflows/sips0003"

// FetchFileList fetches the list of files from a specified URL
func FetchFileList(url string) ([]GitHubFile, error) {
	resp, err := http.Get(url) // Sends an HTTP GET request to the specified URL
	if err != nil {
		return nil, fmt.Errorf("failed to fetch file list: %w", err) // Returns an error if the request fails
	}
	defer resp.Body.Close() // Ensures the response body is closed after function execution

	if resp.StatusCode != http.StatusOK { // Checks if the HTTP status is OK (200)
		return nil, fmt.Errorf("unexpected response: %s", resp.Status) // Returns an error for unexpected responses
	}

	var files []GitHubFile                                            // Declares a slice to store file information
	if err := json.NewDecoder(resp.Body).Decode(&files); err != nil { // Decodes the JSON response into the slice
		return nil, fmt.Errorf("failed to decode response: %w", err) // Returns an error if decoding fails
	}

	return files, nil // Returns the list of files
}

// SelectAndLoadTxtFile selects a random .txt file and loads its content
func SelectAndLoadTxtFile(url string) ([]string, error) {
	files, err := FetchFileList(url) // Fetches the list of files from the repository
	if err != nil {
		return nil, err // Returns an error if file fetching fails
	}

	// Filters the files to include only those with a .txt extension
	var txtFiles []GitHubFile
	for _, file := range files {
		if strings.HasSuffix(file.Name, ".txt") { // Checks if the file name ends with .txt
			txtFiles = append(txtFiles, file) // Adds the .txt file to the list
		}
	}

	if len(txtFiles) == 0 { // Checks if no .txt files were found
		return nil, errors.New("no .txt files found in the directory") // Returns an error
	}

	// Selects a random .txt file from the list
	var selectedFile GitHubFile
	if len(txtFiles) > 0 { // Check if there are any files
		randIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(txtFiles)))) // Generates a random index
		selectedFile = txtFiles[randIndex.Int64()]                              // Selects the file at the random index
	} else {
		return nil, errors.New("no .txt files found") // Error if no files are found
	}

	// Constructs the URL for fetching the raw content of the selected file
	rawBaseURL := "http://raw.githubusercontent.com/sphinx-core/sips/main/.github/workflows/sips0003/" // Changed to HTTP
	fileURL := rawBaseURL + selectedFile.Name

	// Fetches the content of the selected file
	resp, err := http.Get(fileURL) // Sends an HTTP GET request to the file URL
	if err != nil {
		return nil, fmt.Errorf("failed to fetch file content: %w", err) // Returns an error if the request fails
	}
	defer resp.Body.Close() // Ensures the response body is closed after function execution

	body, err := io.ReadAll(resp.Body) // Reads the response body
	if err != nil {
		return nil, fmt.Errorf("failed to read file content: %w", err) // Returns an error if reading fails
	}

	// Splits the content into individual words and trims whitespace
	var words []string
	for _, word := range strings.Split(string(body), "\n") {
		trimmedWord := strings.TrimSpace(word) // Removes leading/trailing whitespace
		if trimmedWord != "" {                 // Ignores empty lines
			words = append(words, trimmedWord) // Adds the word to the list
		}
	}

	// Base64URL encode the words
	encodedWords := make([]string, len(words))
	for i, word := range words {
		encodedWords[i] = base64.URLEncoding.EncodeToString([]byte(word)) // Base64URL encoding each word
	}

	// Returns the encoded words
	return encodedWords, nil // Returns the list of encoded words
}

// GeneratePassphrase creates a secure passphrase using a given word list
func GeneratePassphrase(words []string, wordCount int) (string, string, error) {
	// Check if the word list is empty; if so, return an error
	if len(words) == 0 {
		return "", "", errors.New("word list is empty")
	}

	var passphrase []string
	// Loop to generate a passphrase by selecting random words from the word list
	for i := 0; i < wordCount; i++ {
		// Generate a random index to pick a word from the list
		randIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(words))))
		if err != nil {
			// Return an error if random index generation fails
			return "", "", fmt.Errorf("failed to generate random index: %w", err)
		}
		// Append the selected word to the passphrase slice
		encodedWord := words[randIndex.Int64()]

		// Decode the Base64URL encoded word into its original form
		decodedWord, err := base64.URLEncoding.DecodeString(encodedWord)
		if err != nil {
			// Return an error if decoding fails
			return "", "", fmt.Errorf("failed to decode word: %w", err)
		}
		// Convert the decoded word to a string and append it to the passphrase
		passphrase = append(passphrase, string(decodedWord))
	}

	// Join the words in the passphrase slice into a single string separated by spaces
	passphraseStr := strings.Join(passphrase, " ")

	// Create a slice to hold the 16-byte nonce
	nonce := make([]byte, 16)
	// Generate random bytes to populate the nonce
	if _, err := rand.Read(nonce); err != nil {
		// Return an error if nonce generation fails
		return "", "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Convert the passphrase string to a byte slice for encoding
	passphraseBytes := []byte(passphraseStr)
	// Check if the byte slice is valid UTF-8
	if !utf8.Valid(passphraseBytes) {
		// Return an error if the passphrase contains invalid UTF-8 characters
		return "", "", errors.New("invalid UTF-8 encoding in passphrase")
	}

	// Create a salt by concatenating "mnemonic" with the passphrase string
	salt := "mnemonic" + passphraseStr
	// Convert the salt string to a byte slice for encoding
	saltBytes := []byte(salt)
	// Check if the salt byte slice is valid UTF-8
	if !utf8.Valid(saltBytes) {
		// Return an error if the salt contains invalid UTF-8 characters
		return "", "", errors.New("invalid UTF-8 encoding in salt")
	}

	// Use Argon2 IDKey to stretch the passphrase and salt into a fixed-length hash
	stretchedHash := argon2.IDKey(passphraseBytes, saltBytes, iterations, memory, parallelism, tagSize)
	// Convert the stretched hash to a hexadecimal string representation
	stretchedHashStr := fmt.Sprintf("%x", stretchedHash)

	// Lock the mutex to ensure thread safety when accessing shared data
	mu.Lock()
	defer mu.Unlock()
	// Check if the generated hash already exists in the hash map
	if _, exists := passphraseHashes[stretchedHashStr]; exists {
		// Return an error if a duplicate passphrase is detected
		return "", "", errors.New("duplicate passphrase detected, regenerate")
	}
	// Add the new hash to the hash map
	passphraseHashes[stretchedHashStr] = struct{}{}

	// Encode the passphrase bytes using Base64 URL encoding
	encodedPassphrase := base64.URLEncoding.EncodeToString(passphraseBytes)
	// Encode the nonce bytes using Base64 URL encoding
	encodedNonce := base64.URLEncoding.EncodeToString(nonce)

	// Decode the Base64-encoded passphrase back into a byte slice
	decodedPassphrase, err := base64.URLEncoding.DecodeString(encodedPassphrase)
	if err != nil {
		// Return an error if passphrase decoding fails
		return "", "", fmt.Errorf("failed to decode passphrase: %w", err)
	}

	// Decode the Base64-encoded nonce back into a byte slice
	decodedNonce, err := base64.URLEncoding.DecodeString(encodedNonce)
	if err != nil {
		// Return an error if nonce decoding fails
		return "", "", fmt.Errorf("failed to decode nonce: %w", err)
	}

	// Convert the decoded passphrase and nonce byte slices to strings and return them
	return string(decodedPassphrase), string(decodedNonce), nil
}

// NewMnemonic generates a mnemonic from any .txt file in the directory
func NewMnemonic(entropy int) (string, string, error) {
	wordCount := (entropy + 10) / 11 // Calculates the required number of words based on entropy

	words, err := SelectAndLoadTxtFile(baseURL) // Loads the word list from the repository
	if err != nil {
		return "", "", fmt.Errorf("failed to load words: %w", err) // Returns an error if loading fails
	}

	passphrase, nonce, err := GeneratePassphrase(words, wordCount) // Generates a passphrase using the word list
	if err != nil {
		return "", "", fmt.Errorf("failed to generate passphrase: %w", err) // Returns an error if generation fails
	}

	return passphrase, nonce, nil // Returns the generated passphrase and nonce
}
