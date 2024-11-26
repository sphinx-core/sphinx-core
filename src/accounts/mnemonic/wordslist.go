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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
)

// GitHubFile represents the structure of file information returned by GitHub's API
type GitHubFile struct {
	Name string `json:"name"` // Name of the file
	Path string `json:"path"` // Path to the file in the repository
	Type string `json:"type"` // Type of the file (e.g., file, directory)
}

// Base URL for accessing the repository directory on GitHub (HTTP version)
const baseURL = "http://api.github.com/repos/sphinx-core/sips/contents/.github/workflows/sips0003" // Changed to HTTP

// Mutex and map used for preventing duplicate passphrases
var (
	mu               sync.Mutex              // Ensures thread-safe access to shared resources
	passphraseHashes = map[string]struct{}{} // Stores hashes of generated passphrases
)

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
	selectedFile := txtFiles[0] // Defaults to the first file
	if len(txtFiles) > 1 {      // If more than one .txt file exists
		randIndex, _ := rand.Int(rand.Reader, big.NewInt(int64(len(txtFiles)))) // Generates a random index
		selectedFile = txtFiles[randIndex.Int64()]                              // Selects the file at the random index
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

	return words, nil // Returns the list of words
}

// GeneratePassphrase creates a secure passphrase using a given word list
func GeneratePassphrase(words []string, wordCount int) (string, string, error) {
	if len(words) == 0 { // Checks if the word list is empty
		return "", "", errors.New("word list is empty") // Returns an error
	}

	var passphrase []string          // Stores the generated passphrase
	for i := 0; i < wordCount; i++ { // Loops to generate the required number of words
		randIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(words)))) // Generates a random index
		if err != nil {                                                        // Checks if random index generation fails
			return "", "", fmt.Errorf("failed to generate random index: %w", err) // Returns an error
		}
		passphrase = append(passphrase, words[randIndex.Int64()]) // Adds the selected word to the passphrase
	}

	passphraseStr := strings.Join(passphrase, " ") // Joins the words to form the passphrase string

	// Generate a nonce
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", "", fmt.Errorf("failed to generate nonce: %w", err)
	}
	nonceStr := fmt.Sprintf("%x", nonce) // Converts the nonce to a hexadecimal string

	// Combines the nonce and passphrase for hashing
	dataToHash := nonceStr + "|" + passphraseStr
	hash := sha256.Sum256([]byte(dataToHash)) // Generates the SHA-256 hash of the data
	hashStr := fmt.Sprintf("%x", hash)        // Converts the hash to a hexadecimal string

	// Ensure passphrase uniqueness by checking its hash
	mu.Lock()
	defer mu.Unlock()
	if _, exists := passphraseHashes[hashStr]; exists {
		return "", "", errors.New("duplicate passphrase detected, regenerate")
	}
	passphraseHashes[hashStr] = struct{}{}

	// Base64 encode the nonce for secure transmission
	encodedNonce := base64.StdEncoding.EncodeToString([]byte(nonceStr))

	// Return passphrase in plain text (words) and encoded nonce
	return passphraseStr, encodedNonce, nil
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

	return passphrase, nonce, nil // Returns the generated mnemonic passphrase and nonce
}
