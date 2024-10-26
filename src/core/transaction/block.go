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

package types

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
)

// Hash represents a fixed-size hash (32 bytes).
type Hash [32]byte // Define a Hash type as an array of 32 bytes

// MarshalText encodes h as a hex string with 0x prefix.
func (h Hash) MarshalText() ([]byte, error) {
	return []byte(fmt.Sprintf("0x%s", hex.EncodeToString(h[:]))), nil // Convert Hash to a hex string prefixed with "0x"
}

// UnmarshalText decodes a hex string into a Hash.
func (h *Hash) UnmarshalText(input []byte) error {
	if len(input) == 0 { // Check if input is empty
		return fmt.Errorf("input cannot be empty") // Return an error if empty
	}
	if string(input[:2]) == "0x" { // Check if the input starts with "0x"
		input = input[2:] // Remove the "0x" prefix
	}
	if len(input) != 64 { // Check if the length of the hex string is correct (64 hex characters)
		return fmt.Errorf("invalid Hash length, expected 64 hex characters") // Return an error if invalid
	}
	_, err := hex.Decode(h[:], input) // Decode the hex string into the Hash
	return err                        // Return any error encountered
}

// BlockNonce represents a nonce in the blockchain.
type BlockNonce [8]byte // Define a BlockNonce type as an array of 8 bytes

// EncodeNonce converts the given integer to a block nonce.
func EncodeNonce(i uint64) BlockNonce {
	var n BlockNonce                    // Declare a variable of type BlockNonce
	binary.BigEndian.PutUint64(n[:], i) // Encode the uint64 integer into the BlockNonce
	return n                            // Return the BlockNonce
}

// Uint64 returns the integer value of a block nonce.
func (n BlockNonce) Uint64() uint64 {
	return binary.BigEndian.Uint64(n[:]) // Decode the BlockNonce back to a uint64 integer
}

// MarshalText encodes n as a hex string with 0x prefix.
func (n BlockNonce) MarshalText() ([]byte, error) {
	return []byte(fmt.Sprintf("0x%s", hex.EncodeToString(n[:]))), nil // Convert BlockNonce to a hex string prefixed with "0x"
}

// UnmarshalText decodes a hex string into a BlockNonce.
func (n *BlockNonce) UnmarshalText(input []byte) error {
	if len(input) == 0 { // Check if input is empty
		return fmt.Errorf("input cannot be empty") // Return an error if empty
	}
	if string(input[:2]) == "0x" { // Check if the input starts with "0x"
		input = input[2:] // Remove the "0x" prefix
	}
	if len(input) != 16 { // Check if the length of the hex string is correct (16 hex characters)
		return fmt.Errorf("invalid BlockNonce length, expected 16 bytes") // Return an error if invalid
	}
	_, err := hex.Decode(n[:], input) // Decode the hex string into the BlockNonce
	return err                        // Return any error encountered
}

// UncleBlockHeader represents the header of an uncle block.
type UncleBlockHeader struct {
	ParentHash Hash       `json:"parentHash"` // The hash of the uncle's parent block
	Nonce      BlockNonce `json:"nonce"`      // Nonce for the uncle block
	Timestamp  uint64     `json:"timestamp"`  // Time when the uncle block was created (Unix timestamp)
	RootHash   RootHash   `json:"Roothash"`   // The hash of the uncle block
}

// Header represents the metadata of a block in the blockchain.
type Header struct {
	ParentHash      Hash       `json:"parent_hash"`      // The hash of the parent block
	PreviousHash    Hash       `json:"previous_hash"`    // The hash of the previous block
	Nonce           BlockNonce `json:"nonce"`            // Nonce for proof-of-work
	Timestamp       uint64     `json:"timestamp"`        // Time when the block was created (Unix timestamp)
	RootHash        RootHash   `json:"RootHash"`         // The hash of the current block
	TransactionRoot Hash       `json:"transaction_root"` // The root hash of the transactions in the block
	RecipientRoot   Hash       `json:"recipient_root"`   // The root hash of the recipient addresses
	StateRoot       Hash       `json:"state_root"`       // The root hash of the state
	Difficulty      *big.Int   `json:"difficulty"`       // Difficulty for mining
	GasLimit        *big.Int   `json:"gas_limit"`        // Gas limit for transactions
	GasUsed         *big.Int   `json:"gas_used"`         // Gas used by the block
}

// Block represents a block in the blockchain.
type Block struct {
	Header            *Header             `json:"header"`              // The header containing metadata
	Transactions      TransactionList     `json:"transactions"`        // The list of transactions in the block
	UncleBlockHeaders []*UncleBlockHeader `json:"uncle_block_headers"` // The uncle block headers
}

// NewBlock creates and returns a new block.
func NewBlock(header *Header, txs []*Transaction, uncles []*UncleBlockHeader, receipts []*Receipt, hasher TrieHasher) *Block {
	b := &Block{Header: CopyHeader(header)} // Create a new Block and copy the header

	// Panic if len(txs) != len(receipts)
	if len(txs) != len(receipts) {
		panic(fmt.Sprintf("transaction and receipt lengths do not match: %d vs %d", len(txs), len(receipts))) // Check for matching lengths
	}

	if len(txs) == 0 { // Check if there are no transactions
		b.Header.TransactionRoot = EmptyRootHash // Set transaction root to empty hash
	} else {
		b.Header.TransactionRoot = DeriveSha(Transactions(txs), hasher) // Calculate transaction root hash
		b.Transactions = make(TransactionList, len(txs))                // Create a slice for transactions
		copy(b.Transactions, txs)                                       // Copy transactions into the block
	}

	if len(receipts) == 0 { // Check if there are no receipts
		b.Header.ReceiptHash = EmptyRootHash // Set receipt hash to empty hash
	} else {
		b.Header.ReceiptHash = DeriveSha(Receipts(receipts), hasher) // Calculate receipt hash
		b.Header.Bloom = CreateBloom(receipts)                       // Create bloom filter for receipts
	}

	if len(uncles) == 0 { // Check if there are no uncles
		b.Header.UncleHash = EmptyUncleHash // Set uncle hash to empty hash
	} else {
		b.Header.UncleHash = CalcUncleHash(uncles)                   // Calculate uncle hash
		b.UncleBlockHeaders = make([]*UncleBlockHeader, len(uncles)) // Create a slice for uncle block headers
		for i := range uncles {                                      // Loop through uncle block headers
			b.UncleBlockHeaders[i] = CopyUncleBlockHeader(uncles[i]) // Copy each uncle block header
		}
	}

	return b // Return the newly created block
}

// CalculateHash computes the SHA-256 hash of the block header and its transactions.
func (b *Block) CalculateHash() Hash {
	// Initialize a string to hold the concatenated record of the block's metadata and transaction details
	record := hex.EncodeToString(b.Header.ParentHash[:]) + // Convert ParentHash to a hex string and append
		hex.EncodeToString(b.Header.PreviousHash[:]) + // Convert PreviousHash to a hex string and append
		hex.EncodeToString(b.Header.Nonce[:]) + // Convert Nonce to a hex string and append
		fmt.Sprintf("%d", b.Header.Timestamp) + // Convert Timestamp to a string and append
		hex.EncodeToString(b.Header.TransactionRoot[:]) + // Convert TransactionRoot to a hex string and append
		hex.EncodeToString(b.Header.RecipientRoot[:]) + // Convert RecipientRoot to a hex string and append
		hex.EncodeToString(b.Header.StateRoot[:]) + // Convert StateRoot to a hex string and append
		b.Header.Difficulty.String() + // Convert Difficulty to a string and append
		b.Header.GasLimit.String() + // Convert GasLimit to a string and append
		b.Header.GasUsed.String() // Convert GasUsed to a string and append

	// Iterate through each transaction in the block
	for _, tx := range b.Transactions { // Loop through each transaction
		// Append the details of the transaction (ID, From address, To address, Amount) to the record
		record += tx.ID + tx.From + tx.To + tx.Amount.String() // Concatenate transaction details
	}

	// Iterate through each uncle block header in the block
	for _, uncle := range b.UncleBlockHeaders { // Loop through each uncle block header
		// Append the details of the uncle block (ParentHash, Nonce, Timestamp, Hash) to the record
		record += hex.EncodeToString(uncle.ParentHash[:]) + // Convert ParentHash to a hex string and append
			hex.EncodeToString(uncle.Nonce[:]) + // Convert Nonce to a hex string and append
			fmt.Sprintf("%d", uncle.Timestamp) + // Convert Timestamp to a string and append
			hex.EncodeToString(uncle.Hash[:]) // Convert Hash to a hex string and append
	}

	// Create a new SHA-256 hash object
	h := sha256.New()       // Initialize SHA-256 hash function
	h.Write([]byte(record)) // Write the concatenated record string as bytes to the hash object

	var hash Hash             // Declare a variable of type Hash to hold the computed hash
	copy(hash[:], h.Sum(nil)) // Compute the final hash and copy it into the Hash variable

	return hash // Return the computed SHA-256 hash of the block
}

// SanityCheck performs basic validation on the block's fields.
func (b *Block) SanityCheck() error {
	if len(b.Header.ParentHash) != 32 || len(b.Header.PreviousHash) != 32 { // Check if ParentHash and PreviousHash are 32 bytes long
		return fmt.Errorf("invalid ParentHash or PreviousHash length") // Return an error if invalid
	}

	if b.Header.Timestamp == 0 { // Check if the timestamp is zero
		return fmt.Errorf("invalid timestamp") // Return an error if invalid
	}

	if b.Header.Nonce == (BlockNonce{}) { // Check if the nonce is empty
		return fmt.Errorf("nonce cannot be empty") // Return an error if invalid
	}

	return nil // Return nil if all checks pass
}

// String returns a string representation of the block.
func (b *Block) String() string {
	return fmt.Sprintf("Block{Header: %v, Transactions: %d, Uncles: %d}", b.Header, len(b.Transactions), len(b.UncleBlockHeaders)) // Format block details as a string
}
