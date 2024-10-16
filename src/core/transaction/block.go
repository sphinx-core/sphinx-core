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
	"encoding/hex"
	"math/big"
	"time"
)

// Transaction represents a transaction in the blockchain.
type Transaction struct {
	ID     string   // Unique identifier for the transaction
	From   string   // Sender's address
	To     string   // Receiver's address
	Amount *big.Int // Amount transferred, using big.Int for larger values
}

// TransactionList represents a list of transactions in the blockchain.
type TransactionList struct {
	Transactions []Transaction // Slice of transactions
}

// UncleBlockHeader represents the header of an uncle block.
type UncleBlockHeader struct {
	ParentHash string    // The hash of the uncle's parent block
	Nonce      *big.Int  // Nonce for the uncle block, using big.Int for larger values
	Timestamp  time.Time // Time when the uncle block was created
	Hash       string    // The hash of the uncle block
}

// Header represents the metadata of a block in the blockchain.
type Header struct {
	ParentHash      string    // The hash of the parent block
	PreviousHash    string    // The hash of the previous block
	Nonce           *big.Int  // A nonce for proof-of-work, using big.Int for larger values
	Timestamp       time.Time // The time when the block was created
	Hash            string    // The hash of the current block
	TransactionRoot string    // The root hash of the transactions in the block
	RecipientRoot   string    // The root hash of the recipient addresses
	Difficulty      *big.Int  // The difficulty level for mining, using big.Int for larger values
	Gas             *big.Int  // The gas limit for transactions, using big.Int for larger values
}

// Block represents a block in the blockchain.
type Block struct {
	Header            Header             // The header containing metadata
	TransactionList   TransactionList    // The list of transactions in the block
	UncleBlockHeaders []UncleBlockHeader // The uncle block headers
}

// Define a constant for the hardcoded hash value
// The constant defaultHash serves as a placeholder for the initial hash value of a block when it is first created in the blockchain
// "0x" prefix is base16 widely adopt to tell the mechine that is 256-bit value in hexadecimal format
const defaultHash = "0x4b52f5d04adce68dbe00019747b1fc826f82449eb12c0b837b209f421099589a"

// nBlock creates and returns a new block with the given transactions and previous hashes.
func nBlock(transactionList TransactionList, previousHash string, parentHash string, transactionRoot string, recipientRoot string, difficulty *big.Int, gas *big.Int, uncleBlockHeaders []UncleBlockHeader) *Block {
	header := Header{
		ParentHash:      parentHash,
		PreviousHash:    previousHash,
		Nonce:           big.NewInt(0), // Placeholder for nonce; set this when mining
		Timestamp:       time.Now(),
		Hash:            defaultHash, // Use the constant for the hash
		TransactionRoot: transactionRoot,
		RecipientRoot:   recipientRoot,
		Difficulty:      difficulty,
		Gas:             gas,
	}

	block := &Block{
		Header:            header,
		TransactionList:   transactionList,
		UncleBlockHeaders: uncleBlockHeaders,
	}

	// Calculate the block hash
	block.Header.Hash = block.calculateHash()
	return block
}

// calculateHash computes the SHA-256 hash of the block header and its transactions.
func (b *Block) calculateHash() string {
	record := b.Header.ParentHash + b.Header.PreviousHash + b.Header.Nonce.String() +
		b.Header.Timestamp.String() + b.Header.TransactionRoot + b.Header.RecipientRoot +
		b.Header.Difficulty.String() + b.Header.Gas.String()

	// Include transaction data in the hash
	for _, tx := range b.TransactionList.Transactions {
		record += tx.ID + tx.From + tx.To + tx.Amount.String()
	}

	// Include uncle block headers in the hash
	for _, uncle := range b.UncleBlockHeaders {
		record += uncle.ParentHash + uncle.Nonce.String() + uncle.Timestamp.String() + uncle.Hash
	}

	h := sha256.New()
	h.Write([]byte(record))
	return hex.EncodeToString(h.Sum(nil))
}

// SetNonce sets the nonce for the block.
func (b *Block) SetNonce(nonce *big.Int) {
	b.Header.Nonce = nonce
}

// GetHash returns the hash of the block.
func (b *Block) GetHash() string {
	return b.Header.Hash
}
