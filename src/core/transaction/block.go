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
	"time"
)

// BlockNonce represents a nonce in the blockchain.
type BlockNonce [8]byte

// EncodeNonce converts the given integer to a block nonce.
func EncodeNonce(i uint64) BlockNonce {
	var n BlockNonce
	binary.BigEndian.PutUint64(n[:], i)
	return n
}

// Uint64 returns the integer value of a block nonce.
func (n BlockNonce) Uint64() uint64 {
	return binary.BigEndian.Uint64(n[:])
}

// MarshalText encodes n as a hex string with 0x prefix.
func (n BlockNonce) MarshalText() ([]byte, error) {
	return []byte(fmt.Sprintf("0x%s", hex.EncodeToString(n[:]))), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (n *BlockNonce) UnmarshalText(input []byte) error {
	if len(input) == 0 {
		return fmt.Errorf("input cannot be empty")
	}
	if input[0:2][0] == '0' && input[0:2][1] == 'x' {
		input = input[2:] // Remove 0x prefix if it exists
	}
	if len(input) != 16 {
		return fmt.Errorf("invalid BlockNonce length")
	}
	_, err := hex.Decode(n[:], input)
	return err
}

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
	ParentHash string      // The hash of the uncle's parent block
	Nonce      *BlockNonce // Nonce for the uncle block
	Timestamp  time.Time   // Time when the uncle block was created
	Hash       string      // The hash of the uncle block
}

// Header represents the metadata of a block in the blockchain.
type Header struct {
	ParentHash      string      `json:"parent_hash"`      // The hash of the parent block
	PreviousHash    string      `json:"previous_hash"`    // The hash of the previous block
	Nonce           *BlockNonce `json:"nonce"`            // A nonce for proof-of-work
	Timestamp       time.Time   `json:"timestamp"`        // The time when the block was created
	Hash            string      `json:"hash"`             // The hash of the current block
	TransactionRoot string      `json:"transaction_root"` // The root hash of the transactions in the block
	RecipientRoot   string      `json:"recipient_root"`   // The root hash of the recipient addresses
	Difficulty      *big.Int    `json:"difficulty"`       // The difficulty level for mining
	Gas             *big.Int    `json:"gas"`              // The gas limit for transactions
}

// Block represents a block in the blockchain.
type Block struct {
	Header            Header             // The header containing metadata
	TransactionList   TransactionList    // The list of transactions in the block
	UncleBlockHeaders []UncleBlockHeader // The uncle block headers
}

// nBlock creates and returns a new block with the given transactions and previous hashes.
func nBlock(transactionList TransactionList, previousHash string, parentHash string, transactionRoot string, recipientRoot string, difficulty *big.Int, gas *big.Int, uncleBlockHeaders []UncleBlockHeader) *Block {
	header := Header{
		ParentHash:      parentHash,
		PreviousHash:    previousHash,
		Nonce:           big.NewInt(0), // Placeholder for nonce; set this when mining
		Timestamp:       time.Now(),
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

	// Perform mining to find a valid hash based on the difficulty level
	block.mineBlock()
	return block
}

// mineBlock performs mining by adjusting the nonce until the block hash meets the difficulty requirement.
// SanityCheck checks for basic validity of the block fields.
func (b *Block) SanityCheck() error {
	// Check that ParentHash and PreviousHash are valid hashes (non-empty and length of 64 hex characters).
	if len(b.Header.ParentHash) != 64 || len(b.Header.PreviousHash) != 64 {
		return fmt.Errorf("invalid ParentHash or PreviousHash length")
	}

	// Check that the Nonce is a reasonable size (non-negative).
	if b.Header.Nonce == nil || b.Header.Nonce.Sign() == -1 {
		return fmt.Errorf("invalid Nonce value")
	}

	// Check that the Difficulty is within a reasonable range.
	if b.Header.Difficulty == nil || b.Header.Difficulty.Cmp(big.NewInt(0)) <= 0 || b.Header.Difficulty.Cmp(big.NewInt(1<<30)) > 0 {
		return fmt.Errorf("unrealistic Difficulty value")
	}

	// Check that the Timestamp is not set in the future (give a little leeway for clock drift).
	if b.Header.Timestamp.After(time.Now().Add(5 * time.Minute)) {
		return fmt.Errorf("timestamp too far in the future")
	}

	// Check that the Gas limit is reasonable (greater than zero and less than some upper bound).
	if b.Header.Gas == nil || b.Header.Gas.Cmp(big.NewInt(0)) <= 0 || b.Header.Gas.Cmp(big.NewInt(1<<50)) > 0 {
		return fmt.Errorf("invalid Gas value")
	}

	// Check the hash has valid length (64 hex characters).
	if len(b.Header.Hash) != 64 {
		return fmt.Errorf("invalid Block Hash length")
	}

	// Check all transactions in the TransactionList.
	for _, tx := range b.TransactionList.Transactions {
		if err := tx.SanityCheck(); err != nil {
			return fmt.Errorf("transaction sanity check failed: %v", err)
		}
	}

	// Check all uncle block headers.
	for _, uncle := range b.UncleBlockHeaders {
		if err := uncle.SanityCheck(); err != nil {
			return fmt.Errorf("uncle block header sanity check failed: %v", err)
		}
	}

	return nil
}

// SanityCheck for a Transaction.
func (tx *Transaction) SanityCheck() error {
	// Check that the transaction has a valid ID (non-empty and valid hash length).
	if len(tx.ID) != 64 {
		return fmt.Errorf("invalid Transaction ID length")
	}

	// Check that the From and To addresses are non-empty.
	if tx.From == "" || tx.To == "" {
		return fmt.Errorf("transaction addresses cannot be empty")
	}

	// Check that the Amount is greater than zero.
	if tx.Amount == nil || tx.Amount.Sign() <= 0 {
		return fmt.Errorf("invalid transaction Amount")
	}

	return nil
}

// SanityCheck for an UncleBlockHeader.
func (uncle *UncleBlockHeader) SanityCheck() error {
	// Check the ParentHash is a valid hash (non-empty and 64 hex characters).
	if len(uncle.ParentHash) != 64 {
		return fmt.Errorf("invalid Uncle ParentHash length")
	}

	// Check the Nonce is a reasonable value (non-negative).
	if uncle.Nonce == nil || uncle.Nonce.Sign() == -1 {
		return fmt.Errorf("invalid Uncle Nonce value")
	}

	// Check the Timestamp is not in the future.
	if uncle.Timestamp.After(time.Now().Add(5 * time.Minute)) {
		return fmt.Errorf("uncle block timestamp too far in the future")
	}

	// Check that the Uncle Hash is valid (64 hex characters).
	if len(uncle.Hash) != 64 {
		return fmt.Errorf("invalid Uncle Hash length")
	}

	return nil
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
