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
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/yourproject/common" // replace with your actual common package path
)

// Define custom errors
var (
	ErrUnexpectedProtection = errors.New("unexpected signature protection")
	ErrInvalidSig           = errors.New("invalid signature")
	ErrInvalidDataLength    = errors.New("invalid data length for unmarshal")
)

// AccessList type (define as per your requirements)
type AccessList struct {
	// Define your access list structure
}

// Transaction struct containing transaction data
type Transaction struct {
	inner     TxData    // Transaction data
	Timestamp time.Time // Add timestamp field
}

// TxData interface defining essential methods for transaction data
type TxData interface {
	txType() byte                                 // Returns the type ID
	copy() TxData                                 // Creates a deep copy
	chainID() *big.Int                            // Returns the chain ID
	accessList() AccessList                       // Returns the access list
	data() []byte                                 // Returns the data
	gas() uint64                                  // Returns the gas limit
	gasPrice() *big.Int                           // Returns the gas price
	gasTipCap() *big.Int                          // Returns the gas tip cap
	gasFeeCap() *big.Int                          // Returns the gas fee cap
	value() *big.Int                              // Returns the value
	nonce() uint64                                // Returns the nonce
	to() *common.Address                          // Returns the recipient address
	rawSignatureValues() (v, r, s *big.Int)       // Returns raw signature values
	setSignatureValues(chainID, v, r, s *big.Int) // Sets signature values
}

// Message struct for transaction message
type Message struct {
	from       common.Address
	to         *common.Address
	nonce      uint64
	amount     *big.Int
	gasLimit   uint64
	gasPrice   *big.Int
	gasFeeCap  *big.Int
	gasTipCap  *big.Int
	data       []byte
	accessList AccessList
	isFake     bool
}

// Methods for Message struct
func (m Message) From() common.Address   { return m.from }
func (m Message) To() *common.Address    { return m.to }
func (m Message) GasPrice() *big.Int     { return m.gasPrice }
func (m Message) GasFeeCap() *big.Int    { return m.gasFeeCap }
func (m Message) GasTipCap() *big.Int    { return m.gasTipCap }
func (m Message) Value() *big.Int        { return m.amount }
func (m Message) Gas() uint64            { return m.gasLimit }
func (m Message) Nonce() uint64          { return m.nonce }
func (m Message) Data() []byte           { return m.data }
func (m Message) AccessList() AccessList { return m.accessList }
func (m Message) IsFake() bool           { return m.isFake }

// MarshalBinary for Transaction struct
func (tx *Transaction) MarshalBinary() ([]byte, error) {
	data, err := tx.inner.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// Add timestamp (8 bytes)
	timestamp := make([]byte, 8)
	binary.BigEndian.PutUint64(timestamp, uint64(tx.Timestamp.Unix()))
	return append(data, timestamp...), nil
}

// UnmarshalBinary for Transaction struct
func (tx *Transaction) UnmarshalBinary(data []byte) error {
	if len(data) < 8 { // Check for minimum data length (8 bytes for timestamp)
		return ErrInvalidDataLength
	}

	// Check if the first byte indicates a valid data length
	if len(data) > 0 && data[0] > 0x7f {
		// Read timestamp from data (assuming it's at the end)
		timestamp := int64(binary.BigEndian.Uint64(data[len(data)-8:])) // Last 8 bytes
		tx.Timestamp = time.Unix(timestamp, 0)                          // Convert to time.Time

		// Deserialize transaction data
		tx.inner = &Message{} // Assuming Message implements TxData
		if err := tx.inner.UnmarshalBinary(data[:len(data)-8]); err != nil {
			return err
		}
	} else {
		return ErrInvalidDataLength // Handle case for unexpected data format
	}

	return nil
}

// Sanity check for transaction signature
func sanityCheckSignature(v *big.Int, r *big.Int, s *big.Int, maybeProtected bool) error {
	if isProtectedV(v) && !maybeProtected {
		return ErrUnexpectedProtection
	}

	var plainV byte
	if isProtectedV(v) {
		chainID := deriveChainId(v).Uint64()
		plainV = byte(v.Uint64() - 35 - 2*chainID)
	} else if maybeProtected {
		plainV = byte(v.Uint64() - 27)
	} else {
		plainV = byte(v.Uint64())
	}

	if !ValidateSignatureValues(plainV, r, s, false) {
		return ErrInvalidSig
	}

	return nil
}

// Helper function to check if the signature is protected
func isProtectedV(V *big.Int) bool {
	if V.BitLen() <= 8 {
		v := V.Uint64()
		return v != 27 && v != 28 && v != 1 && v != 0
	}
	return true
}

// Protected method checks whether the transaction is replay-protected
func (tx *Transaction) Protected() bool {
	switch tx := tx.inner.(type) {
	case *LegacyTx: // Ensure LegacyTx implements TxData
		return tx.V != nil && isProtectedV(tx.V)
	default:
		return true
	}
}

// Derives chain ID from the given value
func deriveChainId(v *big.Int) *big.Int {
	// Implement the logic to derive chain ID based on the signature values
	return big.NewInt(1) // Replace with actual implementation
}

// Validates signature values
func ValidateSignatureValues(v byte, r, s *big.Int, requireStrict bool) bool {
	// Implement the validation logic for signature values
	return true // Replace with actual implementation
}

// Sign the transaction using a private key (dummy implementation)
func (m *Message) Sign(privateKey []byte) error {
	// Implement the signing logic using the provided private key
	// For now, just set a dummy signature
	return nil
}

// Verify the transaction signature (dummy implementation)
func (m *Message) Verify() (bool, error) {
	// Implement the verification logic for the signature
	return true, nil // Replace with actual implementation
}

// Display transaction details
func (m Message) String() string {
	return fmt.Sprintf("From: %s, To: %s, Nonce: %d, Amount: %s, Gas Limit: %d, Gas Price: %s, Is Fake: %t",
		m.from.Hex(), m.to.Hex(), m.nonce, m.amount.String(), m.gasLimit, m.gasPrice.String(), m.isFake)
}

// Additional utility functions
func (m *Message) UpdateGasPrice(newGasPrice *big.Int) {
	m.gasPrice = newGasPrice
}

func (m *Message) SetFake(isFake bool) {
	m.isFake = isFake
}
