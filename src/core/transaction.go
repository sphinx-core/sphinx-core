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

package transaction

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/kasperdi/SPHINCSPLUS-golang/parameters"
	"github.com/kasperdi/SPHINCSPLUS-golang/sphincs"
	"golang.org/x/crypto/sha3"
)

// GasFee represents gas price and limit
type GasFee struct {
	GasPrice int64 // Gas price in units of currency
	GasLimit int64 // Maximum gas that can be spent on the transaction
}

// Transaction represents a single coin transaction
type Transaction struct {
	Sender    *sphincs.SPHINCS_PK  // Sender's public key
	Receiver  *sphincs.SPHINCS_PK  // Receiver's public key (for regular transactions)
	Nonce     uint64               // Nonce to prevent double-spending
	Value     int64                // Transaction value
	Signature *sphincs.SPHINCS_SIG // SPHINCS+ signature
	GasFee    GasFee               // Gas fee for the transaction
}

// ContractTransaction represents a contract deployment transaction
type ContractTransaction struct {
	Creator   *sphincs.SPHINCS_PK  // Creator's public key
	Nonce     uint64               // Nonce to prevent replay attacks
	Contract  string               // Contract code or logic (simplified as a string for now)
	Bytecode  []byte               // Bytecode for the contract
	Signature *sphincs.SPHINCS_SIG // SPHINCS+ signature
	GasFee    GasFee               // Gas fee for deploying the contract
}

// Account represents an Ethereum-like account with a nonce and balance
type Account struct {
	PublicKey *sphincs.SPHINCS_PK
	Nonce     uint64
	Balance   int64
}

// State represents the current state of the blockchain
type State struct {
	data map[string]interface{}
}

// Blockchain represents the public ledger
type Blockchain struct {
	transactions []*Transaction         // Chain of regular transactions (ledger)
	contracts    []*ContractTransaction // Chain of contract deployment transactions
	accounts     map[string]*Account    // Accounts by their public key (simplified)
	state        State                  // Current state of the blockchain
}

// NewTransaction creates a new payment transaction signed by the sender
func NewTransaction(sender *sphincs.SPHINCS_SK, receiver *sphincs.SPHINCS_PK, value int64, nonce uint64, gasPrice int64, gasLimit int64) (*Transaction, error) {
	tx := &Transaction{
		Sender:   sender.PublicKey(),
		Receiver: receiver,
		Value:    value,
		Nonce:    nonce,
		GasFee: GasFee{
			GasPrice: gasPrice,
			GasLimit: gasLimit,
		},
	}

	// Hash the transaction data
	txHash := tx.Hash()

	// Sign the transaction hash using the sender's secret key
	sig, _, err := sign.SignMessage(parameters.DefaultParams, txHash, sender)
	if err != nil {
		return nil, err
	}

	tx.Signature = sig

	return tx, nil
}

// NewContractTransaction creates a new contract deployment signed by the creator
func NewContractTransaction(creator *sphincs.SPHINCS_SK, contractCode string, bytecode []byte, nonce uint64, gasPrice int64, gasLimit int64) (*ContractTransaction, error) {
	tx := &ContractTransaction{
		Creator:  creator.PublicKey(),
		Contract: contractCode,
		Bytecode: bytecode,
		Nonce:    nonce,
		GasFee: GasFee{
			GasPrice: gasPrice,
			GasLimit: gasLimit,
		},
	}

	// Hash the contract deployment data
	txHash := tx.Hash()

	// Sign the transaction hash using the creator's secret key
	sig, _, err := sign.SignMessage(parameters.DefaultParams, txHash, creator)
	if err != nil {
		return nil, err
	}

	tx.Signature = sig

	return tx, nil
}

// Hash computes the SHAKE256 hash of a regular transaction
func (tx *Transaction) Hash() []byte {
	txData := fmt.Sprintf("%x%x%d%d%d%d", tx.Sender, tx.Receiver, tx.Value, tx.Nonce, tx.GasFee.GasPrice, tx.GasFee.GasLimit)
	hash := make([]byte, 32) // 32 bytes (256 bits) of output
	shake := sha3.NewShake256()
	shake.Write([]byte(txData))
	shake.Read(hash)
	return hash
}

// Hash computes the SHAKE256 hash of a contract deployment transaction
func (tx *ContractTransaction) Hash() []byte {
	txData := fmt.Sprintf("%x%s%d%d%d", tx.Creator, tx.Contract, tx.Nonce, tx.GasFee.GasPrice, tx.GasFee.GasLimit)
	hash := make([]byte, 32) // 32 bytes (256 bits) of output
	shake := sha3.NewShake256()
	shake.Write([]byte(txData))
	shake.Read(hash)
	return hash
}

// Verify checks the validity of a transaction by verifying its digital signature
func (tx *Transaction) Verify() error {
	txHash := tx.Hash()
	valid := sign.VerifySignature(parameters.DefaultParams, txHash, tx.Signature, tx.Sender, nil)
	if !valid {
		return errors.New("invalid transaction signature")
	}
	return nil
}

// Verify checks the validity of a contract transaction by verifying its digital signature
func (tx *ContractTransaction) Verify() error {
	txHash := tx.Hash()
	valid := sign.VerifySignature(parameters.DefaultParams, txHash, tx.Signature, tx.Creator, nil)
	if !valid {
		return errors.New("invalid contract transaction signature")
	}
}

// AddTransaction adds a new transaction to the blockchain (ledger)
func (bc *Blockchain) AddTransaction(tx *Transaction) error {
	// Verify the transaction before adding it to the ledger
	err := tx.Verify()
	if err != nil {
		return err
	}

	// Check nonce to prevent double-spending or out-of-order transactions
	account, ok := bc.accounts[publicKeyToString(tx.Sender)]
	if !ok || account.Nonce != tx.Nonce {
		return errors.New("invalid nonce")
	}

	// Check for sufficient balance after gas fees
	totalCost := tx.Value + (tx.GasFee.GasPrice * tx.GasFee.GasLimit)
	if account.Balance < totalCost {
		return errors.New("insufficient funds")
	}

	// Deduct balance and increment nonce for the sender
	account.Balance -= totalCost
	account.Nonce++

	// Add the verified transaction to the blockchain
	bc.transactions = append(bc.transactions, tx)
	return nil
}

// AddContractTransaction adds a contract deployment to the blockchain
func (bc *Blockchain) AddContractTransaction(tx *ContractTransaction) error {
	// Verify the contract transaction before adding it to the blockchain
	err := tx.Verify()
	if err != nil {
		return err
	}

	// Check nonce to prevent double-spending
	account, ok := bc.accounts[publicKeyToString(tx.Creator)]
	if !ok || account.Nonce != tx.Nonce {
		return errors.New("invalid nonce")
	}

	// Check for sufficient balance after gas fees
	totalCost := tx.GasFee.GasPrice * tx.GasFee.GasLimit
	if account.Balance < totalCost {
		return errors.New("insufficient funds for contract deployment")
	}

	// Deploy the contract (we could store contract bytecode or logic)
	bc.contracts = append(bc.contracts, tx)
	account.Balance -= totalCost // Deduct the gas fee
	account.Nonce++

	return nil
}

// InvokeContract executes a contract's bytecode and updates the state
func (bc *Blockchain) InvokeContract(contractAddress string, methodName string, args []interface{}) (interface{}, error) {
	// Here we should find the corresponding contract and execute its bytecode
	// For simplicity, we're just printing the method call and args
	for _, contract := range bc.contracts {
		if contract.Contract == contractAddress {
			// Placeholder for actual execution logic
			fmt.Printf("Invoking method %s on contract %s with args: %v\n", methodName, contractAddress, args)
			return nil, nil // Returning nil as no state changes are implemented yet
		}
	}
	return nil, errors.New("contract not found")
}

// publicKeyToString converts a public key to a string representation
func publicKeyToString(pub *sphincs.SPHINCS_PK) string {
	// Adjust this conversion according to the structure of your SPHINCS public key
	return hex.EncodeToString(pub.Serialize())
}
