package blockchain

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/seagercortez/qbitchain/internal/crypto"
)

// Constants for transactions
const (
	// TxVersion is the current transaction version
	TxVersion = 1
	// MaxTxInputs is the maximum number of inputs in a transaction
	MaxTxInputs = 1024
	// MaxTxOutputs is the maximum number of outputs in a transaction
	MaxTxOutputs = 1024
	// MaxTxSize is the maximum size of a transaction in bytes
	MaxTxSize = 100 * 1024 // 100KB
	// MinTxFee is the minimum transaction fee
	MinTxFee = 1000
)

// TxInput represents a transaction input
type TxInput struct {
	TxID        [32]byte `json:"tx_id"`        // The transaction ID being referenced
	OutputIndex uint32   `json:"output_index"` // The output index in the referenced transaction
	Signature   []byte   `json:"signature"`    // The signature to unlock the output
	PublicKey   []byte   `json:"public_key"`   // The public key that matches the output's public key hash
}

// TxOutput represents a transaction output
type TxOutput struct {
	Value         uint64   `json:"value"`          // The amount of coins
	PublicKeyHash []byte   `json:"public_key_hash"` // The public key hash of the recipient
	ScriptType    uint8    `json:"script_type"`    // The type of script (0 = P2PKH, 1 = P2SH, etc.)
}

// Transaction represents a QBitChain transaction
type Transaction struct {
	Version    uint32     `json:"version"`
	Timestamp  time.Time  `json:"timestamp"`
	Inputs     []TxInput  `json:"inputs"`
	Outputs    []TxOutput `json:"outputs"`
	LockTime   uint32     `json:"lock_time"`  // When transaction can be mined (0 = immediately)
	Hash       [32]byte   `json:"hash"`
	Size       uint64     `json:"size"`
	Fee        uint64     `json:"fee"`        // Transaction fee
	GasPrice   uint64     `json:"gas_price"`  // Gas price in QBit/gas
	GasLimit   uint64     `json:"gas_limit"`  // Gas limit for the transaction
	GasUsed    uint64     `json:"gas_used"`   // Gas used by the transaction
	IsCoinbase bool       `json:"is_coinbase"`
}

// NewTransaction creates a new transaction
func NewTransaction(inputs []TxInput, outputs []TxOutput, fee, gasPrice, gasLimit uint64) *Transaction {
	tx := &Transaction{
		Version:   TxVersion,
		Timestamp: time.Now().UTC(),
		Inputs:    inputs,
		Outputs:   outputs,
		LockTime:  0,
		Fee:       fee,
		GasPrice:  gasPrice,
		GasLimit:  gasLimit,
	}

	// Calculate the hash of the transaction
	tx.Hash = tx.CalculateHash()

	return tx
}

// NewCoinbaseTransaction creates a new coinbase transaction with the given reward
func NewCoinbaseTransaction(toAddress string, reward uint64) *Transaction {
	// Create a dummy input for coinbase transaction
	txin := TxInput{
		TxID:        [32]byte{},
		OutputIndex: 0xFFFFFFFF,
		Signature:   []byte{}, // No signature needed for coinbase
		PublicKey:   []byte{}, // No public key needed for coinbase
	}

	// Create the output with the mining reward
	pubKeyHash, _ := crypto.AddressToPublicKeyHash(toAddress)
	txout := TxOutput{
		Value:         reward,
		PublicKeyHash: pubKeyHash,
		ScriptType:    0, // P2PKH
	}

	// Create the transaction
	tx := &Transaction{
		Version:    TxVersion,
		Timestamp:  time.Now().UTC(),
		Inputs:     []TxInput{txin},
		Outputs:    []TxOutput{txout},
		LockTime:   0,
		Fee:        0, // No fee for coinbase transactions
		IsCoinbase: true,
	}

	// Calculate the hash of the transaction
	tx.Hash = tx.CalculateHash()

	return tx
}

// CalculateHash calculates the hash of the transaction
func (tx *Transaction) CalculateHash() [32]byte {
	// Serialize the transaction
	var buf bytes.Buffer

	// Version
	binary.Write(&buf, binary.LittleEndian, tx.Version)

	// Timestamp
	binary.Write(&buf, binary.LittleEndian, tx.Timestamp.Unix())

	// Number of inputs
	binary.Write(&buf, binary.LittleEndian, uint32(len(tx.Inputs)))

	// Inputs
	for _, input := range tx.Inputs {
		buf.Write(input.TxID[:])
		binary.Write(&buf, binary.LittleEndian, input.OutputIndex)
		
		// For coinbase txs, we don't hash the signature and public key
		if !tx.IsCoinbase {
			binary.Write(&buf, binary.LittleEndian, uint32(len(input.Signature)))
			buf.Write(input.Signature)
			binary.Write(&buf, binary.LittleEndian, uint32(len(input.PublicKey)))
			buf.Write(input.PublicKey)
		}
	}

	// Number of outputs
	binary.Write(&buf, binary.LittleEndian, uint32(len(tx.Outputs)))

	// Outputs
	for _, output := range tx.Outputs {
		binary.Write(&buf, binary.LittleEndian, output.Value)
		binary.Write(&buf, binary.LittleEndian, uint32(len(output.PublicKeyHash)))
		buf.Write(output.PublicKeyHash)
		binary.Write(&buf, binary.LittleEndian, output.ScriptType)
	}

	// Lock Time
	binary.Write(&buf, binary.LittleEndian, tx.LockTime)

	// Fee, Gas Price, Gas Limit
	binary.Write(&buf, binary.LittleEndian, tx.Fee)
	binary.Write(&buf, binary.LittleEndian, tx.GasPrice)
	binary.Write(&buf, binary.LittleEndian, tx.GasLimit)

	// Hash the serialized transaction
	return sha256.Sum256(buf.Bytes())
}

// Sign signs the transaction inputs with the provided private key
func (tx *Transaction) Sign(privateKey *crypto.PrivateKey, prevTxs map[[32]byte]*Transaction) error {
	// Coinbase transactions do not need to be signed
	if tx.IsCoinbase {
		return nil
	}

	// Create a copy of the transaction to sign
	txCopy := tx.TrimmedCopy()

	// Sign each input
	for inID, input := range txCopy.Inputs {
		// Find the referenced transaction
		prevTx, ok := prevTxs[input.TxID]
		if !ok {
			return fmt.Errorf("previous transaction not found: %s", hex.EncodeToString(input.TxID[:]))
		}

		// Check if the output index is valid
		if int(input.OutputIndex) >= len(prevTx.Outputs) {
			return fmt.Errorf("invalid output index %d for transaction %s", input.OutputIndex, hex.EncodeToString(input.TxID[:]))
		}

		// Get the output being spent
		output := prevTx.Outputs[input.OutputIndex]

		// Set the signature to nil
		txCopy.Inputs[inID].Signature = nil
		// Set the public key to the output's public key hash
		txCopy.Inputs[inID].PublicKey = output.PublicKeyHash

		// Calculate the hash of the modified transaction
		txCopy.Hash = txCopy.CalculateHash()

		// Reset the public key
		txCopy.Inputs[inID].PublicKey = nil

		// Sign the transaction hash with the private key
		signature, err := privateKey.Sign(txCopy.Hash[:])
		if err != nil {
			return fmt.Errorf("failed to sign transaction: %w", err)
		}

		// Set the signature and public key in the original transaction
		tx.Inputs[inID].Signature = signature
		tx.Inputs[inID].PublicKey = privateKey.PublicKey.Serialize()
	}

	return nil
}

// Validate validates the transaction
func (tx *Transaction) Validate() error {
	// Coinbase transactions are always valid
	if tx.IsCoinbase {
		return nil
	}
	
	// Node reward transactions (special case with OutputIndex = 0xFFFFFFFE) are valid
	if len(tx.Inputs) > 0 && tx.Inputs[0].OutputIndex == 0xFFFFFFFE {
		return nil
	}

	// Check basic transaction constraints
	if len(tx.Inputs) == 0 {
		return fmt.Errorf("transaction has no inputs")
	}
	if len(tx.Inputs) > MaxTxInputs {
		return fmt.Errorf("transaction has too many inputs")
	}
	if len(tx.Outputs) == 0 {
		return fmt.Errorf("transaction has no outputs")
	}
	if len(tx.Outputs) > MaxTxOutputs {
		return fmt.Errorf("transaction has too many outputs")
	}

	// Verify each output has a positive value
	for i, output := range tx.Outputs {
		if output.Value == 0 {
			return fmt.Errorf("output %d has zero value", i)
		}
		if len(output.PublicKeyHash) == 0 {
			return fmt.Errorf("output %d has empty public key hash", i)
		}
	}

	// Verify the transaction size
	serialized, _ := tx.Serialize()
	if len(serialized) > MaxTxSize {
		return fmt.Errorf("transaction size exceeds maximum allowed")
	}

	// Verify the fee is at least the minimum required
	if tx.Fee < MinTxFee {
		return fmt.Errorf("transaction fee is too low")
	}

	// NOTE: To fully validate a transaction, we would need access to the UTXO set
	// to verify that each input actually exists and has not been spent already.
	// This would be done in a separate function that takes the UTXO set as input.

	return nil
}

// TrimmedCopy creates a trimmed copy of the transaction for signing
func (tx *Transaction) TrimmedCopy() *Transaction {
	var inputs []TxInput
	var outputs []TxOutput

	// Copy inputs without signatures and public keys
	for _, input := range tx.Inputs {
		inputs = append(inputs, TxInput{
			TxID:        input.TxID,
			OutputIndex: input.OutputIndex,
			Signature:   nil,
			PublicKey:   nil,
		})
	}

	// Copy outputs as is
	for _, output := range tx.Outputs {
		outputs = append(outputs, output)
	}

	// Create a new transaction with the copied inputs and outputs
	txCopy := &Transaction{
		Version:   tx.Version,
		Timestamp: tx.Timestamp,
		Inputs:    inputs,
		Outputs:   outputs,
		LockTime:  tx.LockTime,
		Fee:       tx.Fee,
		GasPrice:  tx.GasPrice,
		GasLimit:  tx.GasLimit,
	}

	return txCopy
}

// Serialize serializes the transaction to a byte slice
func (tx *Transaction) Serialize() ([]byte, error) {
	var buf bytes.Buffer

	// Version
	binary.Write(&buf, binary.LittleEndian, tx.Version)

	// Timestamp
	binary.Write(&buf, binary.LittleEndian, tx.Timestamp.Unix())

	// Number of inputs
	binary.Write(&buf, binary.LittleEndian, uint32(len(tx.Inputs)))

	// Inputs
	for _, input := range tx.Inputs {
		buf.Write(input.TxID[:])
		binary.Write(&buf, binary.LittleEndian, input.OutputIndex)
		binary.Write(&buf, binary.LittleEndian, uint32(len(input.Signature)))
		buf.Write(input.Signature)
		binary.Write(&buf, binary.LittleEndian, uint32(len(input.PublicKey)))
		buf.Write(input.PublicKey)
	}

	// Number of outputs
	binary.Write(&buf, binary.LittleEndian, uint32(len(tx.Outputs)))

	// Outputs
	for _, output := range tx.Outputs {
		binary.Write(&buf, binary.LittleEndian, output.Value)
		binary.Write(&buf, binary.LittleEndian, uint32(len(output.PublicKeyHash)))
		buf.Write(output.PublicKeyHash)
		binary.Write(&buf, binary.LittleEndian, output.ScriptType)
	}

	// Lock Time
	binary.Write(&buf, binary.LittleEndian, tx.LockTime)

	// Fee, Gas Price, Gas Limit, Gas Used
	binary.Write(&buf, binary.LittleEndian, tx.Fee)
	binary.Write(&buf, binary.LittleEndian, tx.GasPrice)
	binary.Write(&buf, binary.LittleEndian, tx.GasLimit)
	binary.Write(&buf, binary.LittleEndian, tx.GasUsed)

	// IsCoinbase
	var isCoinbaseByte byte
	if tx.IsCoinbase {
		isCoinbaseByte = 1
	}
	binary.Write(&buf, binary.LittleEndian, isCoinbaseByte)

	return buf.Bytes(), nil
}

// Deserialize deserializes a byte slice into a transaction
func DeserializeTransaction(data []byte) (*Transaction, error) {
	tx := &Transaction{}
	buf := bytes.NewReader(data)

	// Version
	binary.Read(buf, binary.LittleEndian, &tx.Version)

	// Timestamp
	var timestamp int64
	binary.Read(buf, binary.LittleEndian, &timestamp)
	tx.Timestamp = time.Unix(timestamp, 0).UTC()

	// Number of inputs
	var numInputs uint32
	binary.Read(buf, binary.LittleEndian, &numInputs)

	// Inputs
	for i := uint32(0); i < numInputs; i++ {
		var input TxInput
		
		// TxID
		buf.Read(input.TxID[:])
		
		// OutputIndex
		binary.Read(buf, binary.LittleEndian, &input.OutputIndex)
		
		// Signature
		var sigLen uint32
		binary.Read(buf, binary.LittleEndian, &sigLen)
		input.Signature = make([]byte, sigLen)
		buf.Read(input.Signature)
		
		// PublicKey
		var pubKeyLen uint32
		binary.Read(buf, binary.LittleEndian, &pubKeyLen)
		input.PublicKey = make([]byte, pubKeyLen)
		buf.Read(input.PublicKey)
		
		tx.Inputs = append(tx.Inputs, input)
	}

	// Number of outputs
	var numOutputs uint32
	binary.Read(buf, binary.LittleEndian, &numOutputs)

	// Outputs
	for i := uint32(0); i < numOutputs; i++ {
		var output TxOutput
		
		// Value
		binary.Read(buf, binary.LittleEndian, &output.Value)
		
		// PublicKeyHash
		var pubKeyHashLen uint32
		binary.Read(buf, binary.LittleEndian, &pubKeyHashLen)
		output.PublicKeyHash = make([]byte, pubKeyHashLen)
		buf.Read(output.PublicKeyHash)
		
		// ScriptType
		binary.Read(buf, binary.LittleEndian, &output.ScriptType)
		
		tx.Outputs = append(tx.Outputs, output)
	}

	// Lock Time
	binary.Read(buf, binary.LittleEndian, &tx.LockTime)

	// Fee, Gas Price, Gas Limit, Gas Used
	binary.Read(buf, binary.LittleEndian, &tx.Fee)
	binary.Read(buf, binary.LittleEndian, &tx.GasPrice)
	binary.Read(buf, binary.LittleEndian, &tx.GasLimit)
	binary.Read(buf, binary.LittleEndian, &tx.GasUsed)

	// IsCoinbase
	var isCoinbaseByte byte
	binary.Read(buf, binary.LittleEndian, &isCoinbaseByte)
	tx.IsCoinbase = isCoinbaseByte == 1

	// Calculate the hash
	tx.Hash = tx.CalculateHash()

	// Calculate the size
	tx.Size = uint64(len(data))

	return tx, nil
}

// String returns a string representation of the transaction
func (tx *Transaction) String() string {
	return fmt.Sprintf("Transaction %s: %d inputs, %d outputs, fee: %d, gas: %d/%d",
		hex.EncodeToString(tx.Hash[:8]), len(tx.Inputs), len(tx.Outputs), tx.Fee, tx.GasUsed, tx.GasLimit)
}