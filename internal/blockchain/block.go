package blockchain

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"time"
)

// Constants for the blockchain
const (
	// Initial mining difficulty target
	InitialDifficulty = 20
	// BlockReward is the reward for mining a block (in QBit / 10^18)
	BlockReward uint64 = 5_000_000_000_000_000_000 // 5 billion * 10^18 (5 quintillion)
	// Target block time in seconds
	TargetBlockTime = 60
	// Difficulty adjustment interval (in blocks)
	DifficultyAdjustmentInterval = 2016 // ~2 weeks at 1 minute block time
)

// Header represents the header of a block
type Header struct {
	Version       uint32    `json:"version"`
	PrevBlockHash [32]byte  `json:"prev_block_hash"`
	MerkleRoot    [32]byte  `json:"merkle_root"`
	Timestamp     time.Time `json:"timestamp"`
	Difficulty    uint32    `json:"difficulty"`
	Nonce         uint64    `json:"nonce"`
}

// Block represents a single block in the blockchain
type Block struct {
	Header       Header        `json:"header"`
	Transactions []*Transaction `json:"transactions"`
	Height       uint64        `json:"height"`
	Hash         [32]byte      `json:"hash"`
	Size         uint64        `json:"size"`
	TxCount      uint64        `json:"tx_count"`
}

// NewBlock creates a new block with the provided parameters
func NewBlock(prevBlockHash [32]byte, height uint64, transactions []*Transaction, difficulty uint32) *Block {
	block := &Block{
		Header: Header{
			Version:       1,
			PrevBlockHash: prevBlockHash,
			Timestamp:     time.Now().UTC(),
			Difficulty:    difficulty,
		},
		Transactions: transactions,
		Height:       height,
		TxCount:      uint64(len(transactions)),
	}

	// Calculate the Merkle root from the transactions
	block.Header.MerkleRoot = block.CalculateMerkleRoot()

	// Calculate the size of the block
	blockJSON, _ := json.Marshal(block)
	block.Size = uint64(len(blockJSON))

	return block
}

// CalculateMerkleRoot calculates the Merkle root of the block's transactions
func (b *Block) CalculateMerkleRoot() [32]byte {
	if len(b.Transactions) == 0 {
		return [32]byte{}
	}

	var hashes [][32]byte
	for _, tx := range b.Transactions {
		hashes = append(hashes, tx.Hash)
	}

	for len(hashes) > 1 {
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}

		var nextLevel [][32]byte
		for i := 0; i < len(hashes); i += 2 {
			hashData := append(hashes[i][:], hashes[i+1][:]...)
			nextHash := sha256.Sum256(hashData)
			nextLevel = append(nextLevel, nextHash)
		}

		hashes = nextLevel
	}

	return hashes[0]
}

// CalculateHash calculates the hash of the block
func (b *Block) CalculateHash() [32]byte {
	headerBytes := b.SerializeHeader()
	return sha256.Sum256(headerBytes)
}

// SerializeHeader serializes the block header to bytes
func (b *Block) SerializeHeader() []byte {
	buf := new(bytes.Buffer)

	// Version
	binary.Write(buf, binary.LittleEndian, b.Header.Version)
	
	// Previous block hash
	buf.Write(b.Header.PrevBlockHash[:])
	
	// Merkle root
	buf.Write(b.Header.MerkleRoot[:])
	
	// Timestamp
	binary.Write(buf, binary.LittleEndian, b.Header.Timestamp.Unix())
	
	// Difficulty
	binary.Write(buf, binary.LittleEndian, b.Header.Difficulty)
	
	// Nonce
	binary.Write(buf, binary.LittleEndian, b.Header.Nonce)

	return buf.Bytes()
}

// Mine mines the block by finding a hash that meets the required difficulty
func (b *Block) Mine(quit chan struct{}) bool {
	target := big.NewInt(1)
	target.Lsh(target, uint(256-b.Header.Difficulty)) // Convert difficulty to target
	
	var hashInt big.Int
	var hash [32]byte

	for b.Header.Nonce < maxUint64 {
		select {
		case <-quit:
			return false
		default:
			b.Header.Nonce++
			hash = b.CalculateHash()
			
			hashInt.SetBytes(hash[:])
			if hashInt.Cmp(target) == -1 {
				b.Hash = hash
				return true
			}
		}
	}
	
	return false
}

// maxUint64 is the maximum value for a uint64
const maxUint64 = ^uint64(0)

// ValidateBlock validates a block against the consensus rules
func (b *Block) ValidateBlock(prevBlock *Block) error {
	// Check that the previous block hash matches
	if !bytes.Equal(b.Header.PrevBlockHash[:], prevBlock.Hash[:]) {
		return fmt.Errorf("invalid previous block hash")
	}
	
	// Check that the block height is correct
	if b.Height != prevBlock.Height+1 {
		return fmt.Errorf("invalid block height")
	}
	
	// Check that the timestamp is not too far in the future
	if b.Header.Timestamp.After(time.Now().Add(2 * time.Hour)) {
		return fmt.Errorf("block timestamp is too far in the future")
	}
	
	// Check that the timestamp is not before the previous block
	if b.Header.Timestamp.Before(prevBlock.Header.Timestamp) {
		return fmt.Errorf("block timestamp is before previous block")
	}
	
	// Verify the Merkle root
	calculatedMerkleRoot := b.CalculateMerkleRoot()
	if !bytes.Equal(b.Header.MerkleRoot[:], calculatedMerkleRoot[:]) {
		return fmt.Errorf("invalid merkle root")
	}
	
	// Verify the hash meets the required difficulty
	hash := b.CalculateHash()
	
	if !bytes.Equal(hash[:], b.Hash[:]) {
		return fmt.Errorf("incorrect block hash")
	}
	
	target := big.NewInt(1)
	target.Lsh(target, uint(256-b.Header.Difficulty))
	
	var hashInt big.Int
	hashInt.SetBytes(hash[:])
	if hashInt.Cmp(target) >= 0 {
		return fmt.Errorf("block hash does not meet difficulty target")
	}
	
	// Validate all transactions in the block
	for _, tx := range b.Transactions {
		if err := tx.Validate(); err != nil {
			return fmt.Errorf("invalid transaction: %w", err)
		}
	}
	
	return nil
}

// String returns a string representation of the block
func (b *Block) String() string {
	return fmt.Sprintf("Block %d (%s) - %d transactions, %d bytes",
		b.Height, hex.EncodeToString(b.Hash[:8]), b.TxCount, b.Size)
}

// CreateGenesisBlock creates the genesis block
func CreateGenesisBlock(coinbaseAddress string) *Block {
	// Create a coinbase transaction
	coinbaseTx := NewCoinbaseTransaction(coinbaseAddress, BlockReward)
	
	block := &Block{
		Header: Header{
			Version:       1,
			PrevBlockHash: [32]byte{}, // Zero hash
			Timestamp:     time.Date(2025, 3, 4, 0, 0, 0, 0, time.UTC),
			Difficulty:    InitialDifficulty,
			Nonce:         0,
		},
		Transactions: []*Transaction{coinbaseTx},
		Height:       0,
		TxCount:      1,
	}
	
	// Calculate the Merkle root
	block.Header.MerkleRoot = block.CalculateMerkleRoot()
	
	// Set a pre-calculated hash for the genesis block, or we can mine it
	// This would typically be a fixed value for a specific network
	// For now, we'll just calculate it
	block.Hash = block.CalculateHash()
	
	return block
}