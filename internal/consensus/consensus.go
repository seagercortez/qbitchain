package consensus

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/seagercortez/qbitchain/internal/blockchain"
)

// Constants for consensus
const (
	// Maximum time difference allowed between blocks
	MaxTimeDrift = 2 * time.Hour
	
	// Minimum number of confirmations required for a transaction to be considered settled
	MinConfirmations = 6
	
	// Maximum number of blocks to reorganize
	MaxReorgDepth = 100
)

// Validator defines the interface for a consensus validator
type Validator interface {
	// Validate validates a block against the consensus rules
	ValidateBlock(block *blockchain.Block, prevBlock *blockchain.Block) error
	
	// ValidateChain validates a chain of blocks
	ValidateChain(blocks []*blockchain.Block) error
}

// ProofOfWorkValidator implements the Validator interface for Proof of Work consensus
type ProofOfWorkValidator struct {
	mtx sync.RWMutex
}

// NewProofOfWorkValidator creates a new Proof of Work validator
func NewProofOfWorkValidator() *ProofOfWorkValidator {
	return &ProofOfWorkValidator{}
}

// ValidateBlock validates a block against the Proof of Work consensus rules
func (v *ProofOfWorkValidator) ValidateBlock(block *blockchain.Block, prevBlock *blockchain.Block) error {
	v.mtx.RLock()
	defer v.mtx.RUnlock()
	
	// Check block header
	if err := v.validateBlockHeader(block, prevBlock); err != nil {
		return err
	}
	
	// Check transactions
	if err := v.validateTransactions(block); err != nil {
		return err
	}
	
	return nil
}

// validateBlockHeader validates the block header against the consensus rules
func (v *ProofOfWorkValidator) validateBlockHeader(block *blockchain.Block, prevBlock *blockchain.Block) error {
	// Check that the previous block hash is correct
	if !bytes.Equal(block.Header.PrevBlockHash[:], prevBlock.Hash[:]) {
		return errors.New("previous block hash does not match")
	}
	
	// Check that the block height is correct
	if block.Height != prevBlock.Height+1 {
		return errors.New("invalid block height")
	}
	
	// Check that the timestamp is not too far in the future
	if block.Header.Timestamp.After(time.Now().Add(MaxTimeDrift)) {
		return errors.New("block timestamp is too far in the future")
	}
	
	// Check that the timestamp is not before the previous block
	if block.Header.Timestamp.Before(prevBlock.Header.Timestamp) {
		return errors.New("block timestamp is before previous block")
	}
	
	// Verify that the hash meets the required difficulty
	target := big.NewInt(1)
	target.Lsh(target, uint(256-block.Header.Difficulty))
	
	var hashInt big.Int
	hashInt.SetBytes(block.Hash[:])
	if hashInt.Cmp(target) > 0 {
		return errors.New("block hash does not meet required difficulty")
	}
	
	// Check that the merkle root is valid
	calculatedMerkleRoot := block.CalculateMerkleRoot()
	if !bytes.Equal(block.Header.MerkleRoot[:], calculatedMerkleRoot[:]) {
		return errors.New("invalid merkle root")
	}
	
	return nil
}

// validateTransactions validates the transactions in a block
func (v *ProofOfWorkValidator) validateTransactions(block *blockchain.Block) error {
	// Check that the block has at least one transaction (the coinbase)
	if len(block.Transactions) == 0 {
		return errors.New("block has no transactions")
	}
	
	// Check that the first transaction is a coinbase transaction
	if !block.Transactions[0].IsCoinbase {
		return errors.New("first transaction is not a coinbase transaction")
	}
	
	// Check that there is only one coinbase transaction
	for i := 1; i < len(block.Transactions); i++ {
		if block.Transactions[i].IsCoinbase {
			return errors.New("multiple coinbase transactions")
		}
	}
	
	// Check that the coinbase reward is correct
	if block.Transactions[0].Outputs[0].Value > blockchain.BlockReward {
		return errors.New("coinbase reward exceeds block reward")
	}
	
	// Check that each transaction is valid
	for _, tx := range block.Transactions {
		if err := tx.Validate(); err != nil {
			return fmt.Errorf("invalid transaction: %w", err)
		}
	}
	
	// Check that the transaction count matches
	if block.TxCount != uint64(len(block.Transactions)) {
		return errors.New("transaction count mismatch")
	}
	
	return nil
}

// ValidateChain validates a chain of blocks
func (v *ProofOfWorkValidator) ValidateChain(blocks []*blockchain.Block) error {
	v.mtx.RLock()
	defer v.mtx.RUnlock()
	
	// Check that the chain is not empty
	if len(blocks) == 0 {
		return errors.New("empty chain")
	}
	
	// First block is validated against itself (should be the genesis block)
	if err := v.ValidateBlock(blocks[0], blocks[0]); err != nil {
		return fmt.Errorf("invalid genesis block: %w", err)
	}
	
	// Validate each subsequent block
	for i := 1; i < len(blocks); i++ {
		if err := v.ValidateBlock(blocks[i], blocks[i-1]); err != nil {
			return fmt.Errorf("invalid block at height %d: %w", blocks[i].Height, err)
		}
	}
	
	return nil
}

// ForkChoice represents a fork choice rule implementation
type ForkChoice interface {
	// ChooseBestChain chooses the best chain from multiple competing chains
	ChooseBestChain(chains [][]*blockchain.Block) []*blockchain.Block
}

// LongestChainRule implements the longest chain fork choice rule
type LongestChainRule struct{}

// NewLongestChainRule creates a new longest chain rule
func NewLongestChainRule() *LongestChainRule {
	return &LongestChainRule{}
}

// ChooseBestChain chooses the best chain based on the longest chain rule
func (r *LongestChainRule) ChooseBestChain(chains [][]*blockchain.Block) []*blockchain.Block {
	if len(chains) == 0 {
		return nil
	}
	
	// Sort chains by length (longest first)
	sort.Slice(chains, func(i, j int) bool {
		return len(chains[i]) > len(chains[j])
	})
	
	// If the longest chain is more than one ahead, choose it
	if len(chains) > 1 && len(chains[0]) > len(chains[1])+1 {
		return chains[0]
	}
	
	// If two chains are tied or very close, choose the one with the most work
	totalDifficulty := make([]big.Int, len(chains))
	for i, chain := range chains {
		for _, block := range chain {
			totalDifficulty[i].Add(&totalDifficulty[i], big.NewInt(int64(block.Header.Difficulty)))
		}
	}
	
	// Find the chain with the highest total difficulty
	bestChainIndex := 0
	for i := 1; i < len(totalDifficulty); i++ {
		if totalDifficulty[i].Cmp(&totalDifficulty[bestChainIndex]) > 0 {
			bestChainIndex = i
		}
	}
	
	return chains[bestChainIndex]
}

// IsBlockOrphan checks if a block is an orphan (has no known parent)
func IsBlockOrphan(block *blockchain.Block, chain []*blockchain.Block) bool {
	// If the chain is empty, the block cannot be an orphan
	if len(chain) == 0 {
		return false
	}
	
	// Check if the block's parent is in the chain
	for _, b := range chain {
		if bytes.Equal(block.Header.PrevBlockHash[:], b.Hash[:]) {
			return false
		}
	}
	
	// If we didn't find the parent, it's an orphan
	return true
}

// CalculateNextDifficulty calculates the next difficulty based on the time it took to mine the last blocks
func CalculateNextDifficulty(blocks []*blockchain.Block, targetTime time.Duration) uint32 {
	if len(blocks) < 2 {
		return blockchain.InitialDifficulty
	}
	
	// Calculate the time it took to mine the blocks
	firstBlock := blocks[0]
	lastBlock := blocks[len(blocks)-1]
	actualTime := lastBlock.Header.Timestamp.Sub(firstBlock.Header.Timestamp)
	
	// Expected time is the target time per block times the number of blocks
	expectedTime := targetTime * time.Duration(len(blocks)-1)
	
	// Adjust the difficulty based on the ratio of actual to expected time
	ratio := float64(actualTime) / float64(expectedTime)
	
	// Limit the adjustment to a factor of 4
	if ratio > 4.0 {
		ratio = 4.0
	} else if ratio < 0.25 {
		ratio = 0.25
	}
	
	// Calculate the new difficulty
	currentDifficulty := lastBlock.Header.Difficulty
	newDifficulty := float64(currentDifficulty) / ratio
	
	// Make sure the difficulty doesn't go below the initial difficulty
	if newDifficulty < float64(blockchain.InitialDifficulty) {
		newDifficulty = float64(blockchain.InitialDifficulty)
	}
	
	return uint32(newDifficulty)
}