package mining

import (
	"fmt"
	"sync"
	"time"

	"github.com/seagercortez/qbitchain/internal/blockchain"
	"github.com/seagercortez/qbitchain/internal/crypto"
	"github.com/seagercortez/qbitchain/pkg/config"
)

// Miner represents a blockchain miner
type Miner struct {
	blockchain      *blockchain.Blockchain
	config          *config.Config
	minerAddress    string
	running         bool
	workers         int
	stopChan        chan struct{}
	submitBlockChan chan *blockchain.Block
	mtx             sync.RWMutex
	
	// Statistics
	hashRate        uint64
	miningStartTime time.Time
	blocksFound     uint64
}

// NewMiner creates a new miner
func NewMiner(bc *blockchain.Blockchain, cfg *config.Config) (*Miner, error) {
	// Check if a miner address is provided
	minerAddress := cfg.Mining.MinerAddress
	if minerAddress == "" {
		return nil, fmt.Errorf("no miner address provided")
	}
	
	// Create the miner
	miner := &Miner{
		blockchain:      bc,
		config:          cfg,
		minerAddress:    minerAddress,
		workers:         cfg.Mining.MinerThreads,
		stopChan:        make(chan struct{}),
		submitBlockChan: make(chan *blockchain.Block, 10),
	}
	
	// If the number of workers is not specified, use a sensible default
	if miner.workers <= 0 {
		miner.workers = 1 // Default to 1 worker
	}
	
	return miner, nil
}

// Start starts the mining process
func (m *Miner) Start() error {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	
	if m.running {
		return nil // Already running
	}
	
	m.running = true
	m.stopChan = make(chan struct{})
	m.miningStartTime = time.Now()
	m.blocksFound = 0
	
	// Start the block submission handler
	go m.blockSubmissionHandler()
	
	// Start the mining workers
	for i := 0; i < m.workers; i++ {
		go m.miningWorker(i)
	}
	
	return nil
}

// Stop stops the mining process
func (m *Miner) Stop() {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	
	if !m.running {
		return // Not running
	}
	
	close(m.stopChan)
	m.running = false
}

// blockSubmissionHandler handles block submissions
func (m *Miner) blockSubmissionHandler() {
	for {
		select {
		case <-m.stopChan:
			return
		case block := <-m.submitBlockChan:
			// Submit the block to the blockchain
			err := m.blockchain.AddBlock(block)
			if err != nil {
				// Block was rejected, log the error
				fmt.Printf("Block rejected: %v\n", err)
			} else {
				// Block was accepted
				m.mtx.Lock()
				m.blocksFound++
				m.mtx.Unlock()
				
				fmt.Printf("Block %d mined successfully!\n", block.Height)
			}
		}
	}
}

// miningWorker is a worker that mines blocks
func (m *Miner) miningWorker(workerID int) {
	fmt.Printf("Mining worker %d started\n", workerID)
	
	for {
		select {
		case <-m.stopChan:
			fmt.Printf("Mining worker %d stopped\n", workerID)
			return
		default:
			// Mine a block
			block, success := m.mineBlock()
			if success {
				// Submit the block
				m.submitBlockChan <- block
			}
		}
	}
}

// mineBlock mines a new block
func (m *Miner) mineBlock() (*blockchain.Block, bool) {
	// Get the latest block
	lastBlock := m.blockchain.GetLastBlock()
	
	// Create a new block
	newBlockHeight := lastBlock.Height + 1
	
	// Get pending transactions from the mempool
	maxTxs := 1000 // Limit the number of transactions in a block
	pendingTxs := m.blockchain.GetPendingTransactions(maxTxs)
	
	// Calculate total transaction fees
	var totalFees uint64
	for _, tx := range pendingTxs {
		totalFees += tx.Fee
	}
	
	// Always add a coinbase transaction first with block reward + fees
	coinbaseTx := blockchain.NewCoinbaseTransaction(m.minerAddress, blockchain.BlockReward+totalFees)
	transactions := []*blockchain.Transaction{coinbaseTx}
	
	// Add other transactions from the mempool
	transactions = append(transactions, pendingTxs...)
	
	// If node rewards are enabled, distribute rewards to participating nodes
	if m.config.NodeRewards.Enabled && m.blockchain != nil {
		nodeRewardTxs, err := m.blockchain.DistributeNodeRewards(blockchain.BlockReward, totalFees)
		if err == nil && len(nodeRewardTxs) > 0 {
			transactions = append(transactions, nodeRewardTxs...)
		}
	}
	
	// Create the new block
	difficulty := lastBlock.Header.Difficulty
	// If it's time to adjust the difficulty, do so
	if newBlockHeight%blockchain.DifficultyAdjustmentInterval == 0 {
		// In a real implementation, we would calculate the new difficulty here
		// For now, we'll just use the same difficulty
	}
	
	newBlock := blockchain.NewBlock(lastBlock.Hash, newBlockHeight, transactions, difficulty)
	
	// Mine the block (find a valid nonce)
	success := newBlock.Mine(m.stopChan)
	
	return newBlock, success
}

// IsRunning returns whether the miner is running
func (m *Miner) IsRunning() bool {
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	return m.running
}

// GetStats returns mining statistics
func (m *Miner) GetStats() (uint64, time.Duration, uint64) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()
	
	duration := time.Since(m.miningStartTime)
	return m.hashRate, duration, m.blocksFound
}

// UpdateHashRate updates the hash rate
func (m *Miner) UpdateHashRate(hashRate uint64) {
	m.mtx.Lock()
	defer m.mtx.Unlock()
	m.hashRate = hashRate
}