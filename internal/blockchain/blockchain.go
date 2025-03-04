package blockchain

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/seagercortez/qbitchain/pkg/config"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/opt"
)

const (
	// Database bucket names
	BlocksBucket        = "blocks"
	TransactionsBucket  = "transactions"
	UTXOBucket          = "utxo"
	MetadataBucket      = "metadata"
	NodeRewardsBucket   = "node_rewards"
	
	// Special key names
	LastBlockHashKey    = "LastBlockHash"
	ChainStateKey       = "ChainState"
	
	// The max number of blocks to keep in memory
	MaxBlocksInMemory   = 1000
	
	// Node rewards
	NodeRewardInterval  = 720 // Reward distribution interval (blocks) - approx. daily at 1 min blocks
)

// UTXO represents an unspent transaction output
type UTXO struct {
	TxID        [32]byte
	OutputIndex uint32
	Output      TxOutput
}

// Blockchain represents the blockchain
type Blockchain struct {
	db           *leveldb.DB
	config       *config.Config
	lastBlock    *Block
	mempool      *TxPool
	chain        []*Block
	mtx          sync.RWMutex
	
	// Channel to notify of new blocks
	newBlockCh   chan *Block
	
	// Main database batch operations
	batch        *leveldb.Batch
	
	// Tracks forks, reorganizations, etc.
	forkDetector *ForkDetector
	
	// Node rewards tracking
	nodeRewards  *NodeRewardTracker
	
	// Light node flag
	isLightNode  bool
}

// ChainState holds metadata about the blockchain state
type ChainState struct {
	Height             uint64    `json:"height"`
	LastBlockHash      [32]byte  `json:"last_block_hash"`
	TotalDifficulty    *big.Int  `json:"total_difficulty"`
	TotalTransactions  uint64    `json:"total_transactions"`
	LastUpdateTime     time.Time `json:"last_update_time"`
	CurrentDifficulty  uint32    `json:"current_difficulty"`
}

// TxPool represents the transaction memory pool
type TxPool struct {
	transactions map[[32]byte]*Transaction
	mtx          sync.RWMutex
}

// NodeRewardTracker tracks node rewards
type NodeRewardTracker struct {
	// Map of node ID/address to accumulated rewards
	rewards map[string]uint64
	// Processor IDs/addresses that processed transactions in the current block
	processors map[string]bool
	// Participating full node IDs/addresses
	fullNodes  map[string]bool
	// Participating light node IDs/addresses
	lightNodes map[string]bool
	mtx        sync.RWMutex
}

// NewNodeRewardTracker creates a new node reward tracker
func NewNodeRewardTracker() *NodeRewardTracker {
	return &NodeRewardTracker{
		rewards:    make(map[string]uint64),
		processors: make(map[string]bool),
		fullNodes:  make(map[string]bool),
		lightNodes: make(map[string]bool),
		mtx:        sync.RWMutex{},
	}
}

// ForkDetector tracks potential forks in the blockchain
type ForkDetector struct {
	// Map of parent hash -> slice of blocks with that parent
	forks      map[string][]*Block
	mainChain  [][32]byte
	mtx        sync.RWMutex
}

// NewBlockchain creates a new blockchain instance
func NewBlockchain(cfg *config.Config, lightNode bool) (*Blockchain, error) {
	// For light nodes, we use a memory database instead of a persistent one
	var db *leveldb.DB
	var err error
	
	if lightNode {
		// For light nodes, use an in-memory database with limited storage
		dbOpts := &opt.Options{
			WriteBuffer: 8 * opt.MiB,
			// Use a bloom filter to speed up lookups
			Filter: opt.NewBloomFilter(10),
		}
		
		// Create a temporary directory for the database
		tmpDir, err := os.MkdirTemp("", "qbitchain-lightnode")
		if err != nil {
			return nil, fmt.Errorf("failed to create temporary directory: %w", err)
		}
		
		// Clean up the temporary directory when the program exits
		go func() {
			<-make(chan struct{}) // This will never be closed, so cleanup happens on process exit
			os.RemoveAll(tmpDir)
		}()
		
		db, err = leveldb.OpenFile(tmpDir, dbOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to open light node database: %w", err)
		}
	} else {
		// For full nodes, use a persistent database
		dbOpts := &opt.Options{
			WriteBuffer: 32 * opt.MiB, // Optimize for write performance
		}
		
		dbPath := fmt.Sprintf("%s/%s/chaindata", cfg.DataDir, cfg.NetworkType)
		db, err = leveldb.OpenFile(dbPath, dbOpts)
		if err != nil {
			return nil, fmt.Errorf("failed to open blockchain database: %w", err)
		}
	}
	
	// Create a new blockchain instance
	bc := &Blockchain{
		db:         db,
		config:     cfg,
		mempool:    &TxPool{transactions: make(map[[32]byte]*Transaction)},
		chain:      make([]*Block, 0, MaxBlocksInMemory),
		newBlockCh: make(chan *Block, 10),
		batch:      new(leveldb.Batch),
		forkDetector: &ForkDetector{
			forks: make(map[string][]*Block),
			mainChain: make([][32]byte, 0),
		},
		nodeRewards: NewNodeRewardTracker(),
		isLightNode: lightNode,
	}
	
	// Check if the blockchain is empty
	exists, err := bc.checkIfBlockchainExists()
	if err != nil {
		return nil, err
	}
	
	// If the blockchain is empty, create the genesis block
	if !exists {
		// Use a default miner address if none is provided
		minerAddr := cfg.Mining.MinerAddress
		if minerAddr == "" {
			minerAddr = "QBC1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqe55vvx9"
		}
		
		genesisBlock := CreateGenesisBlock(minerAddr)
		
		// Add the genesis block to the database
		if err := bc.AddBlock(genesisBlock); err != nil {
			return nil, fmt.Errorf("failed to add genesis block: %w", err)
		}
		
		// Set the genesis block as the last block
		bc.lastBlock = genesisBlock
		
		// Update the chain state
		state := &ChainState{
			Height:            0,
			LastBlockHash:     genesisBlock.Hash,
			TotalDifficulty:   big.NewInt(int64(genesisBlock.Header.Difficulty)),
			TotalTransactions: 1, // The coinbase transaction
			LastUpdateTime:    time.Now().UTC(),
			CurrentDifficulty: genesisBlock.Header.Difficulty,
		}
		
		// Save the chain state
		if err := bc.saveChainState(state); err != nil {
			return nil, fmt.Errorf("failed to save chain state: %w", err)
		}
	} else {
		// Load the existing chain state
		state, err := bc.loadChainState()
		if err != nil {
			return nil, fmt.Errorf("failed to load chain state: %w", err)
		}
		
		// Load the last block
		lastBlock, err := bc.GetBlockByHash(state.LastBlockHash)
		if err != nil {
			return nil, fmt.Errorf("failed to load last block: %w", err)
		}
		
		bc.lastBlock = lastBlock
		
		// Load the most recent blocks into memory
		err = bc.loadRecentBlocks()
		if err != nil {
			return nil, fmt.Errorf("failed to load recent blocks: %w", err)
		}
	}
	
	return bc, nil
}

// checkIfBlockchainExists checks if there is an existing blockchain in the database
func (bc *Blockchain) checkIfBlockchainExists() (bool, error) {
	// Check if the LastBlockHashKey exists in the database
	data, err := bc.db.Get([]byte(LastBlockHashKey), nil)
	if err != nil {
		if err == leveldb.ErrNotFound {
			return false, nil
		}
		return false, fmt.Errorf("failed to check if blockchain exists: %w", err)
	}
	
	return len(data) > 0, nil
}

// loadRecentBlocks loads the most recent blocks into memory
func (bc *Blockchain) loadRecentBlocks() error {
	bc.mtx.Lock()
	defer bc.mtx.Unlock()
	
	// Start from the last block and work backwards
	currentBlock := bc.lastBlock
	bc.chain = append(bc.chain, currentBlock)
	
	// Load up to MaxBlocksInMemory - 1 more blocks (we already added the last block)
	for i := 0; i < MaxBlocksInMemory-1; i++ {
		// Stop if we reach the genesis block
		if currentBlock.Height == 0 {
			break
		}
		
		// Get the previous block
		prevBlock, err := bc.GetBlockByHash(currentBlock.Header.PrevBlockHash)
		if err != nil {
			return fmt.Errorf("failed to load previous block: %w", err)
		}
		
		// Add the block to the in-memory chain
		bc.chain = append([]*Block{prevBlock}, bc.chain...)
		
		// Move to the previous block
		currentBlock = prevBlock
	}
	
	return nil
}

// saveChainState saves the current chain state to the database
func (bc *Blockchain) saveChainState(state *ChainState) error {
	// Serialize the chain state
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to serialize chain state: %w", err)
	}
	
	// Save the chain state to the database
	err = bc.db.Put([]byte(ChainStateKey), data, nil)
	if err != nil {
		return fmt.Errorf("failed to save chain state: %w", err)
	}
	
	// Also save the last block hash separately for quick access
	err = bc.db.Put([]byte(LastBlockHashKey), state.LastBlockHash[:], nil)
	if err != nil {
		return fmt.Errorf("failed to save last block hash: %w", err)
	}
	
	return nil
}

// loadChainState loads the chain state from the database
func (bc *Blockchain) loadChainState() (*ChainState, error) {
	// Get the chain state from the database
	data, err := bc.db.Get([]byte(ChainStateKey), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load chain state: %w", err)
	}
	
	// Deserialize the chain state
	var state ChainState
	err = json.Unmarshal(data, &state)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize chain state: %w", err)
	}
	
	return &state, nil
}

// AddBlock adds a new block to the blockchain
func (bc *Blockchain) AddBlock(block *Block) error {
	bc.mtx.Lock()
	defer bc.mtx.Unlock()
	
	// Check if this is the genesis block
	isGenesis := block.Height == 0
	
	// If this is not the genesis block, validate it
	if !isGenesis {
		prevBlock, err := bc.GetBlockByHash(block.Header.PrevBlockHash)
		if err != nil {
			return fmt.Errorf("failed to get previous block: %w", err)
		}
		
		// Validate the block
		err = block.ValidateBlock(prevBlock)
		if err != nil {
			return fmt.Errorf("invalid block: %w", err)
		}
	}
	
	// Serialize the block
	blockData, err := json.Marshal(block)
	if err != nil {
		return fmt.Errorf("failed to serialize block: %w", err)
	}
	
	// Create a batch operation
	batch := new(leveldb.Batch)
	
	// Store the block
	blockKey := append([]byte(BlocksBucket), block.Hash[:]...)
	batch.Put(blockKey, blockData)
	
	// Store block height -> hash mapping
	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, block.Height)
	heightKey := append([]byte("height-"), heightBytes...)
	batch.Put(heightKey, block.Hash[:])
	
	// Store each transaction
	for _, tx := range block.Transactions {
		// Store transaction
		txKey := append([]byte(TransactionsBucket), tx.Hash[:]...)
		txData, err := tx.Serialize()
		if err != nil {
			return fmt.Errorf("failed to serialize transaction: %w", err)
		}
		batch.Put(txKey, txData)
		
		// Update UTXO set
		bc.updateUTXOSet(tx, batch)
	}
	
	// Update the chain state
	state, err := bc.loadChainState()
	if err != nil && !isGenesis {
		return fmt.Errorf("failed to load chain state: %w", err)
	}
	
	// If this is the genesis block, create a new state
	if isGenesis {
		state = &ChainState{
			Height:            0,
			LastBlockHash:     block.Hash,
			TotalDifficulty:   big.NewInt(int64(block.Header.Difficulty)),
			TotalTransactions: uint64(len(block.Transactions)),
			LastUpdateTime:    time.Now().UTC(),
			CurrentDifficulty: block.Header.Difficulty,
		}
	} else {
		// Update the chain state
		state.Height = block.Height
		state.LastBlockHash = block.Hash
		state.TotalDifficulty.Add(state.TotalDifficulty, big.NewInt(int64(block.Header.Difficulty)))
		state.TotalTransactions += uint64(len(block.Transactions))
		state.LastUpdateTime = time.Now().UTC()
		
		// Update the difficulty if needed
		if block.Height%DifficultyAdjustmentInterval == 0 {
			newDifficulty := bc.calculateNextDifficulty()
			state.CurrentDifficulty = newDifficulty
		}
	}
	
	// Save the updated chain state
	stateData, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("failed to serialize chain state: %w", err)
	}
	batch.Put([]byte(ChainStateKey), stateData)
	batch.Put([]byte(LastBlockHashKey), block.Hash[:])
	
	// Commit the batch operation
	err = bc.db.Write(batch, nil)
	if err != nil {
		return fmt.Errorf("failed to write batch: %w", err)
	}
	
	// Update the in-memory state
	bc.lastBlock = block
	
	// Add the block to the in-memory chain
	bc.chain = append(bc.chain, block)
	if len(bc.chain) > MaxBlocksInMemory {
		// Remove the oldest block from memory
		bc.chain = bc.chain[1:]
	}
	
	// Notify listeners of the new block
	select {
	case bc.newBlockCh <- block:
		// Successfully sent
	default:
		// Channel buffer is full, discard notification
	}
	
	return nil
}

// updateUTXOSet updates the UTXO set for a transaction
func (bc *Blockchain) updateUTXOSet(tx *Transaction, batch *leveldb.Batch) {
	if tx.IsCoinbase {
		// Coinbase transaction creates new UTXOs but doesn't spend any
		for i, output := range tx.Outputs {
			utxoKey := append([]byte(UTXOBucket), tx.Hash[:]...)
			utxoKey = append(utxoKey, byte(i))
			
			// Serialize the UTXO
			utxo := UTXO{
				TxID:        tx.Hash,
				OutputIndex: uint32(i),
				Output:      output,
			}
			utxoData, _ := json.Marshal(utxo)
			
			// Add to the batch
			batch.Put(utxoKey, utxoData)
		}
	} else {
		// Regular transaction - remove spent UTXOs and add new ones
		
		// Remove spent UTXOs
		for _, input := range tx.Inputs {
			utxoKey := append([]byte(UTXOBucket), input.TxID[:]...)
			utxoKey = append(utxoKey, byte(input.OutputIndex))
			
			// Delete from the batch
			batch.Delete(utxoKey)
		}
		
		// Add new UTXOs
		for i, output := range tx.Outputs {
			utxoKey := append([]byte(UTXOBucket), tx.Hash[:]...)
			utxoKey = append(utxoKey, byte(i))
			
			// Serialize the UTXO
			utxo := UTXO{
				TxID:        tx.Hash,
				OutputIndex: uint32(i),
				Output:      output,
			}
			utxoData, _ := json.Marshal(utxo)
			
			// Add to the batch
			batch.Put(utxoKey, utxoData)
		}
	}
}

// calculateNextDifficulty calculates the next difficulty based on the time it took to mine the last 2016 blocks
func (bc *Blockchain) calculateNextDifficulty() uint32 {
	// Get the current difficulty
	state, err := bc.loadChainState()
	if err != nil {
		// If there's an error, keep the current difficulty
		return bc.lastBlock.Header.Difficulty
	}
	
	// If we don't have enough blocks yet, keep the initial difficulty
	if bc.lastBlock.Height < DifficultyAdjustmentInterval {
		return InitialDifficulty
	}
	
	// Get the block at the beginning of the adjustment period
	adjustmentBlockHeight := bc.lastBlock.Height - DifficultyAdjustmentInterval
	adjustmentBlock, err := bc.GetBlockByHeight(adjustmentBlockHeight)
	if err != nil {
		// If there's an error, keep the current difficulty
		return bc.lastBlock.Header.Difficulty
	}
	
	// Calculate how long it took to mine the last 2016 blocks
	expectedTime := DifficultyAdjustmentInterval * TargetBlockTime
	actualTime := bc.lastBlock.Header.Timestamp.Sub(adjustmentBlock.Header.Timestamp).Seconds()
	
	// Adjust difficulty to target a block time of 60 seconds
	ratio := actualTime / float64(expectedTime)
	
	// Limit the adjustment to a factor of 4
	if ratio > 4.0 {
		ratio = 4.0
	} else if ratio < 0.25 {
		ratio = 0.25
	}
	
	// Calculate new difficulty
	newDifficulty := float64(state.CurrentDifficulty) / ratio
	
	// Ensure the difficulty is at least the initial difficulty
	if newDifficulty < InitialDifficulty {
		newDifficulty = InitialDifficulty
	}
	
	return uint32(newDifficulty)
}

// GetBlockByHash retrieves a block by its hash
func (bc *Blockchain) GetBlockByHash(hash [32]byte) (*Block, error) {
	// Check if the block is in memory first
	bc.mtx.RLock()
	for _, block := range bc.chain {
		if bytes.Equal(block.Hash[:], hash[:]) {
			bc.mtx.RUnlock()
			return block, nil
		}
	}
	bc.mtx.RUnlock()
	
	// If not in memory, fetch from the database
	blockKey := append([]byte(BlocksBucket), hash[:]...)
	data, err := bc.db.Get(blockKey, nil)
	if err != nil {
		return nil, fmt.Errorf("block not found: %s", hex.EncodeToString(hash[:]))
	}
	
	// Deserialize the block
	var block Block
	err = json.Unmarshal(data, &block)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize block: %w", err)
	}
	
	return &block, nil
}

// GetBlockByHeight retrieves a block by its height
func (bc *Blockchain) GetBlockByHeight(height uint64) (*Block, error) {
	// Check if the block is in memory first
	bc.mtx.RLock()
	for _, block := range bc.chain {
		if block.Height == height {
			bc.mtx.RUnlock()
			return block, nil
		}
	}
	bc.mtx.RUnlock()
	
	// If not in memory, fetch from the database
	heightBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(heightBytes, height)
	heightKey := append([]byte("height-"), heightBytes...)
	
	hashData, err := bc.db.Get(heightKey, nil)
	if err != nil {
		return nil, fmt.Errorf("block height not found: %d", height)
	}
	
	var hash [32]byte
	copy(hash[:], hashData)
	
	return bc.GetBlockByHash(hash)
}

// GetLastBlock returns the last block in the blockchain
func (bc *Blockchain) GetLastBlock() *Block {
	bc.mtx.RLock()
	defer bc.mtx.RUnlock()
	return bc.lastBlock
}

// GetNewBlockChannel returns the channel for new block notifications
func (bc *Blockchain) GetNewBlockChannel() <-chan *Block {
	return bc.newBlockCh
}

// Close closes the blockchain database
func (bc *Blockchain) Close() error {
	return bc.db.Close()
}

// AddTransaction adds a transaction to the mempool
func (bc *Blockchain) AddTransaction(tx *Transaction) error {
	// Validate the transaction
	if err := tx.Validate(); err != nil {
		return fmt.Errorf("invalid transaction: %w", err)
	}
	
	// Add to the mempool
	bc.mempool.mtx.Lock()
	bc.mempool.transactions[tx.Hash] = tx
	bc.mempool.mtx.Unlock()
	
	// If node rewards are enabled and this is not a coinbase transaction,
	// record the processor in the node reward tracker
	if bc.config.NodeRewards.Enabled && !tx.IsCoinbase {
		addrStr := bc.config.NodeRewards.RewardAddress
		if addrStr != "" {
			bc.nodeRewards.mtx.Lock()
			bc.nodeRewards.processors[addrStr] = true
			bc.nodeRewards.mtx.Unlock()
		}
	}
	
	return nil
}

// GetTransaction retrieves a transaction by its hash
func (bc *Blockchain) GetTransaction(hash [32]byte) (*Transaction, error) {
	// Check if the transaction is in the mempool
	bc.mempool.mtx.RLock()
	if tx, ok := bc.mempool.transactions[hash]; ok {
		bc.mempool.mtx.RUnlock()
		return tx, nil
	}
	bc.mempool.mtx.RUnlock()
	
	// If not in the mempool, check the database
	txKey := append([]byte(TransactionsBucket), hash[:]...)
	data, err := bc.db.Get(txKey, nil)
	if err != nil {
		return nil, fmt.Errorf("transaction not found: %s", hex.EncodeToString(hash[:]))
	}
	
	// Deserialize the transaction
	tx, err := DeserializeTransaction(data)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize transaction: %w", err)
	}
	
	return tx, nil
}

// GetPendingTransactions returns a list of pending transactions from the mempool
func (bc *Blockchain) GetPendingTransactions(maxCount int) []*Transaction {
	bc.mempool.mtx.RLock()
	defer bc.mempool.mtx.RUnlock()
	
	transactions := make([]*Transaction, 0, len(bc.mempool.transactions))
	for _, tx := range bc.mempool.transactions {
		transactions = append(transactions, tx)
		if maxCount > 0 && len(transactions) >= maxCount {
			break
		}
	}
	
	return transactions
}

// RegisterFullNode registers a full node for rewards
func (bc *Blockchain) RegisterFullNode(address string) {
	if !bc.config.NodeRewards.Enabled || address == "" {
		return
	}
	
	bc.nodeRewards.mtx.Lock()
	defer bc.nodeRewards.mtx.Unlock()
	
	bc.nodeRewards.fullNodes[address] = true
}

// RegisterLightNode registers a light node for rewards
func (bc *Blockchain) RegisterLightNode(address string) {
	if !bc.config.NodeRewards.Enabled || address == "" {
		return
	}
	
	bc.nodeRewards.mtx.Lock()
	defer bc.nodeRewards.mtx.Unlock()
	
	bc.nodeRewards.lightNodes[address] = true
}

// DistributeNodeRewards distributes rewards to participating nodes
func (bc *Blockchain) DistributeNodeRewards(blockReward uint64, txFees uint64) ([]*Transaction, error) {
	if !bc.config.NodeRewards.Enabled {
		return nil, nil
	}
	
	bc.nodeRewards.mtx.Lock()
	defer bc.nodeRewards.mtx.Unlock()
	
	// If no nodes are participating, skip reward distribution
	if len(bc.nodeRewards.fullNodes) == 0 && len(bc.nodeRewards.lightNodes) == 0 && len(bc.nodeRewards.processors) == 0 {
		return nil, nil
	}
	
	rewardTransactions := make([]*Transaction, 0)
	
	// Calculate rewards
	fullNodeReward := uint64(float64(blockReward) * bc.config.NodeRewards.FullNodePercent / 100.0)
	lightNodeReward := uint64(float64(blockReward) * bc.config.NodeRewards.LightNodePercent / 100.0)
	txProcessorReward := uint64(float64(txFees) * bc.config.NodeRewards.TxProcessPercent / 100.0)
	
	// Distribute full node rewards
	if len(bc.nodeRewards.fullNodes) > 0 && fullNodeReward > 0 {
		perNodeReward := fullNodeReward / uint64(len(bc.nodeRewards.fullNodes))
		if perNodeReward > 0 {
			for address := range bc.nodeRewards.fullNodes {
				tx := bc.createRewardTransaction(address, perNodeReward, "full-node-reward")
				if tx != nil {
					rewardTransactions = append(rewardTransactions, tx)
				}
			}
		}
	}
	
	// Distribute light node rewards
	if len(bc.nodeRewards.lightNodes) > 0 && lightNodeReward > 0 {
		perNodeReward := lightNodeReward / uint64(len(bc.nodeRewards.lightNodes))
		if perNodeReward > 0 {
			for address := range bc.nodeRewards.lightNodes {
				tx := bc.createRewardTransaction(address, perNodeReward, "light-node-reward")
				if tx != nil {
					rewardTransactions = append(rewardTransactions, tx)
				}
			}
		}
	}
	
	// Distribute transaction processor rewards
	if len(bc.nodeRewards.processors) > 0 && txProcessorReward > 0 {
		perNodeReward := txProcessorReward / uint64(len(bc.nodeRewards.processors))
		if perNodeReward > 0 {
			for address := range bc.nodeRewards.processors {
				tx := bc.createRewardTransaction(address, perNodeReward, "tx-processor-reward")
				if tx != nil {
					rewardTransactions = append(rewardTransactions, tx)
				}
			}
		}
	}
	
	// Clear the processor list for the next block
	bc.nodeRewards.processors = make(map[string]bool)
	
	return rewardTransactions, nil
}

// createRewardTransaction creates a transaction to reward a node
func (bc *Blockchain) createRewardTransaction(toAddress string, amount uint64, memo string) *Transaction {
	if amount == 0 {
		return nil
	}
	
	// Create a dummy input for the reward transaction
	txin := TxInput{
		TxID:        [32]byte{},
		OutputIndex: 0xFFFFFFFE, // Special value for node reward transactions
		Signature:   []byte{memo},
		PublicKey:   []byte{},
	}
	
	// Create the output with the reward
	pubKeyHash, err := crypto.AddressToPublicKeyHash(toAddress)
	if err != nil {
		return nil
	}
	
	txout := TxOutput{
		Value:         amount,
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
		Fee:        0,
		IsCoinbase: false, // Not a coinbase but a special node reward transaction
	}
	
	// Calculate the hash of the transaction
	tx.Hash = tx.CalculateHash()
	
	return tx
}