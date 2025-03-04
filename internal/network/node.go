package network

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/multiformats/go-multiaddr"
	
	"github.com/seagercortez/qbitchain/internal/blockchain"
	"github.com/seagercortez/qbitchain/internal/mining"
	"github.com/seagercortez/qbitchain/internal/wallet"
	"github.com/seagercortez/qbitchain/pkg/config"
)

const (
	// Protocol IDs
	BlockProtocolID      = "/qbitchain/blocks/1.0.0"
	TxProtocolID         = "/qbitchain/tx/1.0.0"
	PeerDiscoveryID      = "/qbitchain/discovery/1.0.0"
	
	// Time constants
	ConnectionTimeout    = 10 * time.Second
	HeartbeatInterval    = 30 * time.Second
	DiscoveryInterval    = 5 * time.Minute
	
	// Network constants
	MaxPeers             = 50
)

// NodeConfig holds the configuration for a node
type NodeConfig struct {
	IsFullNode       bool
	IsLightNode      bool
	IsMiner          bool
	NetworkType      string // "testnet" or "livenet"
	EnableNodeReward bool   // Enable rewards for running this node
}

// Node represents a QBitChain node
type Node struct {
	config        *config.Config
	nodeConfig    NodeConfig
	blockchain    *blockchain.Blockchain
	walletManager *wallet.Manager
	miner         *mining.Miner
	
	// libp2p host
	host          host.Host
	dht           *dht.IpfsDHT
	
	// Peer management
	peers         map[peer.ID]*Peer
	peersMutex    sync.RWMutex
	maxPeers      int
	
	// Channels for communication
	newBlockCh    chan *blockchain.Block
	newTxCh       chan *blockchain.Transaction
	
	// Context for shutdown
	ctx           context.Context
	cancel        context.CancelFunc
	
	// Stats
	stats         *NodeStats
}

// NodeStats keeps track of node statistics
type NodeStats struct {
	StartTime          time.Time
	BlocksReceived     uint64
	BlocksTransmitted  uint64
	TxReceived         uint64
	TxTransmitted      uint64
	PeersConnected     uint64
	BytesReceived      uint64
	BytesTransmitted   uint64
	mtx                sync.RWMutex
}

// Peer represents a connected peer
type Peer struct {
	ID                peer.ID
	Address           multiaddr.Multiaddr
	ConnectedAt       time.Time
	LastSeen          time.Time
	BlocksReceived    uint64
	BlocksTransmitted uint64
	TxReceived        uint64
	TxTransmitted     uint64
	IsFullNode        bool
	Version           string
	mtx               sync.RWMutex
}

// NewNode creates a new QBitChain node
func NewNode(cfg *config.Config, nodeCfg NodeConfig, bc *blockchain.Blockchain, wm *wallet.Manager) (*Node, error) {
	// Create a context for the node
	ctx, cancel := context.WithCancel(context.Background())
	
	// Create stats
	stats := &NodeStats{
		StartTime: time.Now(),
	}
	
	// Create the node
	node := &Node{
		config:        cfg,
		nodeConfig:    nodeCfg,
		blockchain:    bc,
		walletManager: wm,
		peers:         make(map[peer.ID]*Peer),
		maxPeers:      cfg.Network.MaxPeers,
		newBlockCh:    make(chan *blockchain.Block, 100),
		newTxCh:       make(chan *blockchain.Transaction, 1000),
		ctx:           ctx,
		cancel:        cancel,
		stats:         stats,
	}
	
	// If this is a mining node, create a miner
	if nodeCfg.IsMiner {
		miner, err := mining.NewMiner(bc, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create miner: %w", err)
		}
		node.miner = miner
	}
	
	return node, nil
}

// Start starts the node
func (n *Node) Start() error {
	// Parse the listen address
	listenAddr, err := multiaddr.NewMultiaddr(n.config.Network.ListenAddress)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	
	// Create the libp2p host
	host, err := libp2p.New(
		libp2p.ListenAddrs(listenAddr),
		libp2p.NATPortMap(),
	)
	if err != nil {
		return fmt.Errorf("failed to create libp2p host: %w", err)
	}
	n.host = host
	
	// Log the node's information
	nodeType := "Light Node"
	if n.nodeConfig.IsFullNode {
		nodeType = "Full Node"
	}
	if n.nodeConfig.IsMiner {
		nodeType += " + Miner"
	}
	if n.nodeConfig.EnableNodeReward {
		nodeType += " (with rewards)"
	}
	
	fmt.Printf("QBitChain %s started with addresses: %s\n", nodeType, n.host.Addrs())
	fmt.Printf("Node ID: %s\n", n.host.ID())
	
	// Set up protocol handlers
	n.setupProtocolHandlers()
	
	// Start the DHT for peer discovery
	err = n.setupDHT()
	if err != nil {
		return fmt.Errorf("failed to set up DHT: %w", err)
	}
	
	// Connect to bootstrap nodes
	err = n.connectToBootstrapNodes()
	if err != nil {
		fmt.Printf("Warning: Failed to connect to some bootstrap nodes: %v\n", err)
		// Continue anyway, this is not fatal
	}
	
	// Start the peer discovery routine
	go n.discoverPeers()
	
	// Start the block and transaction propagation handlers
	go n.handleNewBlocks()
	go n.handleNewTransactions()
	
	// If this node participates in the rewards program, register it
	if n.nodeConfig.EnableNodeReward {
		rewardAddr := n.config.NodeRewards.RewardAddress
		if rewardAddr == "" {
			// If no reward address is specified, try to use the default wallet address
			if n.walletManager != nil && n.walletManager.GetDefaultWallet() != nil {
				rewardAddr = n.walletManager.GetDefaultWallet().Address
				// Save it to config for future use
				n.config.NodeRewards.RewardAddress = rewardAddr
			} else {
				fmt.Println("Warning: Node rewards enabled but no reward address specified. Create a wallet first.")
			}
		}
		
		// Register based on node type
		if n.nodeConfig.IsFullNode {
			n.blockchain.RegisterFullNode(rewardAddr)
		} else if n.nodeConfig.IsLightNode {
			n.blockchain.RegisterLightNode(rewardAddr)
		}
		
		fmt.Printf("Node registered for rewards with address: %s\n", rewardAddr)
	}
	
	// Start the miner if this is a mining node
	if n.nodeConfig.IsMiner && n.miner != nil {
		err := n.miner.Start()
		if err != nil {
			return fmt.Errorf("failed to start miner: %w", err)
		}
	}
	
	return nil
}

// Stop stops the node
func (n *Node) Stop() error {
	// Stop the miner if it's running
	if n.nodeConfig.IsMiner && n.miner != nil {
		n.miner.Stop()
	}
	
	// Cancel the context to stop all goroutines
	n.cancel()
	
	// Close the libp2p host
	if n.host != nil {
		err := n.host.Close()
		if err != nil {
			return fmt.Errorf("failed to close libp2p host: %w", err)
		}
	}
	
	return nil
}

// setupProtocolHandlers sets up the protocol handlers for the node
func (n *Node) setupProtocolHandlers() {
	// Set up the block protocol handler
	n.host.SetStreamHandler(protocol.ID(BlockProtocolID), n.handleBlockStream)
	
	// Set up the transaction protocol handler
	n.host.SetStreamHandler(protocol.ID(TxProtocolID), n.handleTxStream)
	
	// Set up the peer discovery protocol handler
	n.host.SetStreamHandler(protocol.ID(PeerDiscoveryID), n.handlePeerDiscoveryStream)
}

// setupDHT sets up the DHT for peer discovery
func (n *Node) setupDHT() error {
	// Create a new DHT
	kadDHT, err := dht.New(n.ctx, n.host)
	if err != nil {
		return fmt.Errorf("failed to create DHT: %w", err)
	}
	n.dht = kadDHT
	
	// Bootstrap the DHT
	if err = n.dht.Bootstrap(n.ctx); err != nil {
		return fmt.Errorf("failed to bootstrap DHT: %w", err)
	}
	
	return nil
}

// connectToBootstrapNodes connects to the bootstrap nodes
func (n *Node) connectToBootstrapNodes() error {
	for _, addrStr := range n.config.Network.BootstrapNodes {
		// Parse the multiaddress
		addr, err := multiaddr.NewMultiaddr(addrStr)
		if err != nil {
			fmt.Printf("Invalid bootstrap node address: %v\n", err)
			continue
		}
		
		// Extract the peer ID from the multiaddress
		peerInfo, err := peer.AddrInfoFromP2pAddr(addr)
		if err != nil {
			fmt.Printf("Failed to extract peer info: %v\n", err)
			continue
		}
		
		// Connect to the peer
		err = n.host.Connect(n.ctx, *peerInfo)
		if err != nil {
			fmt.Printf("Failed to connect to bootstrap node %s: %v\n", addrStr, err)
			continue
		}
		
		// Add the peer to our list
		n.addPeer(peerInfo.ID, peerInfo.Addrs[0])
		
		fmt.Printf("Connected to bootstrap node: %s\n", addrStr)
	}
	
	return nil
}

// discoverPeers periodically discovers new peers
func (n *Node) discoverPeers() {
	ticker := time.NewTicker(DiscoveryInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
			// Look for peers with the QBitChain protocol
			peers, err := n.dht.FindPeers(n.ctx, PeerDiscoveryID)
			if err != nil {
				fmt.Printf("Failed to find peers: %v\n", err)
				continue
			}
			
			// Connect to the discovered peers
			for p := range peers {
				// Skip if it's us
				if p.ID == n.host.ID() {
					continue
				}
				
				// Skip if we're already connected to this peer
				if n.isPeerConnected(p.ID) {
					continue
				}
				
				// Skip if we've reached the maximum number of peers
				if n.getPeerCount() >= n.maxPeers {
					break
				}
				
				// Connect to the peer
				err := n.host.Connect(n.ctx, p)
				if err != nil {
					fmt.Printf("Failed to connect to peer %s: %v\n", p.ID, err)
					continue
				}
				
				// Add the peer to our list
				n.addPeer(p.ID, p.Addrs[0])
			}
		}
	}
}

// handleBlockStream handles incoming block streams
func (n *Node) handleBlockStream(s network.Stream) {
	// Create a JSON decoder for the stream
	dec := json.NewDecoder(s)
	
	// Decode the block
	var block blockchain.Block
	if err := dec.Decode(&block); err != nil {
		s.Reset()
		return
	}
	
	// Close the stream
	s.Close()
	
	// Add the peer if we don't already have it
	n.addPeer(s.Conn().RemotePeer(), s.Conn().RemoteMultiaddr())
	
	// Process the block
	n.processBlock(&block, s.Conn().RemotePeer())
}

// handleTxStream handles incoming transaction streams
func (n *Node) handleTxStream(s network.Stream) {
	// Create a JSON decoder for the stream
	dec := json.NewDecoder(s)
	
	// Decode the transaction
	var tx blockchain.Transaction
	if err := dec.Decode(&tx); err != nil {
		s.Reset()
		return
	}
	
	// Close the stream
	s.Close()
	
	// Add the peer if we don't already have it
	n.addPeer(s.Conn().RemotePeer(), s.Conn().RemoteMultiaddr())
	
	// Process the transaction
	n.processTx(&tx, s.Conn().RemotePeer())
}

// handlePeerDiscoveryStream handles peer discovery streams
func (n *Node) handlePeerDiscoveryStream(s network.Stream) {
	// Close the stream - we just use this for peer discovery
	s.Close()
	
	// Add the peer if we don't already have it
	n.addPeer(s.Conn().RemotePeer(), s.Conn().RemoteMultiaddr())
}

// processBlock processes a received block
func (n *Node) processBlock(block *blockchain.Block, fromPeer peer.ID) {
	// Update block stats
	n.stats.mtx.Lock()
	n.stats.BlocksReceived++
	n.stats.mtx.Unlock()
	
	// Update peer stats
	n.peersMutex.RLock()
	peer, ok := n.peers[fromPeer]
	n.peersMutex.RUnlock()
	if ok {
		peer.mtx.Lock()
		peer.BlocksReceived++
		peer.LastSeen = time.Now()
		peer.mtx.Unlock()
	}
	
	// Add the block to the blockchain
	err := n.blockchain.AddBlock(block)
	if err != nil {
		fmt.Printf("Failed to add block from peer %s: %v\n", fromPeer, err)
		return
	}
	
	// Propagate the block to other peers
	n.broadcastBlock(block, fromPeer)
}

// processTx processes a received transaction
func (n *Node) processTx(tx *blockchain.Transaction, fromPeer peer.ID) {
	// Update transaction stats
	n.stats.mtx.Lock()
	n.stats.TxReceived++
	n.stats.mtx.Unlock()
	
	// Update peer stats
	n.peersMutex.RLock()
	peer, ok := n.peers[fromPeer]
	n.peersMutex.RUnlock()
	if ok {
		peer.mtx.Lock()
		peer.TxReceived++
		peer.LastSeen = time.Now()
		peer.mtx.Unlock()
	}
	
	// Add the transaction to the mempool
	err := n.blockchain.AddTransaction(tx)
	if err != nil {
		fmt.Printf("Failed to add transaction from peer %s: %v\n", fromPeer, err)
		return
	}
	
	// Propagate the transaction to other peers
	n.broadcastTx(tx, fromPeer)
}

// broadcastBlock broadcasts a block to all connected peers except the sender
func (n *Node) broadcastBlock(block *blockchain.Block, excludePeer peer.ID) {
	// Get all connected peers
	n.peersMutex.RLock()
	peers := make([]peer.ID, 0, len(n.peers))
	for id := range n.peers {
		if id != excludePeer {
			peers = append(peers, id)
		}
	}
	n.peersMutex.RUnlock()
	
	// Broadcast the block to each peer
	for _, p := range peers {
		// Open a stream to the peer
		s, err := n.host.NewStream(n.ctx, p, protocol.ID(BlockProtocolID))
		if err != nil {
			fmt.Printf("Failed to open stream to peer %s: %v\n", p, err)
			continue
		}
		
		// Encode the block to JSON
		enc := json.NewEncoder(s)
		if err := enc.Encode(block); err != nil {
			s.Reset()
			fmt.Printf("Failed to encode block for peer %s: %v\n", p, err)
			continue
		}
		
		// Close the stream
		s.Close()
		
		// Update stats
		n.stats.mtx.Lock()
		n.stats.BlocksTransmitted++
		n.stats.mtx.Unlock()
		
		// Update peer stats
		n.peersMutex.RLock()
		peer, ok := n.peers[p]
		n.peersMutex.RUnlock()
		if ok {
			peer.mtx.Lock()
			peer.BlocksTransmitted++
			peer.mtx.Unlock()
		}
	}
}

// broadcastTx broadcasts a transaction to all connected peers except the sender
func (n *Node) broadcastTx(tx *blockchain.Transaction, excludePeer peer.ID) {
	// Get all connected peers
	n.peersMutex.RLock()
	peers := make([]peer.ID, 0, len(n.peers))
	for id := range n.peers {
		if id != excludePeer {
			peers = append(peers, id)
		}
	}
	n.peersMutex.RUnlock()
	
	// Broadcast the transaction to each peer
	for _, p := range peers {
		// Open a stream to the peer
		s, err := n.host.NewStream(n.ctx, p, protocol.ID(TxProtocolID))
		if err != nil {
			fmt.Printf("Failed to open stream to peer %s: %v\n", p, err)
			continue
		}
		
		// Encode the transaction to JSON
		enc := json.NewEncoder(s)
		if err := enc.Encode(tx); err != nil {
			s.Reset()
			fmt.Printf("Failed to encode transaction for peer %s: %v\n", p, err)
			continue
		}
		
		// Close the stream
		s.Close()
		
		// Update stats
		n.stats.mtx.Lock()
		n.stats.TxTransmitted++
		n.stats.mtx.Unlock()
		
		// Update peer stats
		n.peersMutex.RLock()
		peer, ok := n.peers[p]
		n.peersMutex.RUnlock()
		if ok {
			peer.mtx.Lock()
			peer.TxTransmitted++
			peer.mtx.Unlock()
		}
	}
}

// handleNewBlocks handles new blocks from the blockchain
func (n *Node) handleNewBlocks() {
	blockCh := n.blockchain.GetNewBlockChannel()
	
	for {
		select {
		case <-n.ctx.Done():
			return
		case block := <-blockCh:
			// Broadcast the block to all peers
			n.broadcastBlock(block, "")
		}
	}
}

// handleNewTransactions handles new transactions from the node
func (n *Node) handleNewTransactions() {
	for {
		select {
		case <-n.ctx.Done():
			return
		case tx := <-n.newTxCh:
			// Add the transaction to the mempool
			err := n.blockchain.AddTransaction(tx)
			if err != nil {
				fmt.Printf("Failed to add transaction to mempool: %v\n", err)
				continue
			}
			
			// Broadcast the transaction to all peers
			n.broadcastTx(tx, "")
		}
	}
}

// addPeer adds a peer to the node's peer list
func (n *Node) addPeer(id peer.ID, addr multiaddr.Multiaddr) {
	n.peersMutex.Lock()
	defer n.peersMutex.Unlock()
	
	// Check if we already have this peer
	if _, ok := n.peers[id]; ok {
		return
	}
	
	// Check if we've reached the maximum number of peers
	if len(n.peers) >= n.maxPeers {
		// Remove the oldest peer
		var oldestPeer peer.ID
		var oldestTime time.Time
		for pid, p := range n.peers {
			if oldestPeer == "" || p.ConnectedAt.Before(oldestTime) {
				oldestPeer = pid
				oldestTime = p.ConnectedAt
			}
		}
		
		// Remove the oldest peer
		delete(n.peers, oldestPeer)
	}
	
	// Add the new peer
	n.peers[id] = &Peer{
		ID:          id,
		Address:     addr,
		ConnectedAt: time.Now(),
		LastSeen:    time.Now(),
	}
	
	// Update stats
	n.stats.mtx.Lock()
	n.stats.PeersConnected = uint64(len(n.peers))
	n.stats.mtx.Unlock()
}

// removePeer removes a peer from the node's peer list
func (n *Node) removePeer(id peer.ID) {
	n.peersMutex.Lock()
	defer n.peersMutex.Unlock()
	
	// Remove the peer
	delete(n.peers, id)
	
	// Update stats
	n.stats.mtx.Lock()
	n.stats.PeersConnected = uint64(len(n.peers))
	n.stats.mtx.Unlock()
}

// isPeerConnected checks if a peer is connected
func (n *Node) isPeerConnected(id peer.ID) bool {
	n.peersMutex.RLock()
	defer n.peersMutex.RUnlock()
	
	_, ok := n.peers[id]
	return ok
}

// getPeerCount returns the number of connected peers
func (n *Node) getPeerCount() int {
	n.peersMutex.RLock()
	defer n.peersMutex.RUnlock()
	
	return len(n.peers)
}

// BroadcastTransaction broadcasts a transaction to the network
func (n *Node) BroadcastTransaction(tx *blockchain.Transaction) {
	// Send the transaction to the handler
	n.newTxCh <- tx
}

// GetStats returns the node's statistics
func (n *Node) GetStats() *NodeStats {
	return n.stats
}

// GetPeers returns the node's peers
func (n *Node) GetPeers() []*Peer {
	n.peersMutex.RLock()
	defer n.peersMutex.RUnlock()
	
	peers := make([]*Peer, 0, len(n.peers))
	for _, p := range n.peers {
		peers = append(peers, p)
	}
	
	return peers
}