package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/seagercortez/qbitchain/internal/blockchain"
	"github.com/seagercortez/qbitchain/internal/network"
	"github.com/seagercortez/qbitchain/internal/wallet"
	"github.com/seagercortez/qbitchain/pkg/config"
)

func main() {
	// Parse command line arguments
	var configPath string
	var isFullNode bool
	var isLightNode bool
	var isMiner bool
	var isTestnet bool
	var enableNodeReward bool
	
	flag.StringVar(&configPath, "config", "config.yaml", "Path to configuration file")
	flag.BoolVar(&isFullNode, "full-node", false, "Run as a full node (validates and stores full blockchain)")
	flag.BoolVar(&isLightNode, "light-node", false, "Run as a light node (processes transactions without storing full blockchain)")
	flag.BoolVar(&isMiner, "miner", false, "Enable mining capabilities")
	flag.BoolVar(&isTestnet, "testnet", false, "Connect to testnet instead of livenet")
	flag.BoolVar(&enableNodeReward, "node-reward", false, "Enable rewards for running this node")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Override config with command line arguments
	if isTestnet {
		cfg.NetworkType = "testnet"
	}

	// Initialize components
	walletManager, err := wallet.NewManager(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize wallet: %v", err)
	}

	// Initialize blockchain
	bc, err := blockchain.NewBlockchain(cfg, isLightNode)
	if err != nil {
		log.Fatalf("Failed to initialize blockchain: %v", err)
	}

	// Validate node configuration
	if isFullNode && isLightNode {
		log.Fatalf("Cannot run as both full node and light node simultaneously")
	}
	
	if !isFullNode && !isLightNode {
		// Default to light node if neither is specified
		isLightNode = true
		fmt.Println("No node type specified, defaulting to light node")
	}
	
	// Set up node configuration
	nodeConfig := network.NodeConfig{
		IsFullNode:      isFullNode,
		IsLightNode:     isLightNode,
		IsMiner:         isMiner,
		NetworkType:     cfg.NetworkType,
		EnableNodeReward: enableNodeReward,
	}

	// Initialize network node
	node, err := network.NewNode(cfg, nodeConfig, bc, walletManager)
	if err != nil {
		log.Fatalf("Failed to initialize node: %v", err)
	}

	// Start the node
	if err := node.Start(); err != nil {
		log.Fatalf("Failed to start node: %v", err)
	}
	defer func() {
		if err := node.Stop(); err != nil {
			log.Printf("Error stopping node: %v", err)
		}
	}()

	fmt.Printf("QBitChain node started (Network: %s, Full Node: %v, Miner: %v)\n", 
		cfg.NetworkType, isFullNode, isMiner)

	// Wait for interrupt signal to gracefully shut down
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	fmt.Println("Shutting down QBitChain node...")
}