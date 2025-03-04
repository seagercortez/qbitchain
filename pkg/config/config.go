package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config holds the application configuration
type Config struct {
	// General settings
	DataDir        string `yaml:"data_dir"`
	NetworkType    string `yaml:"network_type"` // "testnet" or "livenet"
	LogLevel       string `yaml:"log_level"`
	APIEnabled     bool   `yaml:"api_enabled"`
	APIPort        int    `yaml:"api_port"`
	
	// Network settings
	Network struct {
		ListenAddress    string   `yaml:"listen_address"`
		BootstrapNodes   []string `yaml:"bootstrap_nodes"`
		MaxPeers         int      `yaml:"max_peers"`
		HandshakeTimeout int      `yaml:"handshake_timeout"`
	} `yaml:"network"`
	
	// Blockchain settings
	Blockchain struct {
		GenesisFile     string `yaml:"genesis_file"`
		MaxBlockSize    int    `yaml:"max_block_size"`
		TargetBlockTime int    `yaml:"target_block_time"` // in seconds
	} `yaml:"blockchain"`
	
	// Transaction settings
	Transaction struct {
		MinGasPrice int64 `yaml:"min_gas_price"`
		MaxGasLimit int64 `yaml:"max_gas_limit"`
	} `yaml:"transaction"`
	
	// Mining settings
	Mining struct {
		Enabled         bool   `yaml:"enabled"`
		MinerAddress    string `yaml:"miner_address"`
		MinerThreads    int    `yaml:"miner_threads"`
		MinerGasFloor   int64  `yaml:"miner_gas_floor"`
		MinerGasCeiling int64  `yaml:"miner_gas_ceiling"`
	} `yaml:"mining"`
	
	// Node rewards settings
	NodeRewards struct {
		Enabled           bool    `yaml:"enabled"`
		RewardAddress     string  `yaml:"reward_address"`
		FullNodePercent   float64 `yaml:"full_node_percent"`   // Percentage of block reward for full nodes
		LightNodePercent  float64 `yaml:"light_node_percent"`  // Percentage of block reward for light nodes
		TxProcessPercent  float64 `yaml:"tx_process_percent"`  // Percentage of transaction fees for processors
	} `yaml:"node_rewards"`
	
	// Wallet settings
	Wallet struct {
		KeystoreDir string `yaml:"keystore_dir"`
	} `yaml:"wallet"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	
	defaultDataDir := filepath.Join(home, ".qbitchain")
	
	cfg := &Config{
		DataDir:     defaultDataDir,
		NetworkType: "livenet",
		LogLevel:    "info",
		APIEnabled:  true,
		APIPort:     8545,
	}
	
	// Network defaults
	cfg.Network.ListenAddress = "0.0.0.0:9000"
	cfg.Network.MaxPeers = 25
	cfg.Network.HandshakeTimeout = 30
	
	// Default bootstrap nodes
	cfg.Network.BootstrapNodes = []string{
		// These would be replaced with actual bootstrap nodes for testnet/livenet
		"/ip4/127.0.0.1/tcp/9000/p2p/QmBootstrap1",
		"/ip4/127.0.0.1/tcp/9001/p2p/QmBootstrap2",
	}
	
	// Blockchain defaults
	cfg.Blockchain.MaxBlockSize = 1048576 // 1MB
	cfg.Blockchain.TargetBlockTime = 60   // 1 minute
	
	// Transaction defaults
	cfg.Transaction.MinGasPrice = 1000000000  // 1 Gwei
	cfg.Transaction.MaxGasLimit = 12500000    // Similar to Ethereum's limit
	
	// Mining defaults
	cfg.Mining.Enabled = false
	cfg.Mining.MinerThreads = 0 // Use all available cores
	cfg.Mining.MinerGasFloor = 8000000
	cfg.Mining.MinerGasCeiling = 12000000
	
	// Node rewards defaults
	cfg.NodeRewards.Enabled = false
	cfg.NodeRewards.RewardAddress = ""
	cfg.NodeRewards.FullNodePercent = 3.0   // 3% of block reward to full nodes 
	cfg.NodeRewards.LightNodePercent = 1.0  // 1% of block reward to light nodes
	cfg.NodeRewards.TxProcessPercent = 5.0  // 5% of transaction fees to processors
	
	// Wallet defaults
	cfg.Wallet.KeystoreDir = filepath.Join(defaultDataDir, "keystore")
	
	return cfg
}

// LoadConfig loads a configuration from a file
func LoadConfig(configPath string) (*Config, error) {
	// Start with default configuration
	cfg := DefaultConfig()
	
	// Read the configuration file
	data, err := os.ReadFile(configPath)
	if err != nil {
		// If the file doesn't exist, create a default one
		if os.IsNotExist(err) {
			// Create directories if they don't exist
			configDir := filepath.Dir(configPath)
			if err := os.MkdirAll(configDir, 0755); err != nil {
				return nil, fmt.Errorf("failed to create config directory: %w", err)
			}
			
			// Marshal the default config to YAML
			yamlData, err := yaml.Marshal(cfg)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal default config: %w", err)
			}
			
			// Write the default config to file
			if err := os.WriteFile(configPath, yamlData, 0644); err != nil {
				return nil, fmt.Errorf("failed to write default config: %w", err)
			}
			
			return cfg, nil
		}
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	
	// Parse the YAML configuration
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}
	
	// Create necessary directories
	if err := os.MkdirAll(cfg.DataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}
	
	if err := os.MkdirAll(cfg.Wallet.KeystoreDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create keystore directory: %w", err)
	}
	
	return cfg, nil
}

// SaveConfig saves the configuration to a file
func SaveConfig(cfg *Config, configPath string) error {
	// Marshal the config to YAML
	yamlData, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	
	// Write the config to file
	if err := os.WriteFile(configPath, yamlData, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}
	
	return nil
}