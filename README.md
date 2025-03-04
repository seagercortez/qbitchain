# QBitChain: A Quantum-Resistant Blockchain

QBitChain is a minimal, yet production-ready, quantum-resistant blockchain implemented in Go. It features a post-quantum secure cryptographic foundation using dilithium signatures, making it resilient against potential threats from quantum computers.

## Features

- **Quantum Resistance**: Uses dilithium signatures from the CIRCL library for post-quantum security
- **Full Node Support**: Run a full node to validate and relay transactions and blocks
- **Light Node Support**: Run a lightweight node that processes transactions without storing the full blockchain
- **Node Rewards**: Earn rewards for running either a full node or light node
- **Transaction Processing Rewards**: Earn a percentage of transaction fees for processing transactions
- **Mining Capabilities**: Mine new blocks and earn QBit (QBC) rewards
- **Transaction Support**: Create, sign, and broadcast transactions
- **Wallet Management**: Create and manage wallets with secure key storage
- **P2P Networking**: Connect to other nodes on the network using libp2p
- **Configurable**: Customize through YAML configuration files
- **Testnet & Livenet**: Supports both testing and production environments

## Getting Started

### Prerequisites

- Go 1.21 or higher
- Git

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/seagercortez/qbitchain.git
   cd qbitchain
   ```

2. Build the application:
   ```bash
   go build -o qbitchain ./cmd/qbitchain
   ```

3. Run the node:
   ```bash
   # Run as a full node
   ./qbitchain --full-node
   
   # Run as a light node (default if no type is specified)
   ./qbitchain --light-node
   
   # Run as a miner (always requires a full node)
   ./qbitchain --full-node --miner
   
   # Run with node rewards enabled
   ./qbitchain --full-node --node-reward
   
   # Run on testnet
   ./qbitchain --full-node --testnet
   
   # Complete example: full node + miner + rewards on testnet
   ./qbitchain --full-node --miner --node-reward --testnet
   ```

## Configuration

QBitChain can be configured using a YAML configuration file. By default, it looks for a file named `config.yaml` in the current directory, but you can specify a different file using the `--config` flag.

```yaml
# Network settings
network_type: "livenet"  # or "testnet"
data_dir: "~/.qbitchain"
log_level: "info"
api_enabled: true
api_port: 8545

# Network settings
network:
  listen_address: "0.0.0.0:9000"
  bootstrap_nodes:
    - "/ip4/127.0.0.1/tcp/9000/p2p/QmBootstrap1"
    - "/ip4/127.0.0.1/tcp/9001/p2p/QmBootstrap2"
  max_peers: 25
  handshake_timeout: 30

# Blockchain settings
blockchain:
  genesis_file: ""
  max_block_size: 1048576
  target_block_time: 60

# Transaction settings
transaction:
  min_gas_price: 1000000000
  max_gas_limit: 12500000

# Mining settings
mining:
  enabled: false
  miner_address: "QBC1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqe55vvx9"
  miner_threads: 0
  miner_gas_floor: 8000000
  miner_gas_ceiling: 12000000

# Wallet settings
wallet:
  keystore_dir: "~/.qbitchain/keystore"

# Node rewards settings
node_rewards:
  enabled: true
  reward_address: ""  # Set to your wallet address
  full_node_percent: 3.0    # 3% of block reward to full nodes
  light_node_percent: 1.0   # 1% of block reward to light nodes
  tx_process_percent: 5.0   # 5% of transaction fees to processors
```

## Architecture

QBitChain consists of several core components:

- **Blockchain**: Manages the chain of blocks, including validation and UTXO set
- **Network**: Handles P2P communication using libp2p
- **Wallet**: Manages key pairs, addresses, and transaction creation
- **Mining**: Implements the mining process to create new blocks
- **Consensus**: Implements proof-of-work consensus rules
- **Crypto**: Provides quantum-resistant cryptographic operations

## Command Line Interface

QBitChain provides a simple command line interface:

```bash
# Run a full node (stores complete blockchain)
./qbitchain --full-node

# Run a light node (processes transactions without full history)
./qbitchain --light-node

# Run a miner (requires full node)
./qbitchain --miner --full-node

# Enable node rewards
./qbitchain --node-reward --full-node

# Connect to testnet
./qbitchain --testnet

# Specify a configuration file
./qbitchain --config my-config.yaml

# Get help
./qbitchain --help
```

## Wallet Commands

```bash
# Create a new wallet
./qbitchain wallet create --name "my-wallet"

# List all wallets
./qbitchain wallet list

# Get wallet balance
./qbitchain wallet balance --address "QBC1..."

# Create a transaction
./qbitchain wallet send --from "QBC1..." --to "QBC1..." --amount "1.5 QBC" --fee "0.001 QBC"
```

## Mining

To start mining, run:

```bash
./qbitchain --miner --miner-address "QBC1..." --miner-threads 4
```

## Blockchain Explorer

You can interact with the blockchain using the built-in HTTP API:

```bash
# Get blockchain info
curl http://localhost:8545/api/chain/info

# Get block by height
curl http://localhost:8545/api/block/height/1

# Get block by hash
curl http://localhost:8545/api/block/hash/0123456789abcdef...

# Get transaction
curl http://localhost:8545/api/tx/0123456789abcdef...
```

## Project Structure

```
/
├── cmd/
│   └── qbitchain/          # Main executable
├── internal/
│   ├── blockchain/         # Blockchain implementation
│   ├── consensus/          # Consensus rules and validation
│   ├── crypto/             # Cryptographic primitives
│   ├── mining/             # Mining implementation
│   ├── network/            # P2P networking
│   └── wallet/             # Wallet implementation
├── pkg/
│   ├── config/             # Configuration handling
│   └── utils/              # Utility functions
├── testnet/                # Testnet configuration
└── livenet/                # Livenet configuration
```

## Technical Details

- **Block Time**: 60 seconds
- **Mining Algorithm**: Proof of Work with difficulty adjustment
- **Block Reward**: 50 QBC with halving every 210,000 blocks
- **Total Supply**: 21,000,000 QBC
- **Quantum Security**: 192-bit quantum security level
- **Consensus**: Nakamoto consensus with longest chain rule
- **P2P Network**: libp2p with Kademlia DHT
- **Node Types**: Full nodes and lightweight transaction nodes
- **Node Rewards**: 
  - Full nodes: 3% of block rewards
  - Light nodes: 1% of block rewards
  - Transaction processors: 5% of transaction fees

## Development

To contribute to QBitChain:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## License

QBitChain is licensed under the MIT License. See the LICENSE file for details.

## Security

If you discover a security vulnerability, please send an email to security@qbitchain.com instead of opening a public issue.

## Acknowledgments

QBitChain uses the following open-source libraries:

- [libp2p](https://github.com/libp2p/go-libp2p) for P2P networking
- [CIRCL](https://github.com/cloudflare/circl) for post-quantum cryptography
- [LevelDB](https://github.com/syndtr/goleveldb) for key-value storage

## Contact

For questions or feedback, please open an issue on GitHub.