package wallet

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/seagercortez/qbitchain/internal/blockchain"
	"github.com/seagercortez/qbitchain/internal/crypto"
	"github.com/seagercortez/qbitchain/pkg/config"
)

// Manager manages the wallet operations
type Manager struct {
	config       *config.Config
	keystore     string
	wallets      map[string]*Wallet
	defaultWallet *Wallet
	mtx          sync.RWMutex
}

// Wallet represents a QBitChain wallet
type Wallet struct {
	KeyPair   *crypto.KeyPair
	Address   string
	Balance   uint64
	Name      string
	CreatedAt time.Time
	manager   *Manager
}

// NewManager creates a new wallet manager
func NewManager(cfg *config.Config) (*Manager, error) {
	// Create the wallet manager
	manager := &Manager{
		config:   cfg,
		keystore: cfg.Wallet.KeystoreDir,
		wallets:  make(map[string]*Wallet),
	}

	// Load existing wallets
	err := manager.LoadWallets()
	if err != nil {
		return nil, fmt.Errorf("failed to load wallets: %w", err)
	}

	return manager, nil
}

// LoadWallets loads all wallets from the keystore directory
func (m *Manager) LoadWallets() error {
	// Create the keystore directory if it doesn't exist
	if err := os.MkdirAll(m.keystore, 0700); err != nil {
		return fmt.Errorf("failed to create keystore directory: %w", err)
	}

	// Load key pairs from the keystore directory
	keyPairs, err := crypto.LoadAllKeyPairs(m.keystore)
	if err != nil {
		return fmt.Errorf("failed to load key pairs: %w", err)
	}

	// Create wallets from the key pairs
	m.mtx.Lock()
	defer m.mtx.Unlock()

	for _, keyPair := range keyPairs {
		wallet := &Wallet{
			KeyPair:   keyPair,
			Address:   keyPair.Address,
			Balance:   0, // Will be updated when we connect to the blockchain
			Name:      "", // Will be updated if we have a name for it
			CreatedAt: keyPair.Created,
			manager:   m,
		}

		m.wallets[keyPair.Address] = wallet

		// Set as default wallet if we don't have one yet
		if m.defaultWallet == nil {
			m.defaultWallet = wallet
		}
	}

	return nil
}

// CreateWallet creates a new wallet
func (m *Manager) CreateWallet(name string) (*Wallet, error) {
	// Generate a new key pair
	keyPair, err := crypto.NewKeyPair()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Create a wallet from the key pair
	wallet := &Wallet{
		KeyPair:   keyPair,
		Address:   keyPair.Address,
		Balance:   0,
		Name:      name,
		CreatedAt: time.Now().UTC(),
		manager:   m,
	}

	// Save the key pair to a file
	err = crypto.SaveKeyPair(keyPair, m.keystore, fmt.Sprintf("%s.qbckey", name))
	if err != nil {
		return nil, fmt.Errorf("failed to save key pair: %w", err)
	}

	// Add the wallet to the manager
	m.mtx.Lock()
	m.wallets[keyPair.Address] = wallet
	if m.defaultWallet == nil {
		m.defaultWallet = wallet
	}
	m.mtx.Unlock()

	return wallet, nil
}

// GetWallet gets a wallet by address
func (m *Manager) GetWallet(address string) (*Wallet, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	wallet, ok := m.wallets[address]
	if !ok {
		return nil, fmt.Errorf("wallet with address %s not found", address)
	}

	return wallet, nil
}

// GetWallets returns all wallets
func (m *Manager) GetWallets() []*Wallet {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	wallets := make([]*Wallet, 0, len(m.wallets))
	for _, wallet := range m.wallets {
		wallets = append(wallets, wallet)
	}

	return wallets
}

// GetDefaultWallet returns the default wallet
func (m *Manager) GetDefaultWallet() *Wallet {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	return m.defaultWallet
}

// SetDefaultWallet sets the default wallet
func (m *Manager) SetDefaultWallet(address string) error {
	wallet, err := m.GetWallet(address)
	if err != nil {
		return err
	}

	m.mtx.Lock()
	m.defaultWallet = wallet
	m.mtx.Unlock()

	return nil
}

// UpdateBalances updates the balances of all wallets
func (m *Manager) UpdateBalances(bc *blockchain.Blockchain) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	// This would require iterating through the UTXO set in the blockchain
	// For simplicity, we're just stubbing this out for now
	// In a real implementation, we would query the blockchain for UTXOs for each wallet

	return nil
}

// CreateTransaction creates a transaction
func (w *Wallet) CreateTransaction(toAddress string, amount, fee, gasPrice, gasLimit uint64) (*blockchain.Transaction, error) {
	// For simplicity, we're just creating a simple transaction structure
	// In a real implementation, this would be much more complex, involving UTXO selection

	if w.manager == nil {
		return nil, errors.New("wallet has no manager")
	}

	// This is a simplified transaction creation process
	// In a real implementation, we would need to select UTXOs, calculate change, etc.

	// Create a dummy input (in reality, we would select UTXOs)
	input := blockchain.TxInput{
		TxID:        [32]byte{}, // This would be a real UTXO reference
		OutputIndex: 0,
		Signature:   []byte{},   // Will be filled by signing
		PublicKey:   w.KeyPair.PublicKey.Serialize(),
	}

	// Create the outputs
	toPubKeyHash, err := crypto.AddressToPublicKeyHash(toAddress)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient address: %w", err)
	}

	// Output to the recipient
	output1 := blockchain.TxOutput{
		Value:         amount,
		PublicKeyHash: toPubKeyHash,
		ScriptType:    0, // P2PKH
	}

	// Output for change (in reality, this would be calculated based on selected UTXOs)
	// We're just using a dummy change amount for simplicity
	changePubKeyHash, _ := crypto.AddressToPublicKeyHash(w.Address)
	output2 := blockchain.TxOutput{
		Value:         1000, // Dummy change amount
		PublicKeyHash: changePubKeyHash,
		ScriptType:    0, // P2PKH
	}

	// Create the transaction
	tx := blockchain.NewTransaction(
		[]blockchain.TxInput{input},
		[]blockchain.TxOutput{output1, output2},
		fee,
		gasPrice,
		gasLimit,
	)

	// In a real implementation, we would sign the transaction here
	// For simplicity, we're just returning the unsigned transaction

	return tx, nil
}

// Sign signs a transaction
func (w *Wallet) Sign(tx *blockchain.Transaction, prevTxs map[[32]byte]*blockchain.Transaction) error {
	return tx.Sign(w.KeyPair.PrivateKey, prevTxs)
}

// GetBalance returns the wallet balance
func (w *Wallet) GetBalance() uint64 {
	return w.Balance
}

// GetTransactionHistory returns the transaction history for this wallet
func (w *Wallet) GetTransactionHistory(bc *blockchain.Blockchain) ([]*blockchain.Transaction, error) {
	// This would require scanning the blockchain for transactions involving this wallet
	// For simplicity, we're just returning an empty slice
	return []*blockchain.Transaction{}, nil
}