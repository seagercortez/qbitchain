package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cloudflare/circl/sign/dilithium"
	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

const (
	// KeyVersion is the version of the key format
	KeyVersion = 1
	
	// AddressPrefix is the prefix for QBitChain addresses
	AddressPrefix = "QBC"
	
	// AddressChecksum is the number of checksum bytes for addresses
	AddressChecksumLength = 4
	
	// Default mode is Dilithium3 which offers 192-bit quantum security
	DefaultDilithiumMode = dilithium.Mode3
	
	// Key file extension
	KeyFileExtension = ".qbckey"
)

// PrivateKey represents a QBitChain private key
type PrivateKey struct {
	Raw        []byte
	PublicKey  *PublicKey
	Mode       dilithium.Mode
	PrivateKey dilithium.PrivateKey
}

// PublicKey represents a QBitChain public key
type PublicKey struct {
	Raw       []byte
	Mode      dilithium.Mode
	PublicKey dilithium.PublicKey
}

// KeyPair represents a QBitChain key pair
type KeyPair struct {
	PrivateKey *PrivateKey
	PublicKey  *PublicKey
	Address    string
	Created    time.Time
}

// NewKeyPair generates a new key pair
func NewKeyPair() (*KeyPair, error) {
	// Use Dilithium for post-quantum security
	mode := DefaultDilithiumMode
	
	// Generate a new key pair
	publicKey, privateKey, err := mode.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key pair: %w", err)
	}
	
	// Create the public key
	pubKey := &PublicKey{
		Raw:       publicKey,
		Mode:      mode,
		PublicKey: publicKey,
	}
	
	// Create the private key
	privKey := &PrivateKey{
		Raw:        privateKey,
		PublicKey:  pubKey,
		Mode:       mode,
		PrivateKey: privateKey,
	}
	
	// Generate the address
	address, err := GenerateAddress(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate address: %w", err)
	}
	
	// Create the key pair
	keyPair := &KeyPair{
		PrivateKey: privKey,
		PublicKey:  pubKey,
		Address:    address,
		Created:    time.Now().UTC(),
	}
	
	return keyPair, nil
}

// Sign signs a message with the private key
func (pk *PrivateKey) Sign(message []byte) ([]byte, error) {
	// Use the dilithium signing algorithm
	signature := pk.Mode.Sign(pk.PrivateKey, message)
	return signature, nil
}

// Verify verifies a signature with the public key
func (pk *PublicKey) Verify(message, signature []byte) bool {
	// Use the dilithium verification algorithm
	return pk.Mode.Verify(pk.PublicKey, message, signature)
}

// Serialize serializes the private key to a string
func (pk *PrivateKey) Serialize() string {
	return base64.StdEncoding.EncodeToString(pk.Raw)
}

// Serialize serializes the public key to a string
func (pk *PublicKey) Serialize() []byte {
	return pk.Raw
}

// GenerateAddress generates a QBitChain address from a public key
func GenerateAddress(publicKey *PublicKey) (string, error) {
	// Get the raw public key
	pubKeyRaw := publicKey.Serialize()
	
	// Hash the public key
	sha256Hash := sha256.Sum256(pubKeyRaw)
	
	// Create a RIPEMD-160 hash of the SHA-256 hash
	ripemd160Hasher := ripemd160.New()
	_, err := ripemd160Hasher.Write(sha256Hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to hash public key: %w", err)
	}
	
	// Get the RIPEMD-160 hash
	ripemd160Hash := ripemd160Hasher.Sum(nil)
	
	// Add version byte (0x00 for mainnet addresses)
	versionedHash := append([]byte{0x00}, ripemd160Hash...)
	
	// Create a checksum by taking the first 4 bytes of the double SHA-256 hash
	checksum := DoubleHash(versionedHash)[:AddressChecksumLength]
	
	// Append the checksum to get the full address bytes
	fullAddressBytes := append(versionedHash, checksum...)
	
	// Base58 encode the address bytes
	address := base58.Encode(fullAddressBytes)
	
	// Add the QBC prefix
	address = AddressPrefix + address
	
	return address, nil
}

// DoubleHash performs a double SHA-256 hash
func DoubleHash(data []byte) []byte {
	hash1 := sha256.Sum256(data)
	hash2 := sha256.Sum256(hash1[:])
	return hash2[:]
}

// AddressToPublicKeyHash converts an address to a public key hash
func AddressToPublicKeyHash(address string) ([]byte, error) {
	// Check if the address has the QBC prefix
	if !strings.HasPrefix(address, AddressPrefix) {
		return nil, errors.New("invalid address prefix")
	}
	
	// Remove the QBC prefix
	address = strings.TrimPrefix(address, AddressPrefix)
	
	// Base58 decode the address
	decoded := base58.Decode(address)
	if len(decoded) < 4+1+20 { // 4 bytes checksum + 1 byte version + 20 bytes RIPEMD-160 hash
		return nil, errors.New("invalid address length")
	}
	
	// Extract the versioned payload (version + RIPEMD-160 hash)
	versionedPayload := decoded[:len(decoded)-AddressChecksumLength]
	
	// Extract the checksum
	checksum := decoded[len(decoded)-AddressChecksumLength:]
	
	// Verify the checksum
	targetChecksum := DoubleHash(versionedPayload)[:AddressChecksumLength]
	if !bytes.Equal(checksum, targetChecksum) {
		return nil, errors.New("invalid address checksum")
	}
	
	// Extract the public key hash (RIPEMD-160 hash)
	publicKeyHash := versionedPayload[1:] // Skip the version byte
	
	return publicKeyHash, nil
}

// SaveKeyPair saves a key pair to a file
func SaveKeyPair(keyPair *KeyPair, dir, name string) error {
	// Create the directory if it doesn't exist
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}
	
	// Create a unique filename if none is provided
	if name == "" {
		name = fmt.Sprintf("qbc_key_%s_%d", keyPair.Address[:8], time.Now().Unix())
	}
	
	// Add the file extension if it doesn't have one
	if !strings.HasSuffix(name, KeyFileExtension) {
		name += KeyFileExtension
	}
	
	// Create the key file
	filePath := filepath.Join(dir, name)
	file, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer file.Close()
	
	// Write the key file header
	header := fmt.Sprintf("QBitChain Key File v%d\n", KeyVersion)
	_, err = file.WriteString(header)
	if err != nil {
		return fmt.Errorf("failed to write key file header: %w", err)
	}
	
	// Write the key data
	keyData := fmt.Sprintf("Address: %s\n", keyPair.Address)
	keyData += fmt.Sprintf("Created: %s\n", keyPair.Created.Format(time.RFC3339))
	keyData += fmt.Sprintf("Mode: %d\n", int(keyPair.PrivateKey.Mode))
	keyData += fmt.Sprintf("PrivateKey: %s\n", keyPair.PrivateKey.Serialize())
	keyData += fmt.Sprintf("PublicKey: %s\n", hex.EncodeToString(keyPair.PublicKey.Raw))
	
	_, err = file.WriteString(keyData)
	if err != nil {
		return fmt.Errorf("failed to write key data: %w", err)
	}
	
	return nil
}

// LoadKeyPair loads a key pair from a file
func LoadKeyPair(filePath string) (*KeyPair, error) {
	// Read the key file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}
	
	// Parse the key file
	lines := strings.Split(string(data), "\n")
	if len(lines) < 6 {
		return nil, errors.New("invalid key file format")
	}
	
	// Check the header
	if !strings.HasPrefix(lines[0], "QBitChain Key File v") {
		return nil, errors.New("invalid key file header")
	}
	
	// Extract the key data
	var address string
	var created time.Time
	var mode int
	var privateKeyStr string
	var publicKeyStr string
	
	for _, line := range lines[1:] {
		if strings.HasPrefix(line, "Address: ") {
			address = strings.TrimPrefix(line, "Address: ")
		} else if strings.HasPrefix(line, "Created: ") {
			createdStr := strings.TrimPrefix(line, "Created: ")
			created, err = time.Parse(time.RFC3339, createdStr)
			if err != nil {
				return nil, fmt.Errorf("invalid created time: %w", err)
			}
		} else if strings.HasPrefix(line, "Mode: ") {
			modeStr := strings.TrimPrefix(line, "Mode: ")
			_, err = fmt.Sscanf(modeStr, "%d", &mode)
			if err != nil {
				return nil, fmt.Errorf("invalid mode: %w", err)
			}
		} else if strings.HasPrefix(line, "PrivateKey: ") {
			privateKeyStr = strings.TrimPrefix(line, "PrivateKey: ")
		} else if strings.HasPrefix(line, "PublicKey: ") {
			publicKeyStr = strings.TrimPrefix(line, "PublicKey: ")
		}
	}
	
	// Check if we have all the required data
	if address == "" || privateKeyStr == "" || publicKeyStr == "" {
		return nil, errors.New("missing key data")
	}
	
	// Decode the private key
	privateKeyRaw, err := base64.StdEncoding.DecodeString(privateKeyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}
	
	// Decode the public key
	publicKeyRaw, err := hex.DecodeString(publicKeyStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}
	
	// Create the dilithium mode
	dilMode := dilithium.Mode(mode)
	
	// Create the public key
	publicKey := dilMode.PublicKeyFromBytes(publicKeyRaw)
	pubKey := &PublicKey{
		Raw:       publicKeyRaw,
		Mode:      dilMode,
		PublicKey: publicKey,
	}
	
	// Create the private key
	privateKey := dilMode.PrivateKeyFromBytes(privateKeyRaw)
	privKey := &PrivateKey{
		Raw:        privateKeyRaw,
		PublicKey:  pubKey,
		Mode:       dilMode,
		PrivateKey: privateKey,
	}
	
	// Create the key pair
	keyPair := &KeyPair{
		PrivateKey: privKey,
		PublicKey:  pubKey,
		Address:    address,
		Created:    created,
	}
	
	return keyPair, nil
}

// Load all key pairs from a directory
func LoadAllKeyPairs(dir string) ([]*KeyPair, error) {
	// Open the directory
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}
	
	// Load each key file
	var keyPairs []*KeyPair
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), KeyFileExtension) {
			continue
		}
		
		filePath := filepath.Join(dir, entry.Name())
		keyPair, err := LoadKeyPair(filePath)
		if err != nil {
			// Skip invalid key files
			continue
		}
		
		keyPairs = append(keyPairs, keyPair)
	}
	
	return keyPairs, nil
}