package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// FormatTime formats a time in a consistent format
func FormatTime(t time.Time) string {
	return t.Format(time.RFC3339)
}

// ParseTime parses a time string in the format returned by FormatTime
func ParseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}

// FormatHash formats a byte array as a hex string
func FormatHash(hash []byte) string {
	return hex.EncodeToString(hash)
}

// ParseHash parses a hex string into a byte array
func ParseHash(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// FormatAmount formats an amount with the appropriate suffix (e.g., QBC, mQBC, uQBC)
func FormatAmount(amount uint64) string {
	// 1 QBC = 10^18 units (like Ether)
	if amount >= 1e18 {
		return fmt.Sprintf("%.6f QBC", float64(amount)/1e18)
	} else if amount >= 1e15 {
		return fmt.Sprintf("%.6f mQBC", float64(amount)/1e15)
	} else if amount >= 1e12 {
		return fmt.Sprintf("%.6f uQBC", float64(amount)/1e12)
	} else {
		return fmt.Sprintf("%d units", amount)
	}
}

// ParseAmount parses an amount string into a uint64
func ParseAmount(s string) (uint64, error) {
	parts := strings.Split(s, " ")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid amount format: %s", s)
	}
	
	amountStr := parts[0]
	unit := parts[1]
	
	amount, err := strconv.ParseFloat(amountStr, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid amount: %s", amountStr)
	}
	
	var multiplier float64
	switch unit {
	case "QBC":
		multiplier = 1e18
	case "mQBC":
		multiplier = 1e15
	case "uQBC":
		multiplier = 1e12
	case "units":
		multiplier = 1
	default:
		return 0, fmt.Errorf("invalid unit: %s", unit)
	}
	
	return uint64(amount * multiplier), nil
}

// EnsureDir ensures that a directory exists, creating it if necessary
func EnsureDir(path string) error {
	return os.MkdirAll(path, 0755)
}

// TempDir creates a temporary directory with the given prefix
func TempDir(prefix string) (string, error) {
	return os.MkdirTemp("", prefix)
}

// RandomHex generates a random hex string of the given length
func RandomHex(length int) (string, error) {
	bytes := make([]byte, length/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// RandomUint64 generates a random uint64
func RandomUint64() (uint64, error) {
	max := big.NewInt(0).SetUint64(^uint64(0))
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return 0, err
	}
	return n.Uint64(), nil
}

// FileExists checks if a file exists
func FileExists(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	}
	return false
}

// FindFilesWithExtension finds all files with the given extension in the given directory
func FindFilesWithExtension(dir, ext string) ([]string, error) {
	var files []string
	
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if !info.IsDir() && strings.HasSuffix(info.Name(), ext) {
			files = append(files, path)
		}
		
		return nil
	})
	
	return files, err
}

// BytesToHuman converts bytes to a human-readable string (e.g., 1.5 KB, 2.3 MB)
func BytesToHuman(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// HumanToBytes converts a human-readable size string to bytes
func HumanToBytes(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	
	if s == "" {
		return 0, nil
	}
	
	if s == "0" {
		return 0, nil
	}
	
	// Parse the numeric part
	i := 0
	for i < len(s) && (s[i] >= '0' && s[i] <= '9' || s[i] == '.' || s[i] == ',') {
		i++
	}
	
	numStr := s[:i]
	numStr = strings.ReplaceAll(numStr, ",", ".")
	
	num, err := strconv.ParseFloat(numStr, 64)
	if err != nil {
		return 0, err
	}
	
	// Parse the unit part
	unitStr := strings.TrimSpace(s[i:])
	
	var unitMultiplier uint64 = 1
	
	switch strings.ToUpper(unitStr) {
	case "B", "BYTE", "BYTES":
		unitMultiplier = 1
	case "K", "KB", "KIB":
		unitMultiplier = 1024
	case "M", "MB", "MIB":
		unitMultiplier = 1024 * 1024
	case "G", "GB", "GIB":
		unitMultiplier = 1024 * 1024 * 1024
	case "T", "TB", "TIB":
		unitMultiplier = 1024 * 1024 * 1024 * 1024
	case "P", "PB", "PIB":
		unitMultiplier = 1024 * 1024 * 1024 * 1024 * 1024
	default:
		return 0, fmt.Errorf("unknown unit: %s", unitStr)
	}
	
	return uint64(num * float64(unitMultiplier)), nil
}