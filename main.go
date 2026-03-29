package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	version = "0.0.1"
	commit  = "HEAD"
	date    = "now"
	builtBy = "dev"
)

var (
	hashFile    = flag.String("hash-file", "", "Path to file containing SHA-256 hashes (default: auto-detect config dir)")
	minLength   = flag.Int("min-length", 8, "Minimum substring length to check")
	showVersion = flag.Bool("version", false, "Show version information")
)

func getDefaultHashFile() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("unable to determine config directory: %w", err)
	}

	if runtime.GOOS == "darwin" {
		homeDir, err := os.UserHomeDir()
		if err == nil {
			dotConfigDir := filepath.Join(homeDir, ".config")
			if info, err := os.Stat(dotConfigDir); err == nil && info.IsDir() {
				configDir = dotConfigDir
			}
		}
	}

	appConfigDir := filepath.Join(configDir, "password-cleaner")
	hashFilePath := filepath.Join(appConfigDir, "hashes.txt")

	return hashFilePath, nil
}

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("version: %s\n", version)
		fmt.Printf("commit: %s\n", commit)
		fmt.Printf("date: %s\n", date)
		fmt.Printf("builtBy: %s\n", builtBy)
		return
	}

	if len(flag.Args()) > 0 {
		if len(flag.Args()) > 1 {
			fmt.Fprintln(os.Stderr, "Error: only one password argument allowed")
			os.Exit(1)
		}
		password := flag.Args()[0]
		hash := hashString(password)
		fmt.Println(hash)
		return
	}

	hashFilePath := *hashFile
	if hashFilePath == "" {
		defaultPath, err := getDefaultHashFile()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			fmt.Fprintln(os.Stderr, "Please specify --hash-file explicitly")
			os.Exit(1)
		}

		if _, err := os.Stat(defaultPath); os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Error: default hash file not found: %s\n", defaultPath)
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "To create it:")
			fmt.Fprintf(os.Stderr, "  mkdir -p %s\n", filepath.Dir(defaultPath))
			fmt.Fprintf(os.Stderr, "  touch %s\n", defaultPath)
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "Then add hashes with:")
			fmt.Fprintf(os.Stderr, "  password-cleaner \"your-secret\" >> %s\n", defaultPath)
			fmt.Fprintln(os.Stderr, "")
			fmt.Fprintln(os.Stderr, "Or specify a custom hash file:")
			fmt.Fprintln(os.Stderr, "  password-cleaner --hash-file /path/to/hashes.txt")
			os.Exit(1)
		} else if err != nil {
			fmt.Fprintf(os.Stderr, "Error accessing default hash file %s: %v\n", defaultPath, err)
			fmt.Fprintln(os.Stderr, "Please specify --hash-file explicitly")
			os.Exit(1)
		}

		hashFilePath = defaultPath
		fmt.Fprintf(os.Stderr, "Using default hash file: %s\n", hashFilePath)
	}

	hashes, err := loadHashes(hashFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading hashes: %v\n", err)
		os.Exit(1)
	}

	if len(hashes) == 0 {
		fmt.Fprintln(os.Stderr, "Warning: hash file is empty, no filtering will occur")
	}

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := scanner.Text()

		if containsSensitiveData(line, hashes, *minLength) {
			fmt.Fprintln(os.Stderr, line)
		} else {
			fmt.Println(line)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error reading stdin: %v\n", err)
		os.Exit(1)
	}
}

func loadHashes(filepath string) (map[string]bool, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	hashes := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if len(line) != 64 {
			fmt.Fprintf(os.Stderr, "Warning: line %d in hash file has invalid length (expected 64 hex chars): %s\n", lineNum, line)
			continue
		}

		hashes[strings.ToLower(line)] = true
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return hashes, nil
}

func hashString(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func containsSensitiveData(line string, hashes map[string]bool, minLen int) bool {
	lineLen := len(line)

	for start := 0; start < lineLen; start++ {
		for end := start + minLen; end <= lineLen; end++ {
			substring := line[start:end]
			hash := hashString(substring)

			if hashes[hash] {
				return true
			}
		}
	}

	return false
}
