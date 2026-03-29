package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
)

var (
	version = "0.0.1"
	commit  = "HEAD"
	date    = "now"
	builtBy = "dev"
)

var (
	hashFile    = flag.String("hash-file", "", "Path to file containing SHA-256 hashes (one per line)")
	minLength   = flag.Int("min-length", 8, "Minimum substring length to check")
	showVersion = flag.Bool("version", false, "Show version information")
)

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

	if *hashFile == "" {
		fmt.Fprintln(os.Stderr, "Error: --hash-file is required")
		flag.Usage()
		os.Exit(1)
	}

	hashes, err := loadHashes(*hashFile)
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
	defer file.Close()

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
