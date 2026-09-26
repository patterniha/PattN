package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type report struct {
	Root       string   `json:"root"`
	Entries    int      `json:"entries"`
	Bytes      int64    `json:"bytes"`
	Duplicates []string `json:"duplicates,omitempty"`
	Errors     []string `json:"errors,omitempty"`
}

func main() {
	root := flag.String("root", ".", "repository/module root to audit")
	maxBytes := flag.Int64("max-entry-bytes", 256*1024, "maximum committed fuzz corpus entry size")
	flag.Parse()

	result := report{Root: *root}
	seen := map[[32]byte]string{}
	err := filepath.WalkDir(*root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", path, walkErr))
			return nil
		}
		if entry.IsDir() || !strings.Contains(filepath.ToSlash(path), "/testdata/fuzz/") {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", path, err))
			return nil
		}
		if info.Size() > *maxBytes {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %d bytes exceeds limit %d", path, info.Size(), *maxBytes))
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", path, err))
			return nil
		}
		if !strings.HasPrefix(string(raw), "go test fuzz v1\n") {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: invalid Go fuzz corpus header", path))
			return nil
		}
		sum := sha256.Sum256(raw)
		if previous, ok := seen[sum]; ok {
			result.Duplicates = append(result.Duplicates, previous+" == "+path)
		} else {
			seen[sum] = path
		}
		result.Entries++
		result.Bytes += info.Size()
		return nil
	})
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
	}
	sort.Strings(result.Errors)
	sort.Strings(result.Duplicates)
	encoded, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(encoded))
	if len(result.Errors) > 0 || len(result.Duplicates) > 0 {
		os.Exit(1)
	}
}
