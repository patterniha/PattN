package main

import (
	"crypto/sha256"
	"go/ast"
	"go/parser"
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
		if err := validateCorpusEntry(path, raw); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", path, err))
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


var fuzzTargetArgCounts = map[string]int{
	"FuzzParseMessage":     1,
	"FuzzReadName":         2,
	"FuzzParseDNSSECRData": 2,
	"FuzzDnameSynthesis":   3,
	"FuzzNDJSONFraming":    1,
}

func validateCorpusEntry(path string, raw []byte) error {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")
	text = strings.TrimSuffix(text, "\n")
	lines := strings.Split(text, "\n")
	if len(lines) == 0 || lines[0] != "go test fuzz v1" {
		return fmt.Errorf("invalid Go fuzz corpus header")
	}

	target := filepath.Base(filepath.Dir(path))
	want, ok := fuzzTargetArgCounts[target]
	if !ok {
		return fmt.Errorf("unknown fuzz target %q", target)
	}
	values := lines[1:]
	if len(values) != want {
		return fmt.Errorf("fuzz target %s requires %d argument(s), corpus entry has %d", target, want, len(values))
	}
	for i, value := range values {
		if err := validateFuzzValue(value); err != nil {
			return fmt.Errorf("argument %d: %w", i+1, err)
		}
	}
	return nil
}

func validateFuzzValue(value string) error {
	expr, err := parser.ParseExpr(strings.TrimSpace(value))
	if err != nil {
		return fmt.Errorf("invalid Go fuzz value: %w", err)
	}
	call, ok := expr.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return fmt.Errorf("fuzz value must be a single supported type conversion")
	}

	supportedScalar := map[string]bool{
		"string": true, "bool": true, "byte": true, "rune": true,
		"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
		"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true,
		"float32": true, "float64": true,
	}
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		if !supportedScalar[fun.Name] {
			return fmt.Errorf("unsupported fuzz value type %q", fun.Name)
		}
	case *ast.ArrayType:
		elt, ok := fun.Elt.(*ast.Ident)
		if fun.Len != nil || !ok || elt.Name != "byte" {
			return fmt.Errorf("only []byte slice fuzz values are supported")
		}
	default:
		return fmt.Errorf("unsupported fuzz value conversion")
	}

	switch arg := call.Args[0].(type) {
	case *ast.BasicLit:
		return nil
	case *ast.Ident:
		if arg.Name == "true" || arg.Name == "false" {
			return nil
		}
	case *ast.UnaryExpr:
		if _, ok := arg.X.(*ast.BasicLit); ok {
			return nil
		}
	}
	return fmt.Errorf("unsupported fuzz value literal")
}
