package dnsfixture

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type CorpusAudit struct {
	Root              string   `json:"root"`
	Fixtures          int      `json:"fixtures"`
	CapturedFixtures  int      `json:"capturedFixtures"`
	SyntheticFixtures int      `json:"syntheticFixtures"`
	Manifests         int      `json:"manifests"`
	Bundles           int      `json:"bundles"`
	SemanticReplays   int      `json:"semanticReplays"`
	OrphanFixtures    []string `json:"orphanFixtures,omitempty"`
	Errors            []string `json:"errors,omitempty"`
}

func AuditDirectory(root string) CorpusAudit {
	result := CorpusAudit{Root: root}
	root = filepath.Clean(strings.TrimSpace(root))
	if root == "." || root == "" {
		result.Errors = append(result.Errors, "dns fixture audit root is required")
		return result
	}

	info, err := os.Stat(root)
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return result
	}
	if !info.IsDir() {
		result.Errors = append(result.Errors, "dns fixture audit root must be a directory")
		return result
	}

	fixturePaths := map[string]bool{}
	referenced := map[string]bool{}

	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", path, walkErr))
			return nil
		}
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
			return nil
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", path, err))
			return nil
		}
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(raw, &probe); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: invalid json: %v", path, err))
			return nil
		}

		switch {
		case probe["captureKind"] != nil && probe["packetHex"] != nil:
			fixture, err := Load(path)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", path, err))
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			fixturePaths[rel] = true
			result.Fixtures++
			if fixture.CaptureKind == CaptureKindCaptured {
				result.CapturedFixtures++
			} else if fixture.CaptureKind == CaptureKindSynthetic {
				result.SyntheticFixtures++
			}

		case probe["entries"] != nil:
			manifest, err := LoadManifest(path)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", path, err))
				return nil
			}
			replays, err := ReplayManifest(path)
			if err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", path, err))
				return nil
			}
			result.Manifests++
			result.SemanticReplays += len(replays)
			base := filepath.Dir(path)
			for _, item := range manifest.Entries {
				full := filepath.Join(base, filepath.Clean(item.Path))
				rel, err := filepath.Rel(root, full)
				if err == nil {
					referenced[filepath.ToSlash(rel)] = true
				}
			}

		case probe["rootServers"] != nil && probe["exchanges"] != nil:
			if _, err := LoadExchangeBundle(path); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", path, err))
				return nil
			}
			var bundle ExchangeBundle
			if err := json.Unmarshal(raw, &bundle); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", path, err))
				return nil
			}
			result.Bundles++
			base := filepath.Dir(path)
			for _, step := range bundle.Exchanges {
				full := filepath.Join(base, filepath.Clean(step.Fixture))
				rel, err := filepath.Rel(root, full)
				if err == nil {
					referenced[filepath.ToSlash(rel)] = true
				}
			}

		default:
			result.Errors = append(result.Errors, fmt.Sprintf("%s: unrecognized dns fixture json document", path))
		}
		return nil
	})

	for path := range fixturePaths {
		if !referenced[path] {
			result.OrphanFixtures = append(result.OrphanFixtures, path)
		}
	}
	sort.Strings(result.OrphanFixtures)
	sort.Strings(result.Errors)
	return result
}
