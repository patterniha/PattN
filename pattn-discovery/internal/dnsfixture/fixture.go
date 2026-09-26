package dnsfixture

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"pattn-discovery/internal/dnswire"
)

const (
	CaptureKindCaptured  = "captured"
	CaptureKindSynthetic = "synthetic"
)

type Fixture struct {
	Name          string `json:"name"`
	CaptureKind   string `json:"captureKind"`
	Source        string `json:"source"`
	CapturedAt    string `json:"capturedAt,omitempty"`
	QueryName     string `json:"queryName"`
	QueryType     uint16 `json:"queryType"`
	TransactionID uint16 `json:"transactionId"`
	PacketHex     string `json:"packetHex"`
	SHA256        string `json:"sha256"`
	Notes         string `json:"notes,omitempty"`
}

func NewCaptured(
	name, source string,
	capturedAt time.Time,
	queryName string,
	queryType, transactionID uint16,
	packet []byte,
	notes string,
) (Fixture, error) {
	if len(packet) == 0 {
		return Fixture{}, fmt.Errorf("captured dns packet is empty")
	}
	sum := sha256.Sum256(packet)
	fixture := Fixture{
		Name:          strings.TrimSpace(name),
		CaptureKind:   CaptureKindCaptured,
		Source:        strings.TrimSpace(source),
		CapturedAt:    capturedAt.UTC().Format(time.RFC3339),
		QueryName:     strings.TrimSpace(queryName),
		QueryType:     queryType,
		TransactionID: transactionID,
		PacketHex:     hex.EncodeToString(packet),
		SHA256:        fmt.Sprintf("%x", sum),
		Notes:         strings.TrimSpace(notes),
	}
	if err := fixture.Validate(); err != nil {
		return Fixture{}, err
	}
	return fixture, nil
}

func Load(path string) (Fixture, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Fixture{}, err
	}
	var fixture Fixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		return Fixture{}, fmt.Errorf("decode dns fixture: %w", err)
	}
	if err := fixture.Validate(); err != nil {
		return Fixture{}, err
	}
	return fixture, nil
}

func (f Fixture) Save(path string) error {
	if err := f.Validate(); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0o644)
}

func (f Fixture) Validate() error {
	if strings.TrimSpace(f.Name) == "" {
		return fmt.Errorf("dns fixture name is required")
	}
	switch f.CaptureKind {
	case CaptureKindCaptured, CaptureKindSynthetic:
	default:
		return fmt.Errorf("dns fixture captureKind must be %q or %q", CaptureKindCaptured, CaptureKindSynthetic)
	}
	if strings.TrimSpace(f.Source) == "" {
		return fmt.Errorf("dns fixture source is required")
	}
	if f.CaptureKind == CaptureKindCaptured {
		if strings.TrimSpace(f.CapturedAt) == "" {
			return fmt.Errorf("captured dns fixtures require capturedAt")
		}
		if _, err := time.Parse(time.RFC3339, f.CapturedAt); err != nil {
			return fmt.Errorf("invalid dns fixture capturedAt: %w", err)
		}
	}
	if strings.TrimSpace(f.QueryName) == "" {
		return fmt.Errorf("dns fixture queryName is required")
	}
	if f.QueryType == 0 {
		return fmt.Errorf("dns fixture queryType is required")
	}
	if strings.TrimSpace(f.PacketHex) == "" {
		return fmt.Errorf("dns fixture packetHex is required")
	}
	digest, err := hex.DecodeString(strings.TrimSpace(f.SHA256))
	if err != nil || len(digest) != sha256.Size {
		return fmt.Errorf("dns fixture sha256 must be a 32-byte hex digest")
	}
	return nil
}

func (f Fixture) Packet() ([]byte, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	packetHex := strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\n', '\r', '\t':
			return -1
		default:
			return r
		}
	}, f.PacketHex)
	packet, err := hex.DecodeString(packetHex)
	if err != nil {
		return nil, fmt.Errorf("decode dns fixture packet hex: %w", err)
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(packet))
	if !strings.EqualFold(sum, f.SHA256) {
		return nil, fmt.Errorf("dns fixture sha256 mismatch: got %s want %s", sum, f.SHA256)
	}
	return packet, nil
}

func (f Fixture) Replay() (dnswire.Message, error) {
	packet, err := f.Packet()
	if err != nil {
		return dnswire.Message{}, err
	}
	return dnswire.ParseMessage(packet, f.TransactionID, f.QueryName, f.QueryType)
}
