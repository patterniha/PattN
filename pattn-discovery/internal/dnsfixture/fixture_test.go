package dnsfixture

import (
	"strings"
	"testing"
	"time"

	"pattn-discovery/internal/dnswire"
)

func TestLoadAndReplaySyntheticSeed(t *testing.T) {
	fixture, err := Load("testdata/example-a.synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	message, err := fixture.Replay()
	if err != nil {
		t.Fatal(err)
	}
	if fixture.CaptureKind != CaptureKindSynthetic || len(message.Answers) != 1 {
		t.Fatalf("fixture=%+v answers=%d", fixture, len(message.Answers))
	}
	answer := message.Answers[0]
	if answer.Type != dnswire.TypeA || answer.Address.String() != "93.184.216.34" {
		t.Fatalf("answer=%+v", answer)
	}
}

func TestNewCapturedPreservesProvenanceAndReplays(t *testing.T) {
	seed, err := Load("testdata/example-a.synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	packet, err := seed.Packet()
	if err != nil {
		t.Fatal(err)
	}
	capturedAt := time.Date(2026, 9, 23, 18, 0, 0, 0, time.UTC)
	captured, err := NewCaptured(
		"example capture",
		"udp://192.0.2.53:53",
		capturedAt,
		seed.QueryName,
		seed.QueryType,
		seed.TransactionID,
		packet,
		"test capture wrapper",
	)
	if err != nil {
		t.Fatal(err)
	}
	if captured.CaptureKind != CaptureKindCaptured || captured.CapturedAt != capturedAt.Format(time.RFC3339) {
		t.Fatalf("captured=%+v", captured)
	}
	if _, err := captured.Replay(); err != nil {
		t.Fatal(err)
	}
}

func TestPacketRejectsHashMismatch(t *testing.T) {
	fixture, err := Load("testdata/example-a.synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	fixture.SHA256 = strings.Repeat("0", 64)
	if _, err := fixture.Packet(); err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("err=%v", err)
	}
}

func TestCapturedFixtureRequiresTimestamp(t *testing.T) {
	fixture := Fixture{
		Name: "capture",
		CaptureKind: CaptureKindCaptured,
		Source: "pcap extraction",
		QueryName: "example.com",
		QueryType: dnswire.TypeA,
		PacketHex: "00",
		SHA256: strings.Repeat("0", 64),
	}
	if err := fixture.Validate(); err == nil || !strings.Contains(err.Error(), "capturedAt") {
		t.Fatalf("err=%v", err)
	}
}
