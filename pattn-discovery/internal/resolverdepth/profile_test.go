package resolverdepth

import "testing"

func TestDecodeTXTMultipleSegments(t *testing.T) {
	got := decodeTXT([]byte{3, 'o', 'n', 'e', 3, 't', 'w', 'o'})
	if len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("got=%v", got)
	}
}

func TestRunProbeRequiresQuorumAndUsesMedian(t *testing.T) {
	values := []Attempt{
		{Responded: true, LatencyMs: 30, AnswerSignature: "A"},
		{Responded: true, LatencyMs: 10, AnswerSignature: "A"},
		{Responded: false, Error: "timeout"},
	}
	index := 0
	got := runProbe(Options{Attempts: 3, MinimumSuccesses: 2}, "udp", func() Attempt {
		value := values[index]
		index++
		return value
	})
	if !got.QuorumMet || got.Successes != 2 || got.Reliability != 2.0/3.0 || got.MedianLatencyMs != 20 {
		t.Fatalf("got=%+v", got)
	}
}

func TestDeriveEncryptedComparisonFlagsCrossTransportDivergence(t *testing.T) {
	classic := &Probe{QuorumMet: true, AnswerSignature: "A"}
	encrypted := &Probe{QuorumMet: true, AnswerSignature: "B"}
	agree := true
	result := Result{UDP: classic, TCP: classic, DoT: encrypted, DoH: encrypted, UDPAndTCPAgree: &agree}
	deriveEncryptedComparison(&result)
	if result.ClassicEncryptedAgree == nil || *result.ClassicEncryptedAgree || !result.InterceptionSuspected {
		t.Fatalf("result=%+v", result)
	}
	if len(result.InterceptionReasons) < 2 {
		t.Fatalf("reasons=%v", result.InterceptionReasons)
	}
}

func TestTlsVersionName(t *testing.T) {
	if tlsVersionName(0x0304) != "TLS1.3" || tlsVersionName(0x0303) != "TLS1.2" {
		t.Fatal("unexpected TLS version mapping")
	}
}


func TestDeriveQualityMarksStrongWhenEncryptedAndClassicAgree(t *testing.T) {
	agree := true
	result := Result{
		UDP: &Probe{Attempted: true, QuorumMet: true, Reliability: 1, AnswerSignature: "A"},
		TCP: &Probe{Attempted: true, QuorumMet: true, Reliability: 1, AnswerSignature: "A"},
		DoT: &Probe{Attempted: true, QuorumMet: true, Reliability: 1, AnswerSignature: "A"},
		DoH: &Probe{Attempted: true, QuorumMet: true, Reliability: 1, AnswerSignature: "A"},
		UDPAndTCPAgree: &agree,
		ClassicEncryptedAgree: &agree,
		EncryptedDNS: true,
		QuorumTransportCount: 4,
	}
	deriveQuality(&result)
	if result.Quality != "strong" || result.ReliabilityFloor != 1 {
		t.Fatalf("result=%+v", result)
	}
}

func TestDeriveQualityNeverHidesInterceptionSuspicion(t *testing.T) {
	result := Result{
		UDP: &Probe{Attempted: true, QuorumMet: true, Reliability: 1},
		DoH: &Probe{Attempted: true, QuorumMet: true, Reliability: 1},
		InterceptionSuspected: true,
		InterceptionReasons: []string{"classic-encrypted-answer-divergence"},
		QuorumTransportCount: 2,
	}
	deriveQuality(&result)
	if result.Quality != "suspicious" {
		t.Fatalf("result=%+v", result)
	}
}


func TestEncryptedInternalDivergenceDoesNotCreateCrossTransportBaseline(t *testing.T) {
	classic := &Probe{QuorumMet: true, AnswerSignature: "A"}
	result := Result{
		UDP: classic,
		TCP: classic,
		DoT: &Probe{QuorumMet: true, AnswerSignature: "B"},
		DoH: &Probe{QuorumMet: true, AnswerSignature: "C"},
	}
	deriveEncryptedComparison(&result)
	if result.ClassicEncryptedAgree != nil || result.InterceptionSuspected {
		t.Fatalf("result=%+v", result)
	}
	found := false
	for _, reason := range result.InterceptionReasons {
		if reason == "encrypted-transports-diverge" {
			found = true
		}
	}
	if !found {
		t.Fatalf("reasons=%v", result.InterceptionReasons)
	}
}
