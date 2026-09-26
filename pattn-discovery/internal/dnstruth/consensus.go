package dnstruth

import (
	"sort"
	"strings"
)

type SourceKind string

const (
	SourceAuthoritative SourceKind = "authoritative"
	SourceTrusted       SourceKind = "trusted-resolver"
	SourceCandidate     SourceKind = "candidate-resolver"
	SourceSystem        SourceKind = "system-resolver"
)

type Observation struct {
	Source    string     `json:"source"`
	Kind      SourceKind `json:"kind"`
	Signature string     `json:"signature,omitempty"`
	Error     string     `json:"error,omitempty"`
}

type AgreementGroup struct {
	Signature          string   `json:"signature"`
	Count              int      `json:"count"`
	AuthoritativeCount int      `json:"authoritativeCount"`
	Sources            []string `json:"sources"`
}

type Consensus struct {
	EvidenceCount      int              `json:"evidenceCount"`
	ValidEvidenceCount int              `json:"validEvidenceCount"`
	Groups             []AgreementGroup `json:"groups,omitempty"`
	DominantSignature  string           `json:"dominantSignature,omitempty"`
	DominantCount      int              `json:"dominantCount,omitempty"`
	Unanimous          bool             `json:"unanimous"`
	Divergent          bool             `json:"divergent"`
}

func Aggregate(observations []Observation) Consensus {
	result := Consensus{EvidenceCount: len(observations)}
	type groupState struct {
		count         int
		authoritative int
		sources       []string
	}
	groups := make(map[string]*groupState)
	for _, observation := range observations {
		signature := strings.TrimSpace(observation.Signature)
		if signature == "" || strings.TrimSpace(observation.Error) != "" {
			continue
		}
		result.ValidEvidenceCount++
		state := groups[signature]
		if state == nil {
			state = &groupState{}
			groups[signature] = state
		}
		state.count++
		if observation.Kind == SourceAuthoritative {
			state.authoritative++
		}
		state.sources = append(state.sources, observation.Source)
	}
	for signature, state := range groups {
		sort.Strings(state.sources)
		result.Groups = append(result.Groups, AgreementGroup{
			Signature: signature,
			Count: state.count,
			AuthoritativeCount: state.authoritative,
			Sources: append([]string(nil), state.sources...),
		})
	}
	sort.Slice(result.Groups, func(i, j int) bool {
		if result.Groups[i].Count != result.Groups[j].Count {
			return result.Groups[i].Count > result.Groups[j].Count
		}
		if result.Groups[i].AuthoritativeCount != result.Groups[j].AuthoritativeCount {
			return result.Groups[i].AuthoritativeCount > result.Groups[j].AuthoritativeCount
		}
		return result.Groups[i].Signature < result.Groups[j].Signature
	})
	if len(result.Groups) > 0 {
		result.DominantSignature = result.Groups[0].Signature
		result.DominantCount = result.Groups[0].Count
	}
	result.Unanimous = result.ValidEvidenceCount > 0 && len(result.Groups) == 1
	result.Divergent = len(result.Groups) > 1
	return result
}
