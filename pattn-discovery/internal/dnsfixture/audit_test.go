package dnsfixture

import "testing"

func TestAuditDirectoryValidatesCommittedCorpus(t *testing.T) {
	audit := AuditDirectory("testdata")
	if len(audit.Errors) != 0 {
		t.Fatalf("errors=%v", audit.Errors)
	}
	if audit.Fixtures != 2 || audit.SyntheticFixtures != 2 || audit.CapturedFixtures != 0 {
		t.Fatalf("fixture counts=%+v", audit)
	}
	if audit.Manifests != 1 || audit.Bundles != 1 || audit.SemanticReplays != 2 {
		t.Fatalf("document counts=%+v", audit)
	}
	if len(audit.OrphanFixtures) != 0 {
		t.Fatalf("orphans=%v", audit.OrphanFixtures)
	}
}

func TestAuditDirectoryRejectsMissingRoot(t *testing.T) {
	audit := AuditDirectory("testdata/does-not-exist")
	if len(audit.Errors) == 0 {
		t.Fatal("expected missing-root error")
	}
}
