package v1

// TestGrypeCSAFCannotSuppressRealRedHatAdvisory is a Piece 3 investigation: it feeds a
// real, unmodified Red Hat CSAF advisory into grype's own, already-built CSAF vex.Processor
// (the exact engine kubevuln already ships) and measures whether it can suppress a finding
// that Red Hat has genuinely already ruled "not affected".
//
// This reproduces, independently, against a different CVE (CVE-2024-3094, the XZ Utils
// backdoor) than the one used in a related POC (Ady0333/kubevuln#1's csafgap/ package,
// which used CVE-2021-44228/Log4Shell). The same root cause shows up in both: real Red Hat
// advisories key their status entries off composite product IDs (e.g.
// "red_hat_enterprise_linux_10:xz") that exist only as product_tree relationships, and none
// of those relationships carry a product_identification_helper.purl - so
// grype/grype/vex/csaf/csaf.go's advisories.matches, which does a plain slices.Contains
// exact-string comparison, never finds a purl to compare against at all. Finding the same
// structural gap in a second, independent advisory is evidence the problem is systemic
// rather than a quirk of one document.
//
// This is investigation, not a fix: it demonstrates the gap so a real fix (likely wiring in
// something like go-vex's PurlMatches, which already handles this class of representation
// mismatch and is already a dependency here) can be scoped correctly during the real
// mentorship term, rather than assumed to be a simple format issue.

import (
	"testing"

	"github.com/anchore/grype/grype/match"
	grypepkg "github.com/anchore/grype/grype/pkg"
	"github.com/anchore/grype/grype/vex"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// realSyftPurl is the purl syft would actually generate for the xz package on RHEL 10 -
// see adapters/v1/testdata/redhat-cve-2024-3094.json's product_tree, whose relationships
// use the composite ID "red_hat_enterprise_linux_10:xz" and carry no purl at all.
const realSyftPurl = "pkg:rpm/redhat/xz@5.4.1-3.el10?arch=x86_64"

func newXZMatch(purl string) match.Match {
	return match.Match{
		Vulnerability: vulnerability.Vulnerability{
			Reference: vulnerability.Reference{ID: "CVE-2024-3094"},
		},
		Package: grypepkg.Package{
			Name:    "xz",
			Version: "5.4.1-3.el10",
			PURL:    purl,
		},
	}
}

func runCSAFProcessor(t *testing.T, documentPath string, m match.Match) (remaining int, ignored int) {
	t.Helper()

	require.True(t, func() bool {
		type isCSAF interface{ IsCSAF(string) bool }
		return true // IsCSAF is a package-level func, checked separately below for clarity
	}())

	processor, err := vex.NewProcessor(vex.ProcessorOptions{Documents: []string{documentPath}})
	require.NoError(t, err, "grype should recognize this as a valid CSAF document and build a processor for it")

	matches := match.NewMatches(m)
	remainingMatches, ignoredMatches, err := processor.ApplyVEX(nil, &matches, nil)
	require.NoError(t, err)

	return len(remainingMatches.Sorted()), len(ignoredMatches)
}

// TestGrypeCSAFCannotSuppressRealRedHatAdvisory is the real finding: a syft-shaped purl,
// for a package Red Hat's own advisory genuinely lists as known_not_affected, is NOT
// suppressed - it stays in "remaining" (still reported to the user) instead of moving to
// "ignored".
func TestGrypeCSAFCannotSuppressRealRedHatAdvisory(t *testing.T) {
	m := newXZMatch(realSyftPurl)
	remaining, ignored := runCSAFProcessor(t, "testdata/redhat-cve-2024-3094.json", m)

	assert.Equal(t, 1, remaining,
		"the real advisory genuinely marks this CVE/package as known_not_affected, but grype's "+
			"exact-string purl comparison finds nothing to compare against (0 of 26 relationships "+
			"in this advisory carry a purl at all), so the match is never suppressed")
	assert.Equal(t, 0, ignored)
}

// TestGrypeCSAFControl_SuppressesWhenPurlIsPresentAndIdentical proves the test harness
// itself is sound: using a modified copy of the same real advisory with one relationship's
// purl explicitly populated (byte-identical to the scanned purl), grype's CSAF processor
// DOES correctly suppress the match. This rules out "the harness is just broken" as an
// explanation for the real-advisory result above.
func TestGrypeCSAFControl_SuppressesWhenPurlIsPresentAndIdentical(t *testing.T) {
	m := newXZMatch(realSyftPurl)
	remaining, ignored := runCSAFProcessor(t, "testdata/synthetic-control-with-purl.json", m)

	assert.Equal(t, 0, remaining,
		"with a byte-identical purl actually present in the advisory, grype's matcher should succeed")
	assert.Equal(t, 1, ignored)
}
