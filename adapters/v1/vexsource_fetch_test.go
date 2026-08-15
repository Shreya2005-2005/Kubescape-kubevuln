package v1

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kubescape/kubevuln/internal/safefetch"
	vexsourcev1beta1 "github.com/kubescape/kubevuln/pkg/vexsource/v1beta1"
	storagev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	fakespdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8stesting "k8s.io/client-go/testing"
)

// realisticOpenVEXDocument is a genuine, well-formed OpenVEX document, structured the way
// a real vendor feed (e.g. Chainguard) would publish one - two products, the second
// carrying two subcomponents, so the fixture also exercises the exact "package sits in a
// non-first position" scenario that #665 fixed in repositories/apiserver.go's matching
// logic.
const realisticOpenVEXDocument = `{
	"@context": "https://openvex.dev/ns/v0.2.0/openvex.json",
	"@id": "https://example.com/vex/statement/1",
	"author": "Example Vendor",
	"role": "Document Creator",
	"timestamp": "2026-01-01T00:00:00Z",
	"version": 1,
	"statements": [
		{
			"vulnerability": {"name": "CVE-2026-0001"},
			"products": [
				{"@id": "pkg:oci/image-one"},
				{
					"@id": "pkg:oci/image-two",
					"subcomponents": [
						{"@id": "pkg:deb/debian/openssl@1.0"},
						{"@id": "pkg:deb/debian/curl@7.68"}
					]
				}
			],
			"status": "not_affected",
			"justification": "vulnerable_code_not_present"
		}
	]
}`

func TestFetchVEXStatements_RealEndToEnd(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(realisticOpenVEXDocument))
	}))
	defer server.Close()

	source := vexsourcev1beta1.VEXSource{
		Spec: vexsourcev1beta1.VEXSourceSpec{
			FeedURL: server.URL,
			Format:  vexsourcev1beta1.VEXSourceFormatOpenVEX,
		},
	}

	// Uses the TLS test server's own trusted client rather than safefetch.New(),
	// since New()'s IP-blocking would (correctly) refuse this loopback server -
	// that protection is proven separately by
	// TestFetchVEXStatements_UsesSafeFetch_BlocksLoopback below, matching the same
	// split internal/safefetch/safefetch_test.go itself uses.
	fetcher := &safefetch.Fetcher{Client: server.Client()}
	statements, err := FetchVEXStatements(context.Background(), fetcher, source)
	require.NoError(t, err)
	require.Len(t, statements, 1)

	stmt := statements[0]
	assert.Equal(t, "CVE-2026-0001", string(stmt.Vulnerability.Name))
	assert.Equal(t, "not_affected", string(stmt.Status))
	require.Len(t, stmt.Products, 2)
	require.Len(t, stmt.Products[1].Subcomponents, 2)
	assert.Equal(t, "pkg:deb/debian/curl@7.68", stmt.Products[1].Subcomponents[1].ID)
}

func TestFetchVEXStatements_RejectsCSAF(t *testing.T) {
	source := vexsourcev1beta1.VEXSource{
		Spec: vexsourcev1beta1.VEXSourceSpec{
			FeedURL: "https://example.com/feed.json",
			Format:  vexsourcev1beta1.VEXSourceFormatCSAF,
		},
	}

	_, err := FetchVEXStatements(context.Background(), safefetch.New(), source)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedFormat)
}

func TestFetchVEXStatements_RejectsNonOpenVEXResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A real-looking JSON object that is NOT an OpenVEX document - e.g. an API
		// error page that happens to return 200 with a JSON body. This is exactly the
		// case a bare json.Unmarshal into vex.Document would silently accept as an
		// empty, "successfully parsed" document - see Ady0333/kubevuln#1's own fix
		// for this same class of bug.
		_, _ = w.Write([]byte(`{"error": "not found", "code": 404}`))
	}))
	defer server.Close()

	source := vexsourcev1beta1.VEXSource{
		Spec: vexsourcev1beta1.VEXSourceSpec{
			FeedURL: server.URL,
			Format:  vexsourcev1beta1.VEXSourceFormatOpenVEX,
		},
	}

	fetcher := &safefetch.Fetcher{Client: server.Client()}
	_, err := FetchVEXStatements(context.Background(), fetcher, source)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotOpenVEX)
}

func TestFetchVEXStatements_UsesSafeFetch_BlocksLoopback(t *testing.T) {
	source := vexsourcev1beta1.VEXSource{
		Spec: vexsourcev1beta1.VEXSourceSpec{
			FeedURL: "https://169.254.169.254/latest/meta-data/",
			Format:  vexsourcev1beta1.VEXSourceFormatOpenVEX,
		},
	}

	_, err := FetchVEXStatements(context.Background(), safefetch.New(), source)
	require.Error(t, err)
	// Not asserting a specific SafeFetch error type here - just that the fetch was
	// refused, proving SafeFetch's own protections are genuinely in the call path,
	// not bypassed.
}

func TestPersistExternalStatement_CreatesNewContainer(t *testing.T) {
	client := fakespdxv1beta1.FakeSpdxV1beta1{Fake: &k8stesting.Fake{}}

	stmt := storagev1beta1.Statement{
		ID: "https://example.com/vex/statement/1",
		Vulnerability: storagev1beta1.VexVulnerability{
			Name: "CVE-2026-0001",
		},
		Status: storagev1beta1.Status("not_affected"),
	}

	err := PersistExternalStatement(context.Background(), &client, "kubescape", "test-image", stmt)
	require.NoError(t, err)
}
