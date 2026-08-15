package v1

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/openvex/go-vex/pkg/vex"

	"github.com/kubescape/kubevuln/internal/safefetch"
	vexsourcev1beta1 "github.com/kubescape/kubevuln/pkg/vexsource/v1beta1"
	storagev1beta1 "github.com/kubescape/storage/pkg/apis/softwarecomposition/v1beta1"
	spdxv1beta1 "github.com/kubescape/storage/pkg/generated/clientset/versioned/typed/softwarecomposition/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Errors returned by FetchVEXStatements.
var (
	// ErrUnsupportedFormat is returned for any VEXSource.Spec.Format other than
	// "openvex". CSAF parsing is real, separate work - see the package doc comment.
	ErrUnsupportedFormat = errors.New("vexsourcefetch: unsupported format")

	// ErrNotOpenVEX is returned when a fetched document does not carry a genuine
	// OpenVEX @context. A bare json.Unmarshal into vex.Document succeeds on any
	// valid JSON object, including an unrelated API response or an error page, so
	// this check is what actually distinguishes "fetched something" from "fetched
	// a real OpenVEX document" - the same gap independently found and fixed in
	// Ady0333/kubevuln#1's openvexfetch package.
	ErrNotOpenVEX = errors.New("vexsourcefetch: response is not a valid OpenVEX document")
)

// openVEXContext is the real, canonical @context value for OpenVEX documents, per the
// spec at https://openvex.dev/ns/v0.2.0/openvex.json. A document with any other (or
// missing) @context is not genuinely OpenVEX, regardless of whether it happens to
// parse as JSON.
const openVEXContext = "https://openvex.dev/ns/v0.2.0/openvex.json"

// FetchVEXStatements safely retrieves and parses the OpenVEX document declared by
// source, returning its statements. The fetch itself goes through fetcher (expected to
// be an internal/safefetch.Fetcher), so the same SSRF protections (HTTPS-only, private/
// loopback/link-local/metadata-endpoint blocking, DNS-rebinding protection, redirect
// re-validation) already proven for kubevuln's own backend communication apply here too.
//
// Only source.Spec.Format == "openvex" is supported. CSAF parsing is real, separate
// work - deliberately out of scope here, matching the same call made independently in
// Ady0333/kubevuln#1's own README.
func FetchVEXStatements(ctx context.Context, fetcher *safefetch.Fetcher, source vexsourcev1beta1.VEXSource) ([]vex.Statement, error) {
	if source.Spec.Format != vexsourcev1beta1.VEXSourceFormatOpenVEX {
		return nil, fmt.Errorf("%w: %q (only %q is supported)", ErrUnsupportedFormat, source.Spec.Format, vexsourcev1beta1.VEXSourceFormatOpenVEX)
	}

	raw, err := fetcher.Fetch(ctx, source.Spec.FeedURL)
	if err != nil {
		return nil, fmt.Errorf("vexsourcefetch: fetching %s: %w", source.Spec.FeedURL, err)
	}

	doc, err := parseOpenVEXDocument(raw)
	if err != nil {
		return nil, err
	}

	return doc.Statements, nil
}

// parseOpenVEXDocument parses raw as an OpenVEX document, first checking its @context
// strictly matches the real OpenVEX context locator. See ErrNotOpenVEX for why this
// check exists and cannot be skipped.
func parseOpenVEXDocument(raw []byte) (*vex.VEX, error) {
	doc, err := vex.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("vexsourcefetch: parsing response as OpenVEX: %w", err)
	}

	if doc.Context != openVEXContext {
		return nil, fmt.Errorf("%w: @context was %q, expected %q", ErrNotOpenVEX, doc.Context, openVEXContext)
	}

	return doc, nil
}

// convertStatement converts a fetched openvex/go-vex Statement into this repo's own
// storage/v1beta1.Statement shape, so it can be appended into an
// OpenVulnerabilityExchangeContainer's Spec.Statements alongside Kubescape's own,
// locally-generated statements.
//
// The two shapes are structurally very close (same field names, same nested
// Product/Subcomponent/Component pattern) - this is a field-by-field mapping, not a
// real translation layer, so there is little room for subtle semantic drift.
//
// s.ID is preserved as-is from the source document. As long as the real vendor feed
// does not use the "https://kubescape.io/vex/statement/" prefix (which no real external
// vendor would), repositories/apiserver.go's isLocalStatement will correctly treat this
// as an external statement - already covered by the external-statement hardening merged
// in #595, #633, #657, #661, #664, and #666, none of which this function needs to
// duplicate.
func convertStatement(s vex.Statement) storagev1beta1.Statement {
	aliases := make([]string, len(s.Vulnerability.Aliases))
	for i, a := range s.Vulnerability.Aliases {
		aliases[i] = string(a)
	}

	out := storagev1beta1.Statement{
		ID: s.ID,
		Vulnerability: storagev1beta1.VexVulnerability{
			ID:          s.Vulnerability.ID,
			Name:        string(s.Vulnerability.Name),
			Description: s.Vulnerability.Description,
			Aliases:     aliases,
		},
		Status:          storagev1beta1.Status(s.Status),
		StatusNotes:     s.StatusNotes,
		Justification:   storagev1beta1.Justification(s.Justification),
		ImpactStatement: s.ImpactStatement,
		ActionStatement: s.ActionStatement,
	}

	if s.Timestamp != nil {
		out.Timestamp = s.Timestamp.Format(time.RFC3339)
	}
	if s.LastUpdated != nil {
		out.LastUpdated = s.LastUpdated.Format(time.RFC3339)
	}
	if s.ActionStatementTimestamp != nil {
		out.ActionStatementTimestamp = s.ActionStatementTimestamp.Format(time.RFC3339)
	}

	out.Products = make([]storagev1beta1.Product, len(s.Products))
	for i, p := range s.Products {
		out.Products[i] = storagev1beta1.Product{
			Component: storagev1beta1.Component{ID: p.ID},
		}
		out.Products[i].Subcomponents = make([]storagev1beta1.Subcomponent, len(p.Subcomponents))
		for j, sc := range p.Subcomponents {
			out.Products[i].Subcomponents[j] = storagev1beta1.Subcomponent{
				Component: storagev1beta1.Component{ID: sc.ID},
			}
		}
	}

	return out
}

// PersistExternalStatement appends stmt into the OpenVulnerabilityExchangeContainer named
// containerName in namespace, creating the container if it does not yet exist.
//
// Matching a fetched statement to the correct target image(s) automatically - deciding
// which of potentially many scanned images a given VEXSource's statement applies to - is
// real, separate work left for later; containerName is accepted as a parameter here
// rather than derived, so this function does exactly one job (get-or-create, append,
// save) and can be tested and trusted independently of that harder matching problem.
//
// This mirrors the real get-or-create-then-Create-or-Update pattern already used by
// APIServerStore.StoreVEX/createVEX/updateVEX in repositories/apiserver.go, scoped down
// to a single external statement instead of a full scan reconciliation - those functions
// take a domain.CVEManifest and are not reusable here as-is.
func PersistExternalStatement(ctx context.Context, client spdxv1beta1.SpdxV1beta1Interface, namespace, containerName string, stmt storagev1beta1.Statement) error {
	existing, err := client.OpenVulnerabilityExchangeContainers(namespace).Get(ctx, containerName, metav1.GetOptions{})
	if err == nil {
		existing.Spec.Statements = append(existing.Spec.Statements, stmt)
		_, err = client.OpenVulnerabilityExchangeContainers(namespace).Update(ctx, existing, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("vexsourcefetch: updating container %s: %w", containerName, err)
		}
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return fmt.Errorf("vexsourcefetch: getting container %s: %w", containerName, err)
	}

	container := &storagev1beta1.OpenVulnerabilityExchangeContainer{
		ObjectMeta: metav1.ObjectMeta{
			Name: containerName,
		},
		Spec: storagev1beta1.VEX{
			Statements: []storagev1beta1.Statement{stmt},
		},
	}
	if _, err := client.OpenVulnerabilityExchangeContainers(namespace).Create(ctx, container, metav1.CreateOptions{}); err != nil {
		return fmt.Errorf("vexsourcefetch: creating container %s: %w", containerName, err)
	}
	return nil
}
