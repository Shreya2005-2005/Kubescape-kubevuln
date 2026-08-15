package v1beta1

import (
	"errors"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// VEXSourceFormat identifies the wire format an external VEX feed is published in.
type VEXSourceFormat string

const (
	VEXSourceFormatOpenVEX VEXSourceFormat = "openvex"
	VEXSourceFormatCSAF    VEXSourceFormat = "csaf"
)

// VEXSourceConditionType is the vocabulary for VEXSourceStatus.Conditions[].Type.
type VEXSourceConditionType string

const (
	// VEXSourceConditionReady means the feed was fetched and parsed successfully at least once.
	VEXSourceConditionReady VEXSourceConditionType = "Ready"
	// VEXSourceConditionStale means the feed has not been successfully refreshed within
	// its RefreshInterval.
	VEXSourceConditionStale VEXSourceConditionType = "Stale"
)

// VEXSource declares an external VEX feed to fetch and apply against scan results.
//
// This type intentionally mirrors pkg/securityexception/v1beta1.SecurityException: a plain
// struct with no scheme registration, read via the dynamic client as unstructured, not a
// registered, code-generated API type. That is the real, existing convention in this repo
// for this kind of lightweight custom resource.
//
// NOTE ON VALIDATION: the +kubebuilder markers below generate a real CRD manifest -
// see pkg/vexsource/crds/kubescape.io_vexsources.yaml, produced by running
// `controller-gen crd paths=./pkg/vexsource/v1beta1/... output:crd:dir=./pkg/vexsource/crds`.
// That manifest is valid and installable as-is (kubectl apply -f it against a real
// cluster registers the type correctly - group kubescape.io/v1beta1, matching the same
// group repositories/apiserver.go's securityExceptionGVR already uses).
//
// What is NOT done: this manifest is not wired into any install path (this repo,
// kubescape/helm-charts, or kubescape/kubescape). kubescape/kubescape previously carried
// a hand-maintained CRD for SecurityException that was removed for being orphaned and
// uninstallable for exactly that reason - generating the file is necessary but not
// sufficient; wiring it into a real install path is separate, real work left for later.
// +kubebuilder:resource:scope=Namespaced,shortName=vexsrc
// +kubebuilder:printcolumn:name="Format",type=string,JSONPath=`.spec.format`
// +kubebuilder:printcolumn:name="URL",type=string,JSONPath=`.spec.feedURL`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
type VEXSource struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   VEXSourceSpec   `json:"spec,omitempty"`
	Status VEXSourceStatus `json:"status,omitempty"`
}

// VEXSourceList is a list of VEXSource resources.
type VEXSourceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`

	Items []VEXSource `json:"items"`
}

// VEXSourceSpec defines the desired state of a VEXSource.
type VEXSourceSpec struct {
	// FeedURL is the HTTPS address the fetcher retrieves the VEX document from.
	// +kubebuilder:validation:Pattern=`^https://`
	FeedURL string `json:"feedURL"`

	// Format is the wire format of the document at FeedURL.
	// +kubebuilder:validation:Enum=openvex;csaf
	Format VEXSourceFormat `json:"format"`

	// ImageMatch scopes this feed to specific images, as Go path.Match glob patterns
	// (e.g. "docker.io/library/nginx*", "*.redhat.io/*") evaluated against the full
	// image reference. An empty list means the feed is considered for every scanned
	// image - MinItems=1 below exists so an accidentally-empty list fails loudly at
	// apply time instead of silently matching everything.
	// +kubebuilder:validation:MinItems=1
	ImageMatch []string `json:"imageMatch,omitempty"`

	// RefreshInterval is how often the feed should be re-fetched. Empty means the
	// default below applies.
	// +kubebuilder:default="6h"
	RefreshInterval metav1.Duration `json:"refreshInterval,omitempty"`
}

// VEXSourceStatus reports the observed state of a VEXSource's fetch history.
//
// This is modeled after a real gap identified while reading a related POC (Ady0333/kubevuln#1):
// a feed that starts failing silently is worse than one that was never configured, so the
// fetcher (a later piece, not this one) needs somewhere to honestly record what happened on
// its last attempt.
type VEXSourceStatus struct {
	// Conditions is the observed state, using VEXSourceConditionType values.
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastFetchTime is when the fetcher last attempted to retrieve this feed, successful or not.
	LastFetchTime *metav1.Time `json:"lastFetchTime,omitempty"`

	// LastSuccessTime is when the fetcher last successfully retrieved and parsed this feed.
	LastSuccessTime *metav1.Time `json:"lastSuccessTime,omitempty"`

	// LastError is the error message from the most recent failed fetch attempt, if any.
	// Cleared on the next successful fetch.
	LastError string `json:"lastError,omitempty"`
}

// Errors returned by VEXSourceSpec.Validate.
var (
	ErrEmptyFeedURL            = errors.New("vexsource: feedURL must not be empty")
	ErrInvalidFeedURL          = errors.New("vexsource: feedURL must start with https://")
	ErrInvalidFormat           = errors.New("vexsource: format must be \"openvex\" or \"csaf\"")
	ErrEmptyImageMatch         = errors.New("vexsource: imageMatch must have at least one entry")
	ErrNegativeRefreshInterval = errors.New("vexsource: refreshInterval must not be negative")
	ErrZeroRefreshInterval     = errors.New("vexsource: refreshInterval must not be zero")
)

// Validate checks that s is well-formed: FeedURL is a non-empty https:// address, and
// Format is one of the two supported values. This enforces, in Go, the same constraints
// described by the +kubebuilder markers on VEXSourceSpec's fields above - see the NOTE ON
// VALIDATION comment on VEXSource for why those markers alone do not currently enforce
// anything on their own.
func (s VEXSourceSpec) Validate() error {
	if s.FeedURL == "" {
		return ErrEmptyFeedURL
	}
	if !strings.HasPrefix(s.FeedURL, "https://") {
		return ErrInvalidFeedURL
	}
	switch s.Format {
	case VEXSourceFormatOpenVEX, VEXSourceFormatCSAF:
		// valid
	default:
		return ErrInvalidFormat
	}
	if len(s.ImageMatch) == 0 {
		return ErrEmptyImageMatch
	}
	if s.RefreshInterval.Duration < 0 {
		return ErrNegativeRefreshInterval
	}
	if s.RefreshInterval.Duration == 0 {
		return ErrZeroRefreshInterval
	}
	return nil
}
