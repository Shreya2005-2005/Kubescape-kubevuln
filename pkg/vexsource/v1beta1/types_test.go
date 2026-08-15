package v1beta1

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestVEXSourceSpec_Validate(t *testing.T) {
	tests := []struct {
		name    string
		spec    VEXSourceSpec
		wantErr error
	}{
		{
			name: "valid openvex spec",
			spec: VEXSourceSpec{
				FeedURL:         "https://chainguard.dev/vex/feed.json",
				Format:          VEXSourceFormatOpenVEX,
				ImageMatch:      []string{"*"},
				RefreshInterval: metav1.Duration{Duration: 6 * time.Hour},
			},
			wantErr: nil,
		},
		{
			name: "valid csaf spec",
			spec: VEXSourceSpec{
				FeedURL:         "https://access.redhat.com/security/data/csaf/v2/feed.json",
				Format:          VEXSourceFormatCSAF,
				ImageMatch:      []string{"docker.io/library/nginx*"},
				RefreshInterval: metav1.Duration{Duration: 24 * time.Hour},
			},
			wantErr: nil,
		},
		{
			name: "empty imageMatch rejected",
			spec: VEXSourceSpec{
				FeedURL:         "https://chainguard.dev/vex/feed.json",
				Format:          VEXSourceFormatOpenVEX,
				RefreshInterval: metav1.Duration{Duration: 6 * time.Hour},
			},
			wantErr: ErrEmptyImageMatch,
		},
		{
			name: "negative refreshInterval rejected",
			spec: VEXSourceSpec{
				FeedURL:         "https://chainguard.dev/vex/feed.json",
				Format:          VEXSourceFormatOpenVEX,
				ImageMatch:      []string{"*"},
				RefreshInterval: metav1.Duration{Duration: -1 * time.Hour},
			},
			wantErr: ErrNegativeRefreshInterval,
		},
		{
			name: "zero refreshInterval rejected",
			spec: VEXSourceSpec{
				FeedURL:    "https://chainguard.dev/vex/feed.json",
				Format:     VEXSourceFormatOpenVEX,
				ImageMatch: []string{"*"},
			},
			wantErr: ErrZeroRefreshInterval,
		},
		{
			name: "empty feed url rejected",
			spec: VEXSourceSpec{
				FeedURL: "",
				Format:  VEXSourceFormatOpenVEX,
			},
			wantErr: ErrEmptyFeedURL,
		},
		{
			name: "non-https feed url rejected",
			spec: VEXSourceSpec{
				FeedURL: "http://chainguard.dev/vex/feed.json",
				Format:  VEXSourceFormatOpenVEX,
			},
			wantErr: ErrInvalidFeedURL,
		},
		{
			name: "feed url with no scheme rejected",
			spec: VEXSourceSpec{
				FeedURL: "not-even-a-real-website",
				Format:  VEXSourceFormatOpenVEX,
			},
			wantErr: ErrInvalidFeedURL,
		},
		{
			name: "empty format rejected",
			spec: VEXSourceSpec{
				FeedURL: "https://chainguard.dev/vex/feed.json",
				Format:  "",
			},
			wantErr: ErrInvalidFormat,
		},
		{
			name: "garbage format rejected",
			spec: VEXSourceSpec{
				FeedURL: "https://chainguard.dev/vex/feed.json",
				Format:  "banana",
			},
			wantErr: ErrInvalidFormat,
		},
		{
			name: "format check is case-sensitive - uppercase rejected",
			spec: VEXSourceSpec{
				FeedURL: "https://chainguard.dev/vex/feed.json",
				Format:  "OpenVEX",
			},
			wantErr: ErrInvalidFormat,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.spec.Validate()
			if tt.wantErr == nil {
				assert.NoError(t, err)
			} else {
				assert.True(t, errors.Is(err, tt.wantErr),
					"expected error %v, got %v", tt.wantErr, err)
			}
		})
	}
}
