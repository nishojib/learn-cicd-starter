package auth_test

import (
	"net/http"
	"testing"

	"github.com/bootdotdev/learn-cicd-starter/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetAPIKey(t *testing.T) {
	testCases := map[string]struct {
		key         string
		value       string
		expected    string
		expectedErr error
	}{
		"correct authorization header": {
			key:      "Authorization",
			value:    "ApiKey secret-key",
			expected: "secret-key",
		},
		"empty authorization header": {
			key:         "Authorization",
			value:       "",
			expectedErr: auth.ErrNoAuthHeaderIncluded,
		},
		"malformed authorization header": {
			key:         "Authorization",
			value:       "Bearer secret",
			expectedErr: auth.ErrMalformedAuthHeader,
		},
		"no api key passed to authorization header": {
			key:         "Authorization",
			value:       "ApiKey",
			expectedErr: auth.ErrMalformedAuthHeader,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			headers := http.Header{}
			headers.Set(tc.key, tc.value)
			got, err := auth.GetAPIKey(headers)

			if err != nil {
				require.Error(t, err)
				require.ErrorIs(t, err, tc.expectedErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.expected, got)
		})
	}
}
