package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// TestSanitizeURL verifies that the sanitizeURL function correctly masks
// credentials in URLs. It ensures that URLs containing user credentials
// are sanitized by replacing them with asterisks, while URLs without
// credentials remain unchanged.
func TestSanitizeURL(t *testing.T) {
	tests := []struct {
		name                 string
		inputURL             string
		expectedSanitizedURL string
	}{
		{
			name: "url with credentials",
			inputURL: "https://user:pass@github.com/" +
				"OWNER/REPO.git",
			expectedSanitizedURL: "https://%2A%2A%2A%2A%2A@" +
				"github.com/OWNER/REPO.git",
		},
		{
			name: "url without credentials",
			inputURL: "https://github.com/OWNER/REPO" +
				".git",
			expectedSanitizedURL: "https://github.com/OWNER/REPO" +
				".git",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actualSanitizedURL := SanitizeURL(tc.inputURL)
			assert.Equal(t, tc.expectedSanitizedURL,
				actualSanitizedURL, "Sanitized URL does not "+
					"match expected result")
		})
	}
}

// TestCalculateFuzzSeconds verifies that calculateFuzzSeconds correctly
// computes the per-target fuzz duration given a sync frequency, number of
// parallel workers, and total number of fuzz targets.
func TestCalculateFuzzSeconds(t *testing.T) {
	// Define the number of parallel workers and total targets.
	totalWorkers := 7
	totalTargets := 43

	// Compute the expected per-target fuzz duration.
	expectedDuration, err := time.ParseDuration("31m7s")
	assert.NoError(t, err, "failed to parse expectedDuration")

	// Parse a sample total fuzz time.
	syncFrequency, err := time.ParseDuration("3h37m53s")
	assert.NoError(t, err, "failed to parse syncFrequency")

	actualDuration := calculateFuzzSeconds(syncFrequency, totalWorkers,
		totalTargets)

	assert.Equal(t, expectedDuration, actualDuration,
		"calculated fuzz duration does not match expected value",
	)
}

// TestExtractRepo verifies that extractRepo correctly parse the repository
// names from git URLs.
func TestExtractRepo(t *testing.T) {
	cases := []struct {
		name             string
		inputURL         string
		expectedRepoName string
		expectErrMsg     string
	}{
		{
			name:             "valid git URL",
			inputURL:         "https://github.com/owner/repo.git",
			expectedRepoName: "repo",
		},
		{
			name:             "valid git URL without .git suffix",
			inputURL:         "https://github.com/owner/repo",
			expectedRepoName: "repo",
		},
		{
			name:         "invalid git URL",
			inputURL:     "://not a url",
			expectErrMsg: "invalid repository URL",
		},
		{
			name:         "empty repository name in URL",
			inputURL:     "https://github.com/owner/.git",
			expectErrMsg: "could not parse repository name",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractRepo(tc.inputURL)
			if tc.expectErrMsg != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectErrMsg)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedRepoName, got)
		})
	}
}
