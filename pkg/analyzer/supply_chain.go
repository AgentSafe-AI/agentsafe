package analyzer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/AgentSafe-AI/agentsentry/pkg/model"
)

const (
	osvAPIURL       = "https://api.osv.dev/v1/query"
	osvQueryTimeout = 10 * time.Second
)

// Dependency describes a package that a tool depends on.
// Adapters should populate UnifiedTool.Metadata["dependencies"] with
// []Dependency when the source protocol exposes package information.
type Dependency struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"` // e.g. "npm", "Go", "PyPI"
}

// osvClient is an interface for querying the OSV API, enabling test mocking.
type osvClient interface {
	Query(ctx context.Context, dep Dependency) ([]osvVuln, error)
}

// httpOSVClient is the real HTTP implementation of osvClient.
type httpOSVClient struct {
	http    *http.Client
	baseURL string
}

func newHTTPOSVClient() *httpOSVClient {
	return &httpOSVClient{
		http:    &http.Client{Timeout: osvQueryTimeout},
		baseURL: osvAPIURL,
	}
}

// osvQueryBody is the JSON body sent to the OSV batch query endpoint.
type osvQueryBody struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version,omitempty"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID       string        `json:"id"`
	Summary  string        `json:"summary"`
	Severity []osvSeverity `json:"severity"`
	Aliases  []string      `json:"aliases"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

func (c *httpOSVClient) Query(ctx context.Context, dep Dependency) ([]osvVuln, error) {
	body, err := json.Marshal(osvQueryBody{
		Package: osvPackage{Name: dep.Name, Ecosystem: dep.Ecosystem},
		Version: dep.Version,
	})
	if err != nil {
		return nil, fmt.Errorf("osv: marshal query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("osv: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("osv: http request: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			// body close errors after a successful read are non-actionable
			_ = closeErr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv: unexpected status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("osv: read body: %w", err)
	}

	var result osvResponse
	if err = json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("osv: unmarshal response: %w", err)
	}
	return result.Vulns, nil
}

// SupplyChainChecker queries the OSV API for known CVEs in a tool's declared
// dependencies.  Dependencies are read from UnifiedTool.Metadata["dependencies"]
// which adapters populate when the source protocol exposes package info.
//
// Rule ID: AS-004.
type SupplyChainChecker struct {
	client osvClient
}

// NewSupplyChainChecker returns a SupplyChainChecker using the live OSV API.
func NewSupplyChainChecker() *SupplyChainChecker {
	return &SupplyChainChecker{client: newHTTPOSVClient()}
}

// newSupplyChainCheckerWithClient returns a checker with a custom OSV client
// (used in tests to inject a mock).
func newSupplyChainCheckerWithClient(c osvClient) *SupplyChainChecker {
	return &SupplyChainChecker{client: c}
}

// MockVuln describes a fake vulnerability returned by the mock OSV client.
type MockVuln struct {
	ID        string
	Summary   string
	CVSSScore string // CVSS v3 base score string, e.g. "9.8". Empty = no severity.
}

// mockOSVClient is an in-process test double for the OSV API.
type mockOSVClient struct {
	vulns []MockVuln
	err   error
}

func (m *mockOSVClient) Query(_ context.Context, _ Dependency) ([]osvVuln, error) {
	if m.err != nil {
		return nil, m.err
	}
	out := make([]osvVuln, len(m.vulns))
	for i, v := range m.vulns {
		ov := osvVuln{ID: v.ID, Summary: v.Summary}
		if v.CVSSScore != "" {
			ov.Severity = []osvSeverity{{Type: "CVSS_V3", Score: v.CVSSScore}}
		}
		out[i] = ov
	}
	return out, nil
}

// NewSupplyChainCheckerWithMock returns a SupplyChainChecker backed by an
// in-memory mock OSV client.  Intended for unit tests only.
func NewSupplyChainCheckerWithMock(vulns []MockVuln, queryErr error) *SupplyChainChecker {
	return newSupplyChainCheckerWithClient(&mockOSVClient{vulns: vulns, err: queryErr})
}

// Check reads dependencies from tool.Metadata["dependencies"] and queries OSV
// for each one.  Missing or empty metadata results in no findings.
func (c *SupplyChainChecker) Check(tool model.UnifiedTool) ([]model.Issue, error) {
	deps, err := extractDependencies(tool)
	if err != nil || len(deps) == 0 {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), osvQueryTimeout)
	defer cancel()

	var issues []model.Issue
	for _, dep := range deps {
		vulns, err := c.client.Query(ctx, dep)
		if err != nil {
			// Network failures are non-fatal: skip this dependency.
			continue
		}
		for _, v := range vulns {
			issues = append(issues, model.Issue{
				RuleID:      "AS-004",
				Severity:    osvSeverityToModel(v),
				Code:        "SUPPLY_CHAIN_CVE",
				Description: fmt.Sprintf("%s in %s@%s: %s", v.ID, dep.Name, dep.Version, v.Summary),
				Location:    fmt.Sprintf("dependency:%s", dep.Name),
			})
		}
	}
	return issues, nil
}

// extractDependencies deserializes UnifiedTool.Metadata["dependencies"] into
// a []Dependency slice.
func extractDependencies(tool model.UnifiedTool) ([]Dependency, error) {
	raw, ok := tool.Metadata["dependencies"]
	if !ok {
		return nil, nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("supply_chain: marshal deps metadata: %w", err)
	}
	var deps []Dependency
	if err = json.Unmarshal(b, &deps); err != nil {
		return nil, fmt.Errorf("supply_chain: unmarshal deps: %w", err)
	}
	return deps, nil
}

// osvSeverityToModel maps OSV severity information to a model.Severity.
// OSV uses CVSS scores; in the absence of a score we default to HIGH so
// any CVE is surfaced rather than silenced.
func osvSeverityToModel(v osvVuln) model.Severity {
	for _, s := range v.Severity {
		if s.Type == "CVSS_V3" || s.Type == "CVSS_V2" {
			return cvssScoreToSeverity(s.Score)
		}
	}
	return model.SeverityHigh // conservative default
}

// cvssScoreToSeverity maps a CVSS v3 base-score string to model.Severity.
// CVSS base scores: None 0.0, Low 0.1–3.9, Medium 4.0–6.9, High 7.0–8.9,
// Critical 9.0–10.0.
func cvssScoreToSeverity(score string) model.Severity {
	var f float64
	if _, err := fmt.Sscanf(score, "%f", &f); err != nil {
		return model.SeverityHigh
	}
	switch {
	case f >= 9.0:
		return model.SeverityCritical
	case f >= 7.0:
		return model.SeverityHigh
	case f >= 4.0:
		return model.SeverityMedium
	default:
		return model.SeverityLow
	}
}
