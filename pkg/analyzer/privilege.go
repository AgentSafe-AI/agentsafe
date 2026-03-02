package analyzer

import (
	"fmt"
	"strings"

	"github.com/AgentSafe-AI/agentsentry/pkg/model"
)

// broadOAuthScopes are OAuth scope patterns that signal over-privileged access.
// Tools should declare the narrowest scope required for their stated purpose.
var broadOAuthScopes = []string{
	"admin",
	"write:*",
	"repo",   // GitHub full repo scope (prefer repo:read)
	"read:*", // broad wildcard reads
	"*",      // wildcard everything
	"root",
	"superuser",
	"all",
	"full_access",
	"manage",
}

// privilegedDescriptionPatterns detect tools that describe acquiring elevated
// privileges at runtime (distinct from AS-001 prompt-injection patterns).
var privilegedDescriptionPatterns = []string{
	"sudo",
	"run as root",
	"elevated privilege",
	"bypass permission",
	"bypass authorization",
	"escalate privilege",
	"gain admin",
	"impersonate",
}

// PrivilegeEscalationChecker detects OAuth/token scopes that are broader than
// necessary, and description-level signals of privilege escalation at runtime.
//
// Rule ID: AS-005.
type PrivilegeEscalationChecker struct{}

// NewPrivilegeEscalationChecker returns a new PrivilegeEscalationChecker.
func NewPrivilegeEscalationChecker() *PrivilegeEscalationChecker {
	return &PrivilegeEscalationChecker{}
}

// Check inspects:
//  1. tool.Metadata["oauth_scopes"] ([]string) for over-broad OAuth scopes.
//  2. tool.Description for privilege-escalation language.
func (c *PrivilegeEscalationChecker) Check(tool model.UnifiedTool) ([]model.Issue, error) {
	var issues []model.Issue

	// 1. OAuth scope check
	if scopes := extractStringSlice(tool.Metadata, "oauth_scopes"); len(scopes) > 0 {
		for _, scope := range scopes {
			scopeLower := strings.ToLower(strings.TrimSpace(scope))
			for _, broad := range broadOAuthScopes {
				if scopeLower == broad || strings.HasSuffix(scopeLower, ":write") ||
					strings.Contains(scopeLower, "admin") || scopeLower == "*" {
					issues = append(issues, model.Issue{
						RuleID:      "AS-005",
						Severity:    model.SeverityHigh,
						Code:        "BROAD_OAUTH_SCOPE",
						Description: fmt.Sprintf("tool declares over-broad OAuth scope %q", scope),
						Location:    "metadata.oauth_scopes",
					})
					break
				}
			}
		}
	}

	// 2. Description-level privilege-escalation language
	descLower := strings.ToLower(tool.Description)
	for _, pattern := range privilegedDescriptionPatterns {
		if strings.Contains(descLower, pattern) {
			issues = append(issues, model.Issue{
				RuleID:      "AS-005",
				Severity:    model.SeverityHigh,
				Code:        "PRIVILEGE_ESCALATION",
				Description: fmt.Sprintf("tool description suggests privilege escalation: %q", pattern),
				Location:    "description",
			})
			break
		}
	}

	return issues, nil
}

// extractStringSlice is a helper that reads a []string from tool.Metadata.
func extractStringSlice(meta map[string]any, key string) []string {
	if meta == nil {
		return nil
	}
	raw, ok := meta[key]
	if !ok {
		return nil
	}
	switch v := raw.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
