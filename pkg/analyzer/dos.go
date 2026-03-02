package analyzer

import (
	"strings"

	"github.com/AgentSafe-AI/agentsentry/pkg/model"
)

// dosRiskyPermissions are permissions that imply outbound/resource-heavy
// operations where the absence of rate-limiting creates a DoS risk.
var dosRiskyPermissions = []model.Permission{
	model.PermissionNetwork,
	model.PermissionHTTP,
	model.PermissionExec,
}

// rateLimitIndicators are metadata keys or schema property names that signal
// the tool has rate-limiting built in.
var rateLimitIndicators = []string{
	"rate_limit", "ratelimit", "max_requests", "requests_per_minute",
	"retry", "max_retries", "timeout", "throttle",
}

// DoSResilienceChecker detects tools that perform network or resource-heavy
// operations without any visible rate-limit or retry configuration, creating
// potential for denial-of-service or runaway resource consumption.
//
// Rule ID: AS-011.
type DoSResilienceChecker struct{}

// NewDoSResilienceChecker returns a new DoSResilienceChecker.
func NewDoSResilienceChecker() *DoSResilienceChecker { return &DoSResilienceChecker{} }

// Check raises a LOW finding when a tool holds a risky permission but declares
// no rate-limit metadata and has no rate-limit-related schema properties.
func (c *DoSResilienceChecker) Check(tool model.UnifiedTool) ([]model.Issue, error) {
	if !hasRiskyDOSPermission(tool) {
		return nil, nil
	}
	if hasRateLimitSignal(tool) {
		return nil, nil
	}

	return []model.Issue{{
		RuleID:   "AS-011",
		Severity: model.SeverityLow,
		Code:     "MISSING_RATE_LIMIT",
		Description: "tool performs network or execution operations but declares no " +
			"rate-limit, timeout, or retry configuration",
		Location: "permissions+metadata",
	}}, nil
}

func hasRiskyDOSPermission(tool model.UnifiedTool) bool {
	for _, perm := range tool.Permissions {
		for _, risky := range dosRiskyPermissions {
			if perm == risky {
				return true
			}
		}
	}
	return false
}

func hasRateLimitSignal(tool model.UnifiedTool) bool {
	// Check metadata keys
	for key := range tool.Metadata {
		keyLower := strings.ToLower(key)
		for _, indicator := range rateLimitIndicators {
			if strings.Contains(keyLower, indicator) {
				return true
			}
		}
	}
	// Check input schema property names
	for propName := range tool.InputSchema.Properties {
		propLower := strings.ToLower(propName)
		for _, indicator := range rateLimitIndicators {
			if strings.Contains(propLower, indicator) {
				return true
			}
		}
	}
	return false
}
