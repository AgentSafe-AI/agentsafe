package analyzer

import (
	"regexp"
	"strings"

	"github.com/AgentSafe-AI/agentsentry/pkg/model"
)

// injectionPatterns are compiled regexes that signal prompt injection attempts.
var injectionPatterns = []*regexp.Regexp{
	// "ignore previous instructions", "ignore all previous instructions", "ignore all instructions"
	regexp.MustCompile(`(?i)ignore\s+(?:all\s+)?(?:previous\s+|prior\s+)?(instructions?|prompts?|context|rules?)`),
	regexp.MustCompile(`(?i)disregard\s+(your|all|previous|prior)?\s*(instructions?|context|rules?)`),
	regexp.MustCompile(`(?i)system\s*:`),
	regexp.MustCompile(`(?i)<\s*INST\s*>`),
	regexp.MustCompile(`(?i)\[INST\]`),
	regexp.MustCompile(`(?i)act\s+as\s+(an?\s+)?(admin|root|superuser|privileged)`),
	regexp.MustCompile(`(?i)forget\s+(your|all|previous)\s+(instructions?|context|rules?|training)`),
	regexp.MustCompile(`(?i)you\s+(are\s+now|must\s+now|will\s+now)\s+(act|behave|operate)`),
	regexp.MustCompile(`(?i)exfiltrate`),
	regexp.MustCompile(`(?i)developer\s+mode`),
}

// PoisoningChecker inspects a tool's description for prompt injection signals.
type PoisoningChecker struct{}

// NewPoisoningChecker returns a new PoisoningChecker.
func NewPoisoningChecker() *PoisoningChecker { return &PoisoningChecker{} }

// Check runs all injection pattern rules against the tool description.
func (c *PoisoningChecker) Check(tool model.UnifiedTool) ([]model.Issue, error) {
	desc := strings.TrimSpace(tool.Description)
	if desc == "" {
		return nil, nil
	}

	var issues []model.Issue
	for _, pattern := range injectionPatterns {
		if pattern.MatchString(desc) {
			issues = append(issues, model.Issue{
				RuleID:      "AS-001",
				Severity:    model.SeverityCritical,
				Code:        "TOOL_POISONING",
				Description: "possible prompt injection detected in tool description: pattern matched: " + pattern.String(),
				Location:    "description",
			})
			// One finding per tool is sufficient for a poisoning verdict.
			break
		}
	}
	return issues, nil
}
