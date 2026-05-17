package analyzer

import (
	"regexp"
	"strings"

	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/deepscan"
	"github.com/AgentSafe-AI/tooltrust-scanner/pkg/model"
)

// patternRule pairs an injection-detection regex with the severity it emits.
type patternRule struct {
	pattern  *regexp.Regexp
	severity model.Severity
}

// legitimateDataMovementTools lists tool-name keywords that indicate sending
// or forwarding data is the tool's intended purpose — not an injection signal.
var legitimateDataMovementTools = []string{
	"email", "mail", "reply", "forward", "draft", "message",
	"send", "notification", "webhook", "publish", "broadcast",
}

// suspiciousNameTerms cancels the data-movement skip when found in a tool
// name: a name like "send_to_url" or "forward_to_remote_host" is itself a
// red flag, so the data-exfiltration patterns must still run.
var suspiciousNameTerms = []string{
	"external", "remote", "http", "url", "attacker", "exfil",
}

// jailbreakPattern is the single-keyword "jailbreak" rule. It is the only
// AS-001 pattern broad enough that a defensive security tool ("scan input
// for jailbreak attempts", "block jailbreak prompts") trips it without
// any malicious intent. We special-case it in Check(): when the
// description shows defensive framing around the word, we suppress the
// finding. The variable is shared between the rules table and the gating
// logic via pointer identity.
var jailbreakPattern = regexp.MustCompile(`(?i)jailbreak`)

// injectionRules is the ordered list of AS-001 detection rules.
// AS-001 is reserved for explicit prompt/instruction override patterns.
//
// The leading `\b` on the (ignore|disregard|bypass) rule prevents
// false-positive matches against the substring "ignore" inside
// `gitignore`, `mcpignore`, etc. — common in legitimate
// codebase-indexing tool descriptions that say things like
// "respects .gitignore rules".
var injectionRules = []patternRule{
	// ── High-confidence: explicit injection markers ──────────────────────────
	{
		regexp.MustCompile(`(?i)\b(ignore|disregard|bypass)\s+(?:\w+\s+){0,3}(instructions?|prompts?|context|rules?|guidelines?|restrictions?|filters?)`),
		model.SeverityCritical,
	},
	{regexp.MustCompile(`(?im)^\s*system\s*:`), model.SeverityCritical},
	{regexp.MustCompile(`(?i)<\s*INST\s*>`), model.SeverityCritical},
	{regexp.MustCompile(`(?i)\[INST\]`), model.SeverityCritical},
	{
		regexp.MustCompile(`(?i)act\s+as\s+(an?\s+)?(admin|root|superuser|privileged)`),
		model.SeverityCritical,
	},
	{
		regexp.MustCompile(`(?i)forget\s+(your|all|previous)\s+(instructions?|context|rules?|training)`),
		model.SeverityCritical,
	},
	{
		regexp.MustCompile(`(?i)you\s+(are\s+now|must\s+now|will\s+now)\s+(act|behave|operate)`),
		model.SeverityCritical,
	},
	{regexp.MustCompile(`(?i)exfiltrate\s+(?:\w+\s+){0,2}(?:data|info|credentials?|secrets?|content|results?)`), model.SeverityCritical},
	{regexp.MustCompile(`(?i)(developer|unrestricted)\s+mode`), model.SeverityCritical},
	{regexp.MustCompile(`(?i)full\s+system\s+access`), model.SeverityCritical},
	{jailbreakPattern, model.SeverityCritical},
}

// defensiveJailbreakContexts are substrings whose presence (anywhere in the
// description) indicates the tool is describing detection / prevention of
// jailbreaks rather than performing one. Match is case-insensitive on a
// lowercased description. Entries are stems so that inflected forms
// (identify/identifies, detect/detection/detected) all match.
var defensiveJailbreakContexts = []string{
	"detect", "scan", "block", "prevent", "filter",
	"guard", "identif", "flag ", "report",
	"monitor", "audit", "protect", "defense", "defensive",
	"mitigat", "quarantin", "sanitiz",
	"anti-jailbreak", "anti jailbreak",
	"jailbreak attempt", "jailbreak detection", "jailbreak vector",
	"for jailbreak", "against jailbreak",
}

// describesDefensiveJailbreakUse returns true when the description appears
// to be discussing jailbreak detection or prevention rather than performing
// a jailbreak. Used to suppress the lone-keyword `jailbreak` rule for
// security tools such as `scan_prompt`, `anti_injection_scan`, etc.
func describesDefensiveJailbreakUse(descLower string) bool {
	for _, ctx := range defensiveJailbreakContexts {
		if strings.Contains(descLower, ctx) {
			return true
		}
	}
	return false
}

type PoisoningChecker struct {
	enableDeepScan bool
}

func (c *PoisoningChecker) Meta() RuleMeta {
	return RuleMeta{
		ID:          "AS-001",
		Title:       "Tool Poisoning / Prompt Injection",
		Description: "Detects malicious instructions embedded in tool descriptions that attempt to hijack agent behavior, exfiltrate data, or override safety constraints.",
	}
}

// NewPoisoningChecker returns a new PoisoningChecker.
func NewPoisoningChecker(enableDeepScan bool) *PoisoningChecker {
	return &PoisoningChecker{enableDeepScan: enableDeepScan}
}

// Check runs all injection-pattern rules against the tool description.
func (c *PoisoningChecker) Check(tool model.UnifiedTool) ([]model.Issue, error) {
	desc := strings.TrimSpace(tool.Description)
	if desc == "" {
		return nil, nil
	}

	descLower := strings.ToLower(desc)
	defensiveJailbreak := describesDefensiveJailbreakUse(descLower)

	var issues []model.Issue
	for _, rule := range injectionRules {
		if rule.pattern == jailbreakPattern && defensiveJailbreak {
			continue
		}
		if rule.pattern.MatchString(desc) {
			matched := rule.pattern.FindString(desc)
			issues = append(issues, model.Issue{
				RuleID:      "AS-001",
				ToolName:    tool.Name,
				Severity:    rule.severity,
				Code:        "TOOL_POISONING",
				Description: "possible prompt injection detected in tool description: pattern matched: " + rule.pattern.String(),
				Location:    "description",
				Evidence: []model.Evidence{
					{Kind: "description_pattern", Value: rule.pattern.String()},
					{Kind: "description_match", Value: matched},
				},
			})
			// One finding per tool is sufficient for a poisoning verdict.
			break
		}
	}

	if len(issues) == 0 && c.enableDeepScan {
		if _, found := deepscan.Analyze(desc); found {
			issues = append(issues, model.Issue{
				RuleID:      "AS-001",
				ToolName:    tool.Name,
				Severity:    model.SeverityCritical,
				Code:        "TOOL_POISONING",
				Description: "semantic AI analysis detected deep prompt injection in tool description",
				Location:    "description",
				Evidence: []model.Evidence{
					{Kind: "deep_scan", Value: "semantic prompt injection signal in description"},
				},
			})
		}
	}

	return issues, nil
}

// isDataMovementTool returns true when the tool name contains a data-movement
// keyword (email/reply/forward/…) but does NOT also contain an
// external-destination term (url/remote/external/…) that would itself be a
// red flag.  The dual check prevents a malicious tool named "send_to_url"
// or "forward_to_remote_host" from bypassing the data-exfiltration patterns.
func isDataMovementTool(name string) bool {
	nameLower := strings.ToLower(name)
	for _, s := range suspiciousNameTerms {
		if strings.Contains(nameLower, s) {
			return false
		}
	}
	for _, kw := range legitimateDataMovementTools {
		if strings.Contains(nameLower, kw) {
			return true
		}
	}
	return false
}
