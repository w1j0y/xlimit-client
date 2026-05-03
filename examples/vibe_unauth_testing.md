# Unauthenticated Web/API Testing Prompt

Replace:
- <TARGET_URL>

---

Paste into Codex / Claude Code:

```text
You are performing authorized unauthenticated web/API security testing.

Target:
<TARGET_URL>

You MUST use xLimit retrieval before starting.

Run:
~/xlimit-client/xlimit_context.sh "Unauthenticated web security testing for <TARGET_URL>. Focus on exposed endpoints, IDOR, and misconfigurations. Provide methodology guidance."

Rules:
- Use xLimit as supporting context only
- Do NOT treat it as proof
- Re-run retrieval if stuck or unsure

Mindset:
Approach this as a real attacker, not a scanner.

Methodology:
1. Map attack surface
2. Inventory endpoints
3. Generate hypotheses
4. Validate with evidence
5. Report ONLY confirmed issues

Constraints:
- No hallucinations
- No speculation
- Evidence required for every finding

Stop when:
- No new surface
- No provable issues

---

## Output

If none:
No confirmed findings.

Else:

## Finding Title

### Description
### Evidence
### Exploitability
### Impact
### Recommended Fix

### Fix Prompt (for coding agent)

You are fixing a confirmed security vulnerability.

Issue:
<description>

Root Cause:
<cause>

Fix Requirements:
- Minimal safe fix
- Preserve behavior

Verification:
- Add test before/after fix

Output:
Provide exact patch or steps.
```
