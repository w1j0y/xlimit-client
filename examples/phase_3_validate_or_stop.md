# Phase 3 - Validate or Stop

mode: triage
target: <TARGET>

Use the latest Phase 2.5 plan and current local recon artifacts as the source of truth.
Do not redo class mapping.
Do not broaden scope to new hosts.

Use xLimit hosted retrieval if helpful:
~/xlimit-client/xlimit_context.sh "<full phase prompt>"

Inputs:
- Recon artifacts: <RECON_DIR>
- Phase 2.5 plan: <PHASE_2_5_PLAN_OR_PASTE_HERE>
- Optional user notes: <NOTES_FILE_OR_NONE>

Goal:
Using the current evidence only, either confirm one reportable finding or conclude that no viable finding can be demonstrated from the current material.

Constraints:
- Stay within the planned surfaces/tests only.
- Use xLimit hosted retrieval for method selection when useful.
- Keep probes minimal and evidence-driven.
- Include the required tracking header on every live request if one is provided: <CUSTOM_HEADER_OR_NONE>.
- No speculative escalation.
- No destructive actions.
- No brute force attacks.
- Stop after 3 consecutive weak/rejected tests with no new signal.
- If the remaining meaningful work is auth-blocked, say so clearly and stop.
- Do not call anything reportable without concrete reproduction evidence.

Output:
- Tests executed.
- Result of each test.
- Confirmed finding, rejected hypothesis, or inconclusive result with exact blocker.
- Final recommendation: report, continue only with auth material, or stop.
- Short phase summary that can be saved by the user.
