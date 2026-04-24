# Phase 2.5 - Vulnerability-Class Mapping

mode: triage
target: <TARGET>

Use the latest Phase 2 inventory and current local recon artifacts as the source of truth.
Do not redo earlier phases.

Use xLimit hosted retrieval if helpful:
~/xlimit-client/xlimit_context.sh "<full phase prompt>"

Inputs:
- Recon artifacts: <RECON_DIR>
- Phase 2 summary/inventory: <PHASE_2_SUMMARY_OR_PASTE_HERE>
- Optional user notes: <NOTES_FILE_OR_NONE>

Goal:
Map the observed surfaces to fitting vulnerability classes and produce the next test plan.

Constraints:
- Planning only; do not execute exploitation tests here.
- Use xLimit hosted retrieval for method selection when useful.
- Only map classes that concretely fit the observed surface.
- Explicitly rule out classes that do not fit.
- Prefer unauthenticated-testable paths first.
- Mark test plan items as:
  - U = unauthenticated
  - U->A = compare unauthenticated and authenticated states
  - A = authenticated material required
- If the plan becomes mostly auth-blocked and no valid auth material exists, say so clearly and stop.
- Keep the plan short and evidence-driven.
- Stop when the next execution plan is clear.

Output:
- Candidate class map per priority surface.
- Ruled-out classes with brief evidence.
- Ranked next-step test plan with U / U->A / A marks.
- Auth/scope/tooling gaps that block execution.
- Recommendation: proceed, obtain auth first, or stop.
- Short phase summary that can be saved by the user.
