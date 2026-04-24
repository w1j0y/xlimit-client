# Phase 1 - Rank Surfaces

mode: triage
target: <TARGET>

Use the current local recon artifacts for <TARGET> as the source of truth.
Do not re-discover what is already known.

Use xLimit hosted retrieval if helpful:
~/xlimit-client/xlimit_context.sh "<full phase prompt>"

Inputs:
- Recon artifacts: <RECON_DIR>
- Optional user notes: <NOTES_FILE_OR_NONE>

Goal:
Produce a ranked list of the top 3-5 hosts or surfaces worth pursuing next, or conclude that the current recon is too weak to rank confidently.

Constraints:
- Use existing recon artifacts first.
- GET/HEAD only if a live clarification is truly needed.
- Include the required tracking header on every live request if one is provided: <CUSTOM_HEADER_OR_NONE>.
- Do not start async fuzzing or broad content discovery.
- Do not label anything as a finding in this phase.
- Collapse duplicate host families into one ranked surface when appropriate.
- Prefer diverse host types over repeated login/auth wrappers.
- Use xLimit hosted retrieval for method selection when useful.
- Stop when the ranking is complete.
- Do not speculate on exploitation classes beyond what is necessary to justify ranking. Prefer surface quality over hypothetical bug classes.

Output:
- Scope inventory.
- Ranked top 3-5 surfaces with short justification.
- Deprioritized surfaces with reason.
- Open questions that block the next phase.
- Short phase summary that can be saved by the user.
