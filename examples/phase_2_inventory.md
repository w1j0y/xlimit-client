# Phase 2 - Surface Inventory

mode: triage
target: <TARGET>

Use the latest Phase 1 ranking and current local recon artifacts as the source of truth.
Do not redo Phase 1.

Use xLimit hosted retrieval if helpful:
~/xlimit-client/xlimit_context.sh "<full phase prompt>"

Inputs:
- Recon artifacts: <RECON_DIR>
- Phase 1 summary: <PHASE_1_SUMMARY_OR_PASTE_HERE>
- Optional user notes: <NOTES_FILE_OR_NONE>

Goal:
Characterize the ranked surfaces and produce a usable endpoint/surface inventory for the next phase.

Constraints:
- Stay within the ranked hosts/surfaces only.
- Use existing recon artifacts first.
- Use xLimit hosted retrieval for method selection when useful.
- Keep probing minimal and evidence-driven.
- GET/HEAD only unless a non-destructive request is clearly justified for characterization.
- Include the required tracking header on every live request if one is provided: <CUSTOM_HEADER_OR_NONE>.
- Do not treat framework defaults, documentation pages, source maps, SPA shells, or public-by-design endpoints as findings by themselves.
- Stop when the inventory is good enough to support vulnerability-class mapping.

Output:
- Endpoint/surface inventory per ranked host.
- Notable extraction or discovery results.
- Auth boundary observations.
- Top candidate endpoints/surfaces for the next phase.
- Tooling, scope, or auth-material gaps.
- Short phase summary that can be saved by the user.
