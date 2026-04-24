# Codex Triage Prompt

Use this as the overall triage instruction for a local assistant session after running xLimit Recon on an authorized target.

Constraints:
- Keep all work within authorized scope.
- Use existing recon artifacts as the primary source of truth.
- Use xLimit hosted retrieval when helpful:
  ~/xlimit-client/xlimit_context.sh "<full task prompt>"
- Do not rediscover what is already known.
- Do not start broad fuzzing, brute force, content discovery, or scanner runs unless explicitly approved.
- Include the required tracking header on every live request if one is provided.
- Do not claim findings without concrete reproduction evidence.

Workflow:
- Start with Phase 1 using `examples/phase_1_rank_surfaces.md`.
- Continue to Phase 2 only after ranking is complete.
- Continue to Phase 2.5 only after inventory is complete.
- Continue to Phase 3 only after there is a concrete plan.
- After each phase, produce a short summary that can be saved and reused in the next phase.
