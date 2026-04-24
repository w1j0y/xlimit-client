# Codex Triage Prompt

Use the existing recon artifacts I provide. Do not rediscover what is already known.

Constraints:
- Use existing recon artifacts as the primary source of truth.
- Do not start broad rediscovery or enumeration.
- Make live GET or HEAD requests only if clarification is truly needed.
- Include the required custom header on any live request.
- Do not start async fuzzing, content discovery, brute force, or scanner runs.
- Do not label anything as a finding in this triage phase.
- Rank the top 3-5 surfaces by likely assessment value.
- Separate easy wins from likely rabbit holes.
- Write a short summary with the best next manual checks.

Task:
Review the provided artifacts, rank the top surfaces, explain why each matters, and propose the safest next manual validation steps.
