# Recon-to-xLimit Launcher Prompt

Use this when starting a local assistant session after running xLimit Recon.

Prompt:

I have local xLimit Recon artifacts for an authorized target.

Target: <TARGET>
Recon directory: <RECON_DIR>
Required tracking header, if any: <CUSTOM_HEADER_OR_NONE>

Use existing recon artifacts first.
Use xLimit hosted retrieval if helpful:
~/xlimit-client/xlimit_context.sh "<full task prompt>"

Do not rediscover what is already known.
Do not start broad fuzzing or scanner runs unless I explicitly approve it.
Start with Phase 1 ranking using examples/phase_1_rank_surfaces.md.
After each phase, produce a short summary I can save and reuse in the next phase.
