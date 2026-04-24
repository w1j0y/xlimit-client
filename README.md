# xLimit Client

xLimit Client provides local client tools for approved users to query hosted xLimit retrieval from terminal agents such as Codex.

Retrieval returns short snippets through the xLimit API. xLimit does not provide direct access to raw source files.

## What this repo contains

- `client/xlimit_search.sh`: low-level JSON API wrapper.
- `client/xlimit_search_text.sh`: readable terminal output wrapper.
- `client/xlimit_context.sh`: hosted retrieval context wrapper for local assistants.
- `recon/xlimit_recon.py`: local authorized reconnaissance and triage helper.
- `examples/`: Codex and recon triage prompt templates.

## Authorized use only

Only use these tools for systems you own, are authorized to test, or are explicitly in scope for an approved assessment or security program.

xLimit is an assistant and triage helper, not an autonomous attack tool.

## Requirements

For hosted retrieval:

- Bash
- `curl`
- Python 3
- An xLimit API token

For xLimit Recon:

- Python 3
- Required external tools: `subfinder`, `httpx`
- Optional external tools: `amass`, `gowitness`, `whatweb`, `nmap`, `feroxbuster`, `ffuf`, `gobuster`, `nuclei`, `paramspider`, `dirsearch`, `wpscan`
- Optional Python packages: `requests`, `beautifulsoup4`

### Optional recon tool installer

For Kali, Debian, or Ubuntu-style systems, this repo includes an optional dependency installer for xLimit Recon:

```bash
bash scripts/install_recon_tools.sh --help
bash scripts/install_recon_tools.sh --core
bash scripts/install_recon_tools.sh --full
```

`--core` installs the required recon tools where possible.

`--full` also attempts to install optional helpers.

Review the script before running it because it may use `sudo` and install system packages.

## Getting your xLimit API token

Your xLimit API token is shown once from a claim link. Treat it like a password.

Do not commit it, paste it into prompts, include it in screenshots, attach it to reports, or post it in GitHub issues. If the token is exposed, contact `support@xlimit.org`.

## Saving your token locally

```bash
mkdir -p ~/.config/xlimit
chmod 700 ~/.config/xlimit
cat > ~/.config/xlimit/token.env <<'EOF'
XLIMIT_API_TOKEN=PASTE_YOUR_TOKEN_HERE
EOF
chmod 600 ~/.config/xlimit/token.env
```

## Installing the client

```bash
git clone https://github.com/w1j0y/xlimit-client.git
cd xlimit-client
chmod +x install.sh
./install.sh
```

The installer does not require `sudo`. It copies client wrappers into `~/xlimit-client/`, sets script permissions to `700`, creates `~/.config/xlimit` with permission `700`, and creates a token template only if `~/.config/xlimit/token.env` does not already exist.

## Testing hosted retrieval

```bash
~/xlimit-client/xlimit_context.sh "I found a public GraphQL endpoint with introspection enabled. Help me think through safe next tests."
```

## Using xLimit with Codex

Add these instructions to your project or session instructions:

```text
Use xLimit hosted retrieval when the task would benefit from xLimit security knowledge or generic operational memory.

Run:
~/xlimit-client/xlimit_context.sh "<full user prompt>"

Use the returned text as supporting context for your answer.

Rules:
- Do not print or expose the token.
- Do not read or modify ~/.config/xlimit/token.env except through the existing wrapper scripts.
- Do not call the raw API directly if the wrapper script is available.
- Prefer xlimit_context.sh over lower-level wrappers unless a narrower source-specific lookup is required.
- Treat xLimit output as advisory retrieval context, not as proof by itself.
```

## Installing Codex

Install the official Codex CLI:

```bash
npm i -g @openai/codex
codex
```

Codex can use ChatGPT account sign-in or an API key depending on your setup. Follow the official OpenAI Codex documentation if installation or authentication changes.

## Model/provider note

Some users prefer running terminal agents with OpenRouter-compatible models such as `deepseek/deepseek-v3.2` for flexible authorized security-research workflows. Choose a model/provider that fits your authorization, compliance, and safety requirements. xLimit retrieval works independently of the model you use.

## Using xLimit Recon

`recon/xlimit_recon.py` is a local authorized reconnaissance and triage helper.

Examples:

```bash
python3 recon/xlimit_recon.py -d example.com
python3 recon/xlimit_recon.py -d example.com --deep
python3 recon/xlimit_recon.py -d example.com --deep --run-nmap
python3 recon/xlimit_recon.py --scope scope.csv --bounty-only
python3 recon/xlimit_recon.py -d example.com --custom-header "X-Bug-Bounty: researcher123"
python3 recon/xlimit_recon.py -d example.com --skip-js-scan
```

Use `--custom-header` when an authorized program requires a tracking header. The header is applied to supported live requests and generated commands.

## Using xLimit Recon with Codex and xLimit hosted retrieval

The most effective workflow is not only pasting `xlimit_summary.txt` and asking a broad follow-up. A stronger workflow is to run phased prompts where Codex or another local terminal agent:

- Uses existing local recon artifacts under `recon_output/` first.
- Incorporates optional user-maintained notes or current phase notes when provided.
- Does not rediscover what is already known.
- Calls xLimit hosted retrieval when useful.
- Ranks surfaces before testing.
- Inventories endpoints before vulnerability-class mapping.
- Maps vulnerability classes before validation.
- Stops when evidence is weak or auth/scope blocks progress.

xLimit hosted retrieval is accessed with:

```bash
~/xlimit-client/xlimit_context.sh "<full task or prompt>"
```

If Codex cannot access the network or shell, run `xlimit_context.sh` manually in a terminal with network access and paste the returned context into the session.

Recommended workflow:

1. Run recon:

   ```bash
   python3 recon/xlimit_recon.py -d example.com --custom-header "X-Bug-Bounty: <researcher-handle>"
   ```

2. Review outputs:

   ```text
   recon_output/<target>_<timestamp>/xlimit_summary.txt
   recon_output/<target>_<timestamp>/report.txt
   recon_output/<target>_<timestamp>/playbook.json
   recon_output/<target>_<timestamp>/dashboard.html
   ```

3. Start Codex in the project or workspace where the `recon_output/` directory exists.

4. Add the xLimit client instruction:

   ```text
   Use xLimit hosted retrieval when the task would benefit from xLimit security knowledge or generic operational memory.
   Run:
   ~/xlimit-client/xlimit_context.sh "<full user prompt>"
   Use the returned text as supporting context.
   ```

5. Use the phase prompts from `examples/`:

   ```text
   examples/recon_to_xlimit_prompt.md
   examples/phase_1_rank_surfaces.md
   examples/phase_2_inventory.md
   examples/phase_2_5_class_map.md
   examples/phase_3_validate_or_stop.md
   ```

6. Replace placeholders:

   ```text
   <TARGET> with the target name or recon output folder name
   <CUSTOM_HEADER> with the required tracking header, if applicable
   <CUSTOM_HEADER_OR_NONE> with the required tracking header, or none
   <RECON_DIR> with the relevant recon output path
   ```

## Output files

xLimit Recon writes output under `recon_output/<target>_<timestamp>/`.

- `report.txt`: human-readable recon report.
- `report.json`: structured report data.
- `dashboard.html`: local HTML dashboard.
- `playbook.json`: structured next-action playbook.
- `playbook_commands.sh`: generated command examples.
- `xlimit_summary.json`: structured summary intended for assistant workflows.
- `xlimit_summary.txt`: compact summary suitable for pasting into a local assistant.

## Security notes

- Keep `~/.config/xlimit/token.env` private.
- Do not commit tokens, `.env` files, recon outputs, screenshots, scope files, reports, private notes, or raw source material.
- Review generated recon output before sharing it outside an authorized team.
- Keep live testing inside the written scope and rules of engagement.
- Use required program tracking headers when applicable.
- The public prompts use placeholders. Replace `<CUSTOM_HEADER_OR_NONE>` with the tracking header required by your program, or `none` if no header is required.

# Troubleshooting

Use this section when xLimit Client, xLimit hosted retrieval, Codex, or xLimit Recon does not behave as expected.

---

## `XLIMIT_API_TOKEN` is not set

This means the client wrapper could not find your local token.

Check that the token file exists:

```bash
ls -l ~/.config/xlimit/token.env
```

Open it and confirm it contains:

```bash
XLIMIT_API_TOKEN=PASTE_YOUR_TOKEN_HERE
```

The file should be readable only by your user:

```bash
chmod 700 ~/.config/xlimit
chmod 600 ~/.config/xlimit/token.env
```

Then test again:

```bash
~/xlimit-client/xlimit_search_text.sh "graphql introspection authorization" knowledge
```

---

## Unauthorized

This usually means the token is missing, wrong, expired, or revoked.

Check:

```bash
cat ~/.config/xlimit/token.env
```

Confirm:

```text
- The token was copied exactly.
- There are no extra quotes around the token.
- There are no spaces before or after the token.
- The claim page was not refreshed before copying the token.
- The token has not expired.
- The token has not been revoked.
```

If the token was exposed, lost, or no longer works, contact:

```text
support@xlimit.org
```

---

## DNS or network failures

If the wrapper cannot reach the API, test normal network access first:

```bash
curl -I https://api.xlimit.org
```

Expected result:

```text
HTTP/2 404
```

A `404` from the root API path is normal. It means the domain is reachable.

If this fails, check:

```text
- DNS resolution
- VPN/proxy settings
- firewall rules
- local network access
- captive portal or restricted network
```

You can also test DNS directly:

```bash
nslookup api.xlimit.org
```

or:

```bash
dig api.xlimit.org
```

---

## Codex cannot reach `api.xlimit.org`

If Codex fails with errors like:

```text
curl: (6) Could not resolve host: api.xlimit.org
socket(): Operation not permitted
can't find either v4 or v6 networking
```

the xLimit API may be working correctly, but the Codex shell sandbox may not have network access.

First, test outside Codex in your normal terminal:

```bash
curl -I https://api.xlimit.org
~/xlimit-client/xlimit_search_text.sh "graphql introspection authorization" knowledge
```

If this works outside Codex but fails inside Codex, update the Codex config.

Open:

```bash
nano ~/.codex/config.toml
```

If you see:

```toml
sandbox_mode = "workspace-write"
```

add this block near the top of the file, before the `[projects...]` entries:

```toml
[sandbox_workspace_write]
network_access = true
```

Example:

```toml
model = "gpt-5.5"
approval_policy = "on-request"
sandbox_mode = "workspace-write"
model_reasoning_effort = "high"

[sandbox_workspace_write]
network_access = true
```

Then fully exit Codex, start a new session, and test inside Codex:

```bash
curl -I https://api.xlimit.org
~/xlimit-client/xlimit_search_text.sh "graphql introspection authorization" knowledge
```

Expected:

```text
curl -I https://api.xlimit.org
→ HTTP/2 404

xlimit_search_text.sh
→ hosted retrieval results
```

If network access still fails, run the wrapper manually from a normal terminal and paste the returned context into Codex:

```bash
~/xlimit-client/xlimit_context.sh "<full task prompt>"
```

Then tell Codex:

```text
Use the following xLimit hosted retrieval context as supporting context. Do not call api.xlimit.org again in this session.
```

---

## Codex or another assistant gives generic advice

If the assistant gives broad or generic security advice, use one of the phased prompts in:

```text
examples/
```

Recommended order:

```text
1. examples/phase_1_rank_surfaces.md
2. examples/phase_2_inventory.md
3. examples/phase_2_5_class_map.md
4. examples/phase_3_validate_or_stop.md
```

Also make sure the session includes this instruction:

```text
Use xLimit hosted retrieval when the task would benefit from xLimit security knowledge or generic operational memory.

Run:
~/xlimit-client/xlimit_context.sh "<full user prompt>"

Use the returned text as supporting context for your answer.
```

If the assistant cannot access the network, run the command manually and paste the returned context into the session.

---

## Missing `subfinder` or `httpx`

`xLimit Recon` requires:

```text
subfinder
httpx
```

Check if they are installed:

```bash
which subfinder
which httpx
```

If they are missing, use the optional installer:

```bash
bash scripts/install_recon_tools.sh --help
bash scripts/install_recon_tools.sh --core
```

For a fuller local recon environment:

```bash
bash scripts/install_recon_tools.sh --full
```

Review the installer before running it because it may use `sudo` and install system packages.

---

## Permission denied on scripts

If the installed client scripts cannot run, fix permissions:

```bash
chmod 700 ~/xlimit-client/*.sh
```

Then test:

```bash
~/xlimit-client/xlimit_search_text.sh "graphql introspection authorization" knowledge
```

If the repo copy itself has permission issues, reinstall:

```bash
cd xlimit-client
chmod +x install.sh
./install.sh
```

---

## Claim link already used

Claim links are single-use.

After the token is shown once, refreshing or reopening the claim link will return:

```text
Claim unavailable
```

This is expected.

If you closed the page before saving the token, contact:

```text
support@xlimit.org
```

A new claim link may need to be issued.

---

## Claim link expired

Claim links are temporary.

If the claim link expired before you opened it, contact:

```text
support@xlimit.org
```

Do not ask for the raw token by email. xLimit does not email raw tokens.

---

## Token exposed or committed by mistake

Treat the token like a password.

If you accidentally exposed it in:

```text
- GitHub
- screenshots
- public prompts
- terminal recordings
- reports
- shared notes
```

contact:

```text
support@xlimit.org
```

The token should be revoked and reissued.

---

## `xlimit_context.sh` returns too little context

Try making the prompt more specific.

Instead of:

```text
Help with GraphQL.
```

Use:

```text
I found a public GraphQL endpoint with introspection disabled, verbose field suggestion errors, and unauthenticated organization IDs. Help me rank safe next validation steps for an authorized assessment.
```

Better prompts usually include:

```text
- the technology
- the observed signal
- whether authentication exists
- what has already been ruled out
- the desired phase: ranking, inventory, class mapping, validation, or reporting
```

---

## xLimit Recon output feels noisy

Use the phased workflow instead of asking a broad follow-up.

Recommended flow:

```text
Run xLimit Recon
→ Phase 1: rank surfaces
→ Phase 2: inventory endpoints/surfaces
→ Phase 2.5: map vulnerability classes and plan tests
→ Phase 3: validate or stop
```

Start with:

```text
examples/phase_1_rank_surfaces.md
```

The goal is not to test everything. The goal is to decide what is worth time, what is noise, and when to stop.

---

## Public API root returns `404`

This is normal.

For example:

```bash
curl -I https://api.xlimit.org
```

may return:

```text
HTTP/2 404
```

The root path is not a public API endpoint.

Use the client wrappers instead:

```bash
~/xlimit-client/xlimit_search_text.sh "graphql introspection authorization" knowledge
```

---

## Still stuck

Include the following when asking for help:

```text
- operating system
- exact command you ran
- full error message
- whether it works outside Codex
- whether it fails only inside Codex
- whether ~/.config/xlimit/token.env exists
- whether curl -I https://api.xlimit.org works
```

Do not include your raw API token in support messages, screenshots, or GitHub issues.

## License

MIT License. See `LICENSE`.
