# xLimit Client

xLimit Client provides local client tools for approved users to query hosted xLimit retrieval from terminal agents such as Codex.

Retrieval returns short snippets through the xLimit API. xLimit does not provide direct access to raw knowledge files.

## What this repo contains

- `client/xlimit_search.sh`: low-level JSON API wrapper.
- `client/xlimit_search_text.sh`: readable terminal output wrapper.
- `client/xlimit_context.sh`: combined hosted knowledge and memory context wrapper for local assistants.
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
~/xlimit-client/xlimit_search_text.sh "graphql introspection authorization" knowledge

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

## Using xLimit Recon output with Codex and xLimit knowledge

1. Run:

   ```bash
   python3 recon/xlimit_recon.py -d example.com --custom-header "X-Bug-Bounty: researcher123"
   ```

2. Open:

   ```text
   recon_output/<target>_<timestamp>/xlimit_summary.txt
   ```

3. Ask your local assistant:

   ```text
   Use xLimit hosted retrieval if helpful. Based on this recon summary, rank the top surfaces by likely assessment value, explain why they matter, identify easy wins versus rabbit holes, and suggest the best next manual checks.
   ```

4. Paste `xlimit_summary.txt`.

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
- Do not commit tokens, `.env` files, recon outputs, screenshots, scope files, reports, memory files, or knowledge files.
- Review generated recon output before sharing it outside an authorized team.
- Keep live testing inside the written scope and rules of engagement.
- Use required program tracking headers when applicable.

## Troubleshooting

`Error: XLIMIT_API_TOKEN is not set`

Check `~/.config/xlimit/token.env` and confirm the `XLIMIT_API_TOKEN` variable is set.

`Unauthorized`

Confirm the token was copied correctly and has not been revoked. If needed, request support through `support@xlimit.org`.

DNS or network failures

Check local DNS, proxy, VPN, firewall, and general network access.

Codex sandbox cannot reach `api.xlimit.org`

Run the wrapper from a terminal with network access, or configure the agent environment so it can make the outbound HTTPS request.

Missing `subfinder` or `httpx`

Install the required recon tools and confirm they are available in `PATH`.

Permission denied on scripts

Run:

```bash
chmod 700 ~/xlimit-client/*.sh
```

Claim link already used

Claim links are single-use. Contact `support@xlimit.org` if you no longer have access to the token.

## License

MIT License. See `LICENSE`.
