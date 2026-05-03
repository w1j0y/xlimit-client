# Authenticated Web/API Testing Prompt

Use this prompt for authorized authenticated security testing against a target web application or API.

This prompt supports three authentication modes:

1. Username/password credentials
2. Session token / bearer token
3. Cookie-based browser session, useful for OAuth-only apps such as Google login

Use only one applicable authentication mode unless the engagement requires more.

---

## Replace

- `<TARGET_URL>` with the in-scope base URL
- `<TEST_EMAIL_OR_USERNAME>` with the test account email/username, or `none`
- `<TEST_PASSWORD_OR_NONE>` with the test account password, or `none`
- `<SESSION_TOKEN_OR_NONE>` with a bearer/session token, or `none`
- `<COOKIE_FILE_OR_NONE>` with a local temporary file containing the full Cookie header, or `none`
- `<COOKIE_HEADER_OR_NONE>` with a full HTTP Cookie header, or `none`
- `<AUTH_NOTES_OR_NONE>` with short context about the auth method, or `none`

Example cookie header:

```text
Cookie: token=REDACTED; oauth_id_token=REDACTED
```

Do not save real secrets inside this prompt file.

## Cookie Handling Note

Cookies and session tokens are secrets.

For quick local testing, users may paste a Cookie header directly into this prompt. However, they should not commit it, screenshot it, share the transcript, or include it in reports.

For cleaner handling, store the Cookie header in a temporary local file:

```bash
cat > .xlimit-cookie <<'EOF'
Cookie: token=PASTE_VALUE; oauth_id_token=PASTE_VALUE
EOF
chmod 600 .xlimit-cookie
```

Then set:

```text
<COOKIE_FILE_OR_NONE> = .xlimit-cookie
<COOKIE_HEADER_OR_NONE> = none
```

Delete it after testing:

```bash
shred -u .xlimit-cookie
```

---

## Paste into Codex / Claude Code

```text
You are performing authorized authenticated web/API security testing.

Target:
<TARGET_URL>

Authentication inputs:
- Email/User: <TEST_EMAIL_OR_USERNAME>
- Password: <TEST_PASSWORD_OR_NONE>
- Session token: <SESSION_TOKEN_OR_NONE>
- Cookie file: <COOKIE_FILE_OR_NONE>
- Cookie header: <COOKIE_HEADER_OR_NONE>
- Auth notes: <AUTH_NOTES_OR_NONE>

Use only the authentication material provided above.
If all authentication values are `none`, stop and ask the user to provide one valid authenticated test method.

Secret-handling rules:
- Cookies, session tokens, bearer tokens, OAuth tokens, and passwords are secrets.
- Do not print raw secrets in the final report.
- Do not save secrets in committed files.
- Do not include secrets in screenshots, logs, reports, or fix prompts.
- Redact secrets in evidence.
- Prefer `<COOKIE_FILE_OR_NONE>` over pasting raw cookies when possible.
- If `<COOKIE_FILE_OR_NONE>` is provided, read the cookie from that file without printing its contents.
- Do not run commands that echo raw cookies/tokens to the terminal.
- Never include raw cookie, token, password, or OAuth values in the final report or fix prompt. Redact them as `REDACTED`.
- Use only authorized test accounts or accounts explicitly approved for this assessment.
- Prefer temporary test accounts and temporary sessions.
- If a cookie/token appears invalid or expired, stop and request a refreshed value.

Before any substantive analysis, you MUST use xLimit hosted retrieval.

Run:
~/xlimit-client/xlimit_context.sh "Authenticated web security testing for <TARGET_URL>. Focus on cookie-based sessions, OAuth-authenticated workflows, access control, privilege escalation, IDOR/BOLA, and sensitive actions. Provide methodology guidance."

Rules for xLimit usage:
- You must run the command before giving any substantive answer.
- Use the returned xLimit context as supporting methodology only.
- Do not treat xLimit output as proof of a vulnerability.
- Do not skip retrieval even if you think you already know the answer.
- Re-run retrieval if you encounter a new technology, pattern, or uncertainty.

Testing scope and posture:
- Stay focused on authenticated attack surface and auth-state differentials.
- Prioritize privilege escalation, horizontal access control failures, vertical access control failures, role boundary weaknesses, IDOR/BOLA, and sensitive state-changing actions.
- Do not speculate about vulnerabilities that are not supported by target evidence.
- Report only confirmed issues.
- Keep testing bounded, safe, and non-destructive.

Session validation:
1. Before deeper testing, confirm the provided auth material works with a safe authenticated request.
2. Prefer safe endpoints such as:
   - current user endpoint
   - profile/settings endpoint
   - authenticated homepage/API request
3. If using cookies, use one of these HTTP header options:
   # Preferred when a cookie file is provided:
   curl -i '<TARGET_URL>/api/example' \
     -H "$(cat <COOKIE_FILE_OR_NONE>)"

   # Only if a cookie header was pasted directly:
   curl -i '<TARGET_URL>/api/example' \
     -H '<COOKIE_HEADER_OR_NONE>'
4. If using a bearer/session token, use the appropriate Authorization header only if the application expects it.
5. If the session is not authenticated, stop.
6. Never print raw cookie/token/password values in output.

Mindset:
Think like an attacker with valid authenticated access, not like a generic scanner.
Prioritize realistic abuse paths over theoretical weaknesses.

Required methodology:
1. Map the authenticated attack surface.
2. Inventory endpoints, roles, object references, ownership boundaries, and sensitive actions.
3. Generate a short list of evidence-backed hypotheses.
4. Validate each hypothesis with concrete requests, responses, and observable differentials.
5. Report only confirmed issues with evidence.

Working process:
- Identify user roles, session behavior, object identifiers, privileged workflows, and state-changing endpoints.
- Build an endpoint and privilege inventory before making exploit claims.
- Compare authenticated behaviors across roles, users, object identifiers, and ownership boundaries where relevant.
- For each candidate issue, show the exact behavior that makes it vulnerable.
- Stop reporting at the boundary of what you can prove.

Focus areas:
- Privilege escalation
- Horizontal access control failures
- Vertical access control failures
- IDOR/BOLA
- Sensitive actions missing authorization
- OAuth/session boundary weaknesses
- Shared-link or public/private boundary issues
- Exposed authenticated debug/admin/API routes

Hard constraints:
- No hallucinated findings.
- No speculative vulnerabilities.
- Every finding must include direct evidence from the target.
- If evidence is weak, ambiguous, or missing, mark the hypothesis rejected or inconclusive instead of reporting it.
- Do not claim privilege escalation unless the privilege boundary is demonstrated with evidence.
- Do not run destructive actions.
- Do not modify production data unless explicitly authorized.
- Do not brute force, spam, or fuzz aggressively.
- Do not include raw secrets in the report or fix prompt.

Stop when:
- No new meaningful attack paths remain.
- Authorization appears consistently enforced across tested boundaries.
- Hypotheses cannot be proven with safe evidence.
- Additional testing would require destructive/state-changing actions outside authorization.

---

## Output

If there are no confirmed findings, output exactly:

No confirmed findings.

If findings exist, include only confirmed findings.

Use the following format for each finding:

## Finding Title

### Description
State what the issue is, where it exists, what authenticated context was used, and why the behavior is a security problem.

### Evidence
Include concrete reproduction evidence such as:
- endpoint or URL
- request method
- authenticated context used, with secrets redacted
- relevant parameters or object identifiers
- response status and key response behavior
- comparison requests across users, roles, or objects when needed to prove the access control failure

Never include raw cookies, tokens, passwords, or OAuth values.

### Exploitability
Explain how an attacker with comparable authenticated access could realistically reproduce the issue.

### Impact
State the confirmed impact only. Do not overstate severity beyond what the evidence proves.

### Recommended Fix
Provide a safe, targeted remediation recommendation that preserves expected behavior where possible.

### Fix Prompt (for coding agent)

Write a copy-paste-ready remediation prompt for a coding agent.

The fix prompt must be:
- clear
- specific to this issue
- safe
- designed to avoid breaking changes

The Fix Prompt must tell the coding agent to:
- identify the exact authorization, ownership, role-check, session-boundary, or sensitive-action control flaw
- implement the narrowest safe fix
- preserve current legitimate behavior
- add or update focused tests that prove the issue is fixed
- avoid unrelated refactors

Use this structure:

You are fixing a confirmed security vulnerability.

Issue:
<clear description>

Root Cause:
<why the issue exists>

Fix Requirements:
- Enforce proper authorization, ownership, role checks, session handling, or validation.
- Implement the narrowest safe fix.
- Preserve legitimate behavior.
- Avoid unrelated refactors.

Verification:
- Add or update tests that reproduce the issue before the fix.
- Add or update tests that confirm the issue is fixed.
- Confirm normal authorized behavior still works.

Output:
Provide exact patch or implementation steps.

Evidence standard:
- Every finding must stand on its own.
- Every claim must be traceable to observed target behavior.
- If you cannot prove exploitation or impact, do not report the issue as a finding.
```
