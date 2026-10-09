# SSH Security Auditor

Internal tool to audit the SSH posture of routers and other network devices:
negotiation (algorithms, host keys, Terrapin, post-quantum KEX, FIPS-oriented path and
authentication methods), functional authentication, device inventory and effective
`sshd` configuration. Yescrypt and concurrency are planned next. Results are cached in
server RAM for a limited time and can be exported from the web or Claude (MCP).

For use on the **internal network** only, against **authorised devices** (mandatory
allowlist).

## Status

Phases 1–3 are implemented: the plugin engine; connectivity, negotiation, authentication,
inventory and effective `sshd -T -C` tests; API; web UI with live progress;
JSON/HTML/CSV export; detailed comparison; shared device profiles and policies; and an
MCP server for Claude Code and Claude Desktop. The full design is in `instrucciones.md`.

## Using it from Claude (MCP)

The MCP server runs in the same process and port as the web: `http://<server>:7284/mcp`
(Streamable HTTP, no token). The page `http://<server>:7284/claude` has the
`claude mcp add` command for Claude Code, a `.mcp.json` to download, and a `.mcpb`
bundle for Claude Desktop (a local stdio→HTTP bridge, because Claude's remote connectors
can't reach the internal network).

Tools: `list_tests`, `list_profiles`, `start_scan`, `get_scan`, `cancel_scan`,
`compare_scans`. The server applies the allowlist, the profile limits and the
`confirm_impact` rule to every request, from the web or from Claude.
`max_active_scans` in `config.yaml` caps the scans Claude runs in the background.

## Profiles and policies

- **Built-in** ones ship in `config/profiles/` and `config/policies/` and can't be
  changed from the web.
- Engineers can **download** any of them or a commented **example**, edit it, and
  **upload** it. Uploads are stored on the server (`custom_dir`) and every engineer sees
  them.
- Only the engineer who uploaded an item can **delete** it, from the same browser: the
  server returns an owner token on upload and the browser keeps it. If that browser's
  data is lost, an administrator deletes the file from `custom_dir` (the `.yaml` and its
  `.meta.json`).
- A policy used by a profile can't be deleted until the profile is.

## Development

```bash
python3 -m venv .venv            # on Debian 13 this may need get-pip (see below)
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest -q              # whole suite
SSH_AUDITOR_CONFIG=config/config.example.yaml .venv/bin/python -m ssh_auditor
```

Then open `http://localhost:7284/`. Set `allow_networks` in the YAML before scanning.
Uploads go to `data/` in development.

> If `python3 -m venv` creates the environment without `pip` (minimal Debian), bootstrap it:
> `python3 -m venv --without-pip .venv && curl -fsSL https://bootstrap.pypa.io/get-pip.py | .venv/bin/python`

## Deployment on Debian 13

```bash
sudo deploy/install.sh
sudo nano /etc/ssh-auditor/config.yaml   # set allow_networks
sudo systemctl enable --now ssh-auditor
```

## Security

- Mandatory allowlist of target networks (empty = reject everything).
- The server stores no credentials and no scan results on disk; the result cache is in
  RAM with a TTL.
- Credentials are sent only with a scan. The web saves them only when the engineer clicks
  **Save**, as plain text in that browser's `localStorage`, keyed by target host and port;
  **Forget** removes that entry.
- The only thing written to disk is uploaded profiles and policies (YAML validated against
  a strict schema, 64 KB max) in `/var/lib/ssh-auditor`.
- Internal network only, no login token.

## Licence

Internal.
