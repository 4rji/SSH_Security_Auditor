from pathlib import Path


def test_static_files_reference_api():
    base = Path("ssh_auditor/web/static")
    idx = (base / "index.html").read_text()
    js = (base / "app.js").read_text()
    assert "SSH Security Auditor" in idx
    assert "/api/v1/scans" in js
    assert "sessionStorage" in js
    assert (base / "claude.html").exists()
    # Every page applies the saved theme early and loads the shared switch.
    for page in ("index.html", "claude.html"):
        text = (base / page).read_text()
        assert "sshAuditor.theme" in text and "/theme.js" in text
    assert "run_by" in js
    claude = (base / "claude.html").read_text()
    assert "/claude/ssh-auditor.mcpb" in claude and "/claude/mcp.json" in claude
    assert "claude mcp add --transport http ssh-auditor" in claude
    assert "Phase 2" not in claude  # the page no longer says the MCP is coming
    # Port fields refuse what the server would reject anyway.
    assert idx.count('min="1" max="65535"') == 3
    # navigator.clipboard only exists on HTTPS or localhost; the server is plain HTTP.
    assert "execCommand" in claude
