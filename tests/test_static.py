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
