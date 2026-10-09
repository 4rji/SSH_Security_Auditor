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


def test_credentials_ui_can_save_and_forget_per_target():
    base = Path("ssh_auditor/web/static")
    idx = (base / "index.html").read_text()
    js = (base / "app.js").read_text()
    # The credential store/form moved to the shared module.
    core = (base / "core.js").read_text()

    # The form covers every Phase 3 method and explicitly describes plaintext storage.
    for control in (
        "authMethod", "authUsername", "authPassword", "authPrivateKey",
        "authPassphrase", "authCertificate", "authResponses",
        "credentialSave", "credentialForget", "credentialMsg",
    ):
        assert f'id="{control}"' in idx
    assert "stores them as plain text in this browser" in idx
    assert 'id="authPassword" type="password"' in idx
    assert 'id="authPassphrase" type="password"' in idx

    # Save/Forget share one versioned localStorage map indexed by normalized host:port.
    assert 'const CREDENTIALS_KEY = "sshAuditor.credentials.v1"' in core
    assert "trim().toLowerCase().replace(/\\.$/, \"\")" in core
    assert "`${normalized}:${parseInt(port || \"22\", 10)}`" in core
    assert "all[key] = credential" in core
    assert "delete all[key]" in core
    assert 'addEventListener("click", saveCredentials)' in core
    assert 'addEventListener("click", forgetCredentials)' in core
    # Username-only negative checks travel without requiring another secret (scanBody).
    assert 'credential.method !== "none" || credential.username' in js
    assert "body.credentials = credential" in js
    assert 'data-methods="none password private_key certificate keyboard_interactive"' in idx


def test_profile_metadata_exposes_remote_commands_before_a_scan():
    base = Path("ssh_auditor/web/static")
    idx = (base / "index.html").read_text()
    js = (base / "app.js").read_text()

    assert 'id="profileMeta"' in idx
    # The form no longer asks for model, firmware or tags.
    for field in ("model", "firmware", "tags"):
        assert f'id="{field}"' not in idx
        assert f'$("{field}")' not in js
    assert "it.shell" in js
    assert "it.safe_command" in js
    # Metadata is rendered as text, so custom profile commands cannot inject markup.
    assert "$(k.meta).textContent = text" in js


def test_risky_tests_are_grouped_and_locked_until_approved():
    base = Path("ssh_auditor/web/static")
    idx = (base / "index.html").read_text()
    js = (base / "app.js").read_text()

    # The approval lives inside the medium/high-impact group it unlocks.
    group = idx[idx.index('id="riskyGroup"'):]
    assert group.index('id="confirmImpact"') < group.index('id="testsRisky"')
    assert 'addEventListener("change", updateRiskyTests)' in js
    assert "c.disabled = !approved" in js
    assert "if (!approved) c.checked = false" in js
    # "Select all" never ticks a locked test.
    assert '.tchk:not(:disabled)' in js
    assert 'const RISKY_IMPACTS = ["medium", "high"]' in js


def test_load_testing_page_reuses_core_module():
    base = Path("ssh_auditor/web/static")
    assert (base / "core.js").exists()
    load = (base / "load.html").read_text()
    assert "core.js" in load and "load.js" in load
    assert "Load testing" in load
    # F parameter controls and the run button are present.
    for control in ("iterations", "errorRatePct", "p95Factor", "runLoad"):
        assert f'id="{control}"' in load
    # Both pages share the streaming/render code (no duplicated renderResults).
    app = (base / "app.js").read_text()
    loadjs = (base / "load.js").read_text()
    core = (base / "core.js").read_text()
    assert "function renderResults" in core
    assert "function renderResults" not in app and "function renderResults" not in loadjs
    assert "/core.js" in (base / "index.html").read_text()
    # The main page links to the load testing page.
    assert "/load.html" in (base / "index.html").read_text()
