"""RED: First failing test for mcp-guard core scanner."""

from mcp_guard.scanner import Scanner, ScanResult, Severity


def test_scanner_flags_tool_with_shell_command():
    """A tool that accepts shell commands must be flagged as CRITICAL."""
    fake_tool = {
        "name": "run_bash",
        "description": "Execute a bash command on the server",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command to run"}
            },
            "required": ["command"],
        },
    }

    scanner = Scanner()
    results = scanner.scan_tool(fake_tool)

    assert len(results) > 0, "Scanner must return at least one finding"

    shell_findings = [
        r for r in results if "shell" in r.rule_id or "command" in r.rule_id
    ]
    assert len(shell_findings) > 0, "Must flag shell/command injection"
    assert shell_findings[0].severity == Severity.CRITICAL
    assert isinstance(shell_findings[0], ScanResult)


def test_scanner_passes_safe_tool():
    """A read-only tool with constrained input must pass cleanly."""
    safe_tool = {
        "name": "get_weather",
        "description": "Get current weather for a city",
        "inputSchema": {
            "type": "object",
            "properties": {
                "city": {"type": "string", "enum": ["tel-aviv", "london", "nyc"]}
            },
            "required": ["city"],
        },
    }

    scanner = Scanner()
    results = scanner.scan_tool(safe_tool)

    criticals = [r for r in results if r.severity == Severity.CRITICAL]
    assert len(criticals) == 0, "Safe tool must not have critical findings"


def test_scanner_flags_url_parameter_as_ssrf():
    """A tool that accepts a URL parameter must be flagged for SSRF risk."""
    url_tool = {
        "name": "fetch_url",
        "description": "Fetch content from a URL",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string", "format": "uri"}},
            "required": ["url"],
        },
    }

    scanner = Scanner()
    results = scanner.scan_tool(url_tool)

    ssrf_findings = [r for r in results if "ssrf" in r.rule_id]
    assert len(ssrf_findings) > 0, "Must flag SSRF risk on URL parameter"
    assert ssrf_findings[0].severity in (Severity.CRITICAL, Severity.WARNING)


def test_scanner_flags_second_url_param_after_benign_first():
    """Regression for #131: an enum-constrained URL param first must not hide
    a free-form URL param later in the schema (attacker-shaped evasion)."""
    tool = {
        "name": "fetch_tool",
        "description": "fetches data",
        "inputSchema": {
            "properties": {
                "callback": {
                    "type": "string",
                    "description": "callback url",
                    "enum": ["https://hooks.example.com"],
                },
                "target": {"type": "string", "description": "target url to fetch"},
            }
        },
    }

    results = Scanner().scan_tool(tool)
    ssrf = [r for r in results if r.rule_id == "ssrf-risk"]
    by_param = {r.message.split("'")[1]: r for r in ssrf}

    assert "callback" in by_param, "enum-constrained URL param must be flagged"
    assert by_param["callback"].severity == Severity.WARNING
    assert "target" in by_param, (
        "free-form URL param after a benign one must be flagged (#131)"
    )
    assert by_param["target"].severity == Severity.CRITICAL


def test_scanner_flags_all_shell_params_not_just_first():
    """Regression for #131: every shell-like parameter is reported, not only
    the first match."""
    tool = {
        "name": "deploy_helper",
        "description": "helps with deployments",
        "inputSchema": {
            "properties": {
                "command": {"type": "string", "description": "command to run"},
                "script_path": {
                    "type": "string",
                    "description": "path to helper script",
                },
            }
        },
    }

    results = Scanner().scan_tool(tool)
    shell = [r for r in results if r.rule_id == "shell-injection"]
    flagged = {r.message.split("'")[1] for r in shell}

    assert flagged == {"command", "script_path"}, (
        f"both shell params must be flagged, got {flagged}"
    )
    assert all(r.severity == Severity.CRITICAL for r in shell)


def test_scanner_flags_multiple_freeform_url_params():
    """Three unconstrained URL params produce three CRITICAL ssrf-risk findings."""
    tool = {
        "name": "multi_fetch",
        "description": "fetches from several places",
        "inputSchema": {
            "properties": {
                "endpoint": {"type": "string", "format": "uri"},
                "webhook": {"type": "string", "description": "webhook to notify"},
                "link": {"type": "string", "description": "link to follow"},
            }
        },
    }

    results = Scanner().scan_tool(tool)
    ssrf = [r for r in results if r.rule_id == "ssrf-risk"]

    assert len(ssrf) == 3, f"expected 3 ssrf findings, got {len(ssrf)}"
    assert all(r.severity == Severity.CRITICAL for r in ssrf)
