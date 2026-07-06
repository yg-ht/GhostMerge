from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_caddy_example_mounts_ghostmerge_under_merge_prefix():
    caddyfile = PROJECT_ROOT / "packaging" / "caddy" / "Caddyfile.example"

    content = caddyfile.read_text(encoding="utf-8")

    assert "redir /merge /merge/ 308" in content
    assert "handle_path /merge/*" in content
    assert "reverse_proxy 127.0.0.1:5000" in content
    assert 'web_access.reverse_proxy_prefix to "/merge"' in content
    assert "header_up X-Forwarded-Prefix /merge" in content
    assert "header_up X-Forwarded-For {remote_host}" in content
