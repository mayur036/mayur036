#!/usr/bin/env python3
"""Scan public GitHub repositories for accidentally exposed Anthropic API keys.

This tool is intended for ethical security auditing and responsible disclosure.
It respects GitHub rate limits, avoids downloading large or binary files, and
never stores or outputs full keys.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import time
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

GITHUB_API = "https://api.github.com"
MAX_FILE_SIZE_BYTES = 200_000
# Underscore is allowed for permissive detection, matching the documented pattern.
ANTHROPIC_REGEX = re.compile(r"sk-ant-[a-zA-Z0-9-_]{20,}")
KEYWORDS = ("anthropic", "claude", "api_key")


def _headers() -> Dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "anthropic-scanner",
    }
    token = os.getenv("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _sleep_for_rate_limit(reset_header: Optional[str]) -> None:
    if not reset_header:
        time.sleep(60)
        return
    try:
        reset_epoch = int(reset_header)
    except ValueError:
        time.sleep(60)
        return
    sleep_for = max(reset_epoch - int(time.time()), 1)
    time.sleep(sleep_for)


def github_get_json(
    path: str, params: Optional[Dict[str, str]] = None, allow_404: bool = False
) -> Tuple[Optional[dict], Dict[str, str]]:
    """Perform a GitHub GET request returning JSON and headers."""
    query = f"?{urlencode(params)}" if params else ""
    url = f"{GITHUB_API}{path}{query}"

    while True:
        try:
            req = Request(url, headers=_headers())
            with urlopen(req) as resp:
                body = resp.read()
                headers = dict(resp.headers)
                remaining = headers.get("X-RateLimit-Remaining")
                reset = headers.get("X-RateLimit-Reset")
                if remaining is not None:
                    try:
                        remaining_int = int(remaining)
                    except ValueError:
                        remaining_int = 1
                    if remaining_int <= 2:
                        _sleep_for_rate_limit(reset)
                return json.loads(body.decode("utf-8")), headers
        except HTTPError as error:
            if error.code == 404 and allow_404:
                return None, dict(error.headers)
            if error.code == 403 and error.headers.get("X-RateLimit-Remaining") == "0":
                _sleep_for_rate_limit(error.headers.get("X-RateLimit-Reset"))
                continue
            raise


def fetch_repositories(owner: str) -> List[dict]:
    """List public repositories for a GitHub user or organization."""
    repos: List[dict] = []
    page = 1
    fetch_path = f"/users/{owner}/repos"

    # Attempt user endpoint first; fall back to orgs if needed.
    initial_data, _ = github_get_json(fetch_path, {"per_page": 1}, allow_404=True)
    if initial_data is None:
        fetch_path = f"/orgs/{owner}/repos"

    while True:
        data, _ = github_get_json(
            fetch_path,
            {"per_page": 100, "page": page, "type": "public", "sort": "updated"},
        )
        if not data:
            break
        repos.extend(data)
        if len(data) < 100:
            break
        page += 1
    return repos


def is_text_content(raw: bytes) -> bool:
    """Heuristic to skip binary files."""
    if b"\x00" in raw:
        return False
    if not raw:
        return False
    sample = raw[:2048]
    text_chars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x7F)))
    nontext = sum(byte not in text_chars for byte in sample)
    return nontext / len(sample) < 0.30


def mask_key(key: str) -> str:
    """Mask a key to avoid exposing sensitive data."""
    prefix = key[:7]
    suffix = key[-4:] if len(key) > 11 else ""
    mask_length = max(len(key) - len(prefix) - len(suffix), 0)
    return f"{prefix}{'*' * mask_length}{suffix}"


def find_in_text(
    content: str, repo: str, path: str
) -> Iterable[Dict[str, object]]:
    findings: List[Dict[str, object]] = []
    for line_number, line in enumerate(content.splitlines(), start=1):
        regex_hits = list(ANTHROPIC_REGEX.finditer(line))
        if regex_hits:
            for match in regex_hits:
                findings.append(
                    {
                        "repository": repo,
                        "file_path": path,
                        "line_number": line_number,
                        "masked_key": mask_key(match.group(0)),
                        "detection_type": "regex",
                        "snippet": line.strip(),
                        "remediation": "Rotate the Anthropic API key and update any dependent services.",
                    }
                )
            continue

        lowered = line.lower()
        if any(keyword in lowered for keyword in KEYWORDS):
            findings.append(
                {
                    "repository": repo,
                    "file_path": path,
                    "line_number": line_number,
                    "masked_key": None,
                    "detection_type": "keyword",
                    "snippet": line.strip(),
                    "remediation": "Review this line for potential secret exposure and rotate keys if necessary.",
                }
            )
    return findings


def fetch_file_content(
    owner: str, repo: str, path: str, ref: str
) -> Optional[str]:
    data, _ = github_get_json(
        f"/repos/{owner}/{repo}/contents/{path}", {"ref": ref}, allow_404=True
    )
    if data is None or isinstance(data, list):
        return None
    if data.get("size", 0) > MAX_FILE_SIZE_BYTES:
        return None
    if data.get("encoding") != "base64" or "content" not in data:
        return None
    try:
        raw = base64.b64decode(data["content"], validate=True)
    except (ValueError, base64.binascii.Error):
        return None
    if not is_text_content(raw):
        return None
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return None


def scan_repository(owner: str, repo: dict) -> List[Dict[str, object]]:
    repo_name = repo["name"]
    default_branch = repo.get("default_branch") or "main"
    tree_data, _ = github_get_json(
        f"/repos/{owner}/{repo_name}/git/trees/{default_branch}",
        {"recursive": "1"},
        allow_404=True,
    )
    if not tree_data or "tree" not in tree_data:
        return []

    findings: List[Dict[str, object]] = []
    for entry in tree_data["tree"]:
        if entry.get("type") != "blob":
            continue
        if entry.get("size", 0) and entry["size"] > MAX_FILE_SIZE_BYTES:
            continue
        path = entry.get("path", "")
        content = fetch_file_content(owner, repo_name, path, default_branch)
        if not content:
            continue
        findings.extend(find_in_text(content, repo_name, path))
    return findings


def scan_owner(owner: str) -> Dict[str, object]:
    repositories = fetch_repositories(owner)
    results: List[Dict[str, object]] = []
    for repo in repositories:
        results.extend(scan_repository(owner, repo))

    return {
        "owner": owner,
        "scanned_repositories": len(repositories),
        "findings": results,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "advice": "If any keys are found, immediately rotate them in Anthropic settings and audit usage.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Scan public GitHub repositories for potential Anthropic API key exposure."
        )
    )
    parser.add_argument("owner", help="GitHub username or organization to scan")
    parser.add_argument(
        "--output",
        "-o",
        default="scan_results.json",
        help="Path to write JSON results (default: scan_results.json)",
    )
    args = parser.parse_args()

    try:
        results = scan_owner(args.owner)
    except HTTPError as error:
        print(f"GitHub API error: {error}", file=sys.stderr)
        sys.exit(1)

    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)

    findings = results["findings"]
    if findings:
        print(f"Potential exposures found: {len(findings)}")
        for finding in findings:
            key_info = finding["masked_key"] or "[keyword match]"
            print(
                f"- {finding['repository']}:{finding['file_path']} "
                f"(line {finding['line_number']}): {key_info}"
            )
        print("Rotate any exposed keys and follow responsible disclosure practices.")
    else:
        print("No potential Anthropic API keys found.")
    print(f"Results saved to {args.output}")


if __name__ == "__main__":
    main()
