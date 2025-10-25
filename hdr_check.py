#!/usr/bin/env python3
"""
hdr_check.py

Sample output (--sample-output):

Vulnerable site example:
$ python hdr_check.py http://vulnerable.example
INFO   http://vulnerable.example  Fetching URL
FAIL   Strict-Transport-Security      missing -> Add HSTS with max-age>=31536000; includeSubDomains
FAIL   Content-Security-Policy       missing -> Implement restrictive CSP (avoid 'unsafe-*')
FAIL   X-Frame-Options               missing -> Set X-Frame-Options: DENY or SAMEORIGIN
FAIL   X-Content-Type-Options        missing -> Set X-Content-Type-Options: nosniff
FAIL   Referrer-Policy               missing -> Set Referrer-Policy: strict-origin-when-cross-origin
FAIL   Set-Cookie flags              cookie missing Secure/HttpOnly/SameSite -> Ensure cookies use Secure; HttpOnly; SameSite

Hardened site example:
$ python hdr_check.py https://secure.example
INFO   https://secure.example  Fetching URL
PASS   Strict-Transport-Security      max-age=31536000; includeSubDomains; preload
PASS   Content-Security-Policy       present (no obvious unsafe constructs)
PASS   X-Frame-Options               SAMEORIGIN
PASS   X-Content-Type-Options        nosniff
PASS   Referrer-Policy               strict-origin-when-cross-origin
PASS   Set-Cookie flags              Secure; HttpOnly; SameSite=Lax

Exit codes: 0=all PASS, 1=any FAIL, 2=network/runtime error

OWASP references mapping (examples):
- HSTS: https://owasp.org/www-project-top-ten/ (see transport security) and https://owasp.org/www-project-cheat-sheets/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
- CSP & Clickjacking: https://owasp.org/www-project-cheat-sheets/Content_Security_Policy_Cheat_Sheet/
- X-Content-Type-Options: https://owasp.org/www-project-cheat-sheets/ (MIME sniffing recommendations)
- Referrer-Policy: https://owasp.org/www-project-cheat-sheets/ (privacy headers)
- Cookie flags: https://owasp.org/www-project-cheat-sheets/Session_Management_Cheat_Sheet/

"""
from __future__ import annotations

import argparse
import json
import sys
import re
from typing import Dict, List, Tuple, Any

# Try imports and instruct if missing
try:
    import httpx
except Exception:  # pragma: no cover - runtime import
    print("Missing dependency: httpx. Install with: pip install httpx")
    sys.exit(2)

try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
except Exception:  # pragma: no cover - runtime import
    print("Missing dependency: rich. Install with: pip install rich")
    sys.exit(2)

console = Console()


def print_banner() -> None:
    """Print a small ASCII banner for the tool."""
    banner = [
        "+----------------+",
        "|    HDR CHECK   |",
        "+----------------+",
        "",
        " Header Security Checker - httpx + rich",
    ]
    for line in banner:
        console.print(f"[bold cyan]{line}[/bold cyan]")


def fetch_url(url: str, timeout: float = 8.0, follow_redirects: bool = True) -> Tuple[httpx.Response, List[str]]:
    """Fetch a URL using httpx and return (response, errors).

    Returns a list of error messages (empty on success). Raises nothing; network errors are reported via the errors list.
    """
    errors: List[str] = []
    if "://" not in url:
        url = "https://" + url
    try:
        with httpx.Client(follow_redirects=follow_redirects, timeout=timeout, verify=True) as client:
            resp = client.get(url)
        return resp, errors
    except httpx.RequestError as e:
        errors.append(str(e))
        return None, errors  # type: ignore


def _get_set_cookie_lines(resp: httpx.Response) -> List[str]:
    """Return all Set-Cookie header lines as provided by the response."""
    raw = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
    # fallback: iterate
    if not raw:
        raw = [v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"] if hasattr(resp.headers, "multi_items") else []
    return raw


def analyze_headers(resp: httpx.Response) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    """Analyze response headers and return (results, raw_headers).
    
    Returns:
        - results: List of check results, each with {name, status, evidence, recommendation, manual_test, issue_detail}
        - raw_headers: Dict of original response headers
    """
    checks: List[Dict[str, Any]] = []
    headers = {k.lower(): v for k, v in resp.headers.items()}  # lower-case mapping

    def get_specific_issues(header_name: str, value: str) -> str:
        """Return specific issues found in a header value."""
        header_name = header_name.lower()
        value = value.lower()
        
        if header_name == "strict-transport-security":
            issues = []
            if "max-age=" in value:
                try:
                    max_age = int(re.search(r"max-age=(\d+)", value).group(1))
                    if max_age < 31536000:
                        issues.append(f"max-age too short: {max_age}s < 31536000s (1 year)")
                except (AttributeError, ValueError):
                    issues.append("invalid max-age value")
            else:
                issues.append("missing max-age")
            if "includesubdomains" not in value:
                issues.append("missing includeSubDomains directive")
            return "; ".join(issues) if issues else ""
            
        elif header_name == "content-security-policy":
            issues = []
            if "unsafe-inline" in value:
                issues.append("uses unsafe-inline (enables inline scripts/styles)")
            if "unsafe-eval" in value:
                issues.append("uses unsafe-eval (enables dynamic code evaluation)")
            if "*" in value:
                directives = re.findall(r"([a-z-]+)\s+[^;]+", value)
                wildcards = [d for d in directives if "*" in d]
                if wildcards:
                    issues.append(f"overly permissive wildcards in: {', '.join(wildcards)}")
            return "; ".join(issues) if issues else ""
            
        elif header_name == "x-frame-options":
            if value not in ("deny", "sameorigin"):
                return f"invalid value: {value} (must be DENY or SAMEORIGIN)"
                
        elif header_name == "permissions-policy" or header_name == "feature-policy":
            if "*" in value:
                return "contains overly permissive wildcards"
                
        elif "cookie" in header_name:
            issues = []
            if "secure" not in value:
                issues.append("missing Secure flag")
            if "httponly" not in value:
                issues.append("missing HttpOnly flag")
            if "samesite" not in value:
                issues.append("missing SameSite attribute")
            elif "samesite=none" in value and "secure" not in value:
                issues.append("SameSite=None requires Secure flag")
            return "; ".join(issues) if issues else ""
            
        elif header_name == "referrer-policy":
            unsafe = {"unsafe-url", "origin", "no-referrer-when-downgrade"}
            value_parts = {p.strip() for p in value.split(",")}
            if any(u in value_parts for u in unsafe):
                return f"uses less secure policy: {value}"
                
        return ""

    def add(name: str, status: str, evidence: str = "", rec: str = "", manual_test: str = "") -> None:
        # Get specific issues if the header exists but has problems
        issue_detail = ""
        if status == "FAIL" and evidence and evidence != "missing":
            issue_detail = get_specific_issues(name, evidence)
        
        checks.append({
            "name": name,
            "status": status,
            "evidence": evidence,
            "recommendation": rec,
            "manual_test": manual_test,
            "issue_detail": issue_detail
        })

    # HSTS: OWASP HTTP Strict Transport Security Cheat Sheet
    sts = headers.get("strict-transport-security")
    scheme = resp.url.scheme.lower()
    if scheme != "https":
        add(
            "Strict-Transport-Security",
            "FAIL",
            evidence=f"resource served over {scheme}",
            rec="Serve over HTTPS and enable HSTS with max-age>=31536000; includeSubDomains; preload if appropriate.",
        )
    else:
        if not sts:
            add(
                "Strict-Transport-Security",
                "FAIL",
                evidence="missing",
                rec="Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload.",
            )
        else:
            m = re.search(r"max-age=(\d+)", sts, flags=re.I)
            max_age = int(m.group(1)) if m else 0
            if max_age < 31536000 or "includesubdomains" not in sts.lower():
                add("Strict-Transport-Security", "FAIL", evidence=sts, rec="Increase max-age to >=31536000 and includeSubDomains.")
            else:
                add("Strict-Transport-Security", "PASS", evidence=sts, rec="HSTS configured.")

    # Content-Security-Policy: OWASP CSP Cheat Sheet
    csp = headers.get("content-security-policy")
    if not csp:
        add("Content-Security-Policy", "FAIL", evidence="missing", rec="Implement a restrictive CSP without 'unsafe-inline' and avoid wildcard sources.")
    else:
        issues = []
        if "unsafe-inline" in csp or "unsafe-eval" in csp:
            issues.append("uses unsafe-*")
        if "*" in csp:
            issues.append("contains wildcard ''*")
        if issues:
            add("Content-Security-Policy", "FAIL", evidence=csp, rec="Harden CSP: remove 'unsafe-*' and avoid '*' sources; prefer nonce/hash.")
        else:
            add("Content-Security-Policy", "PASS", evidence=csp, rec="CSP present.")

    # X-Frame-Options: clickjacking
    xfo = headers.get("x-frame-options")
    if not xfo:
        add("X-Frame-Options", "FAIL", evidence="missing", rec="Set X-Frame-Options: DENY or SAMEORIGIN or use CSP frame-ancestors.")
    else:
        if xfo.strip().upper() not in ("DENY", "SAMEORIGIN"):
            add("X-Frame-Options", "FAIL", evidence=xfo, rec="Use DENY or SAMEORIGIN; prefer CSP frame-ancestors for complex cases.")
        else:
            add("X-Frame-Options", "PASS", evidence=xfo, rec="OK.")

    # X-Content-Type-Options
    xcto = headers.get("x-content-type-options")
    if not xcto:
        add("X-Content-Type-Options", "FAIL", evidence="missing", rec="Add X-Content-Type-Options: nosniff.")
    else:
        if xcto.strip().lower() != "nosniff":
            add("X-Content-Type-Options", "FAIL", evidence=xcto, rec="Set to 'nosniff'.")
        else:
            add("X-Content-Type-Options", "PASS", evidence=xcto, rec="OK.")

    # Referrer-Policy
    rp = headers.get("referrer-policy")
    if not rp:
        add("Referrer-Policy", "FAIL", evidence="missing", rec="Set a restrictive Referrer-Policy (e.g., strict-origin-when-cross-origin or no-referrer).")
    else:
        bad = {"no-referrer-when-downgrade", "origin-when-cross-origin"}
        if rp.strip().lower() in bad:
            add("Referrer-Policy", "FAIL", evidence=rp, rec="Use strict-origin-when-cross-origin or no-referrer.")
        else:
            add("Referrer-Policy", "PASS", evidence=rp, rec="OK.")

    # Permissions-Policy / Feature-Policy
    pp = headers.get("permissions-policy") or headers.get("feature-policy")
    if not pp:
        add("Permissions-Policy", "FAIL", evidence="missing", rec="Add Permissions-Policy to restrict powerful features (camera, geolocation, etc.).")
    else:
        add("Permissions-Policy", "PASS", evidence=pp, rec="OK.")

    # Expect-CT
    ect = headers.get("expect-ct")
    if not ect:
        add("Expect-CT", "INFO", evidence="missing", rec="Optional: Consider Expect-CT with a report-uri to detect misissued certs.")
    else:
        add("Expect-CT", "PASS", evidence=ect, rec="OK.")

    # COOP / COEP
    coop = headers.get("cross-origin-opener-policy")
    coep = headers.get("cross-origin-embedder-policy")
    if not coop:
        add("Cross-Origin-Opener-Policy", "INFO", evidence="missing", rec="Consider COOP 'same-origin' to improve isolation when needed.")
    else:
        add("Cross-Origin-Opener-Policy", "PASS", evidence=coop, rec="OK.")
    if not coep:
        add("Cross-Origin-Embedder-Policy", "INFO", evidence="missing", rec="Consider COEP 'require-corp' if using cross-origin isolation features.")
    else:
        add("Cross-Origin-Embedder-Policy", "PASS", evidence=coep, rec="OK.")

    # Server / X-Powered-By disclosure
    server = headers.get("server")
    xpb = headers.get("x-powered-by")
    if server:
        add("Server header", "FAIL", evidence=server, rec="Remove or minimize Server header to reduce fingerprinting.")
    else:
        add("Server header", "PASS", evidence="absent", rec="OK.")
    if xpb:
        add("X-Powered-By", "FAIL", evidence=xpb, rec="Remove X-Powered-By header to avoid exposing technology stack.")
    else:
        add("X-Powered-By", "PASS", evidence="absent", rec="OK.")

    # Set-Cookie flags
    set_cookie_lines = _get_set_cookie_lines(resp)
    # Names of cookies that are commonly intentionally not HttpOnly (e.g., client-side CSRF tokens)
    csrf_cookie_whitelist = {"xsrf-token", "x-xsrf-token", "csrf-token", "x-csrf-token", "xsrf", "csrf"}
    if not set_cookie_lines:
        add("Set-Cookie flags", "INFO", evidence="no cookies set", rec="If sessions exist, ensure cookies have Secure; HttpOnly; SameSite.")
    else:
        any_fail = False
        evid = []
        for line in set_cookie_lines:
            evid.append(line)
            ll = line.lower()
            missing = []
            if "secure" not in ll:
                missing.append("Secure")
            # Determine cookie name to allow exceptions for known XSRF/CSRF token cookies
            cookie_name = None
            m_name = re.match(r"\s*([^=;\s]+)\s*=", line)
            if m_name:
                cookie_name = m_name.group(1).strip().lower()

            if "httponly" not in ll:
                # allow missing HttpOnly for known client-side CSRF cookie names
                if not cookie_name or cookie_name not in csrf_cookie_whitelist:
                    missing.append("HttpOnly")
            if "samesite" not in ll:
                missing.append("SameSite")
            else:
                m = re.search(r"samesite=([^;\s]+)", ll)
                if m and m.group(1).strip().lower() == "none" and "secure" not in ll:
                    missing.append("SameSite=None requires Secure")
            if missing:
                any_fail = True
        if any_fail:
            add("Set-Cookie flags", "FAIL", evidence="; ".join(evid), rec="Ensure cookies include Secure; HttpOnly; and SameSite where appropriate.")
        else:
            add("Set-Cookie flags", "PASS", evidence="; ".join(evid), rec="OK.")

    # Get raw headers while preserving original case
    raw_headers = dict(resp.headers.items())
    return checks, raw_headers


def enrich_results(results: List[Dict[str, Any]]) -> None:
    """Append OWASP WSTG/cheatsheet references and manual_test curl examples to each result when missing.

    This mutates the list in-place, adding keys `wstg_ref` and `manual_test` when possible.
    """
    wstg_base = "https://owasp.org/www-project-web-security-testing-guide/latest/"
    cheats = {
        "Strict-Transport-Security": (
            "https://owasp.org/www-project-cheat-sheets/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
            "curl -sI https://example.com | grep -i Strict-Transport-Security",
        ),
        "Content-Security-Policy": (
            "https://owasp.org/www-project-cheat-sheets/Content_Security_Policy_Cheat_Sheet/",
            "curl -sI https://example.com | grep -i Content-Security-Policy",
        ),
        "X-Frame-Options": (
            wstg_base + "#client-side-testing",
            "curl -sI https://example.com | grep -i X-Frame-Options",
        ),
        "X-Content-Type-Options": (
            wstg_base + "#client-side-testing",
            "curl -sI https://example.com | grep -i X-Content-Type-Options",
        ),
        "Referrer-Policy": (wstg_base + "#client-side-testing", "curl -sI https://example.com | grep -i Referrer-Policy"),
        "Permissions-Policy": (wstg_base + "#client-side-testing", "curl -sI https://example.com | grep -i Permissions-Policy"),
        "Expect-CT": (wstg_base + "#client-side-testing", "curl -sI https://example.com | grep -i Expect-CT"),
        "Cross-Origin-Opener-Policy": (wstg_base + "#client-side-testing", "curl -sI https://example.com | grep -i Cross-Origin-Opener-Policy"),
        "Cross-Origin-Embedder-Policy": (wstg_base + "#client-side-testing", "curl -sI https://example.com | grep -i Cross-Origin-Embedder-Policy"),
        "Server header": (wstg_base + "#information-disclosure", "curl -sI https://example.com | grep -i '^Server:'"),
        "X-Powered-By": (wstg_base + "#information-disclosure", "curl -sI https://example.com | grep -i X-Powered-By"),
        "Set-Cookie flags": (
            "https://owasp.org/www-project-cheat-sheets/Session_Management_Cheat_Sheet/",
            "curl -sI https://example.com | grep -i Set-Cookie",
        ),
        "Content-Security-Policy": (
            "https://owasp.org/www-project-cheat-sheets/Content_Security_Policy_Cheat_Sheet/",
            "curl -sI https://example.com | grep -i Content-Security-Policy",
        ),
    }

    for r in results:
        name = r.get("name")
        if not name:
            continue
        # add wstg_ref only if not present
        if "wstg_ref" not in r or not r.get("wstg_ref"):
            ref, manual = cheats.get(name, (wstg_base, f"curl -sI {r.get('url', 'https://example.com')} | grep -i {name}"))
            # attach short WSTG/cheatsheet pointer
            r["wstg_ref"] = ref
            # if there's already a manual_test, don't override
            if not r.get("manual_test"):
                r["manual_test"] = manual
            # append the ref to recommendation if not already present
            rec = r.get("recommendation") or ""
            if ref not in rec:
                sep = " " if rec else ""
                r["recommendation"] = f"{rec}{sep}See: {ref}"


def format_output(results: List[Dict[str, Any]], url: str, headers: Dict[str, str], json_out: bool = False) -> int:
    """Format and print results using rich or emit JSON. Returns exit status (0 or 1).

    Exit code 0 if no FAIL, 1 if any FAIL.
    """
    # Enrich results with WSTG references and manual_test examples before output
    try:
        enrich_results(results)
    except Exception:
        # non-fatal: proceed without enrichment
        pass

    if json_out:
        out = {"url": str(url), "results": results, "raw_headers": headers}
        print(json.dumps(out, indent=2))
        return 1 if any(r["status"] == "FAIL" for r in results) else 0

    # Build a map of failing headers and their issues for highlighting
    failing_headers = {}
    for r in results:
        if r["status"] == "FAIL":
            header_name = r["name"].lower().replace(" header", "")
            if header_name in headers:
                # Extract just the first sentence of the recommendation, removing any URLs
                rec = r.get("recommendation", "")
                first_sentence = rec.split('.')[0].strip()
                if "See" in first_sentence:  # Remove any "See..." references
                    first_sentence = first_sentence.split("See")[0].strip()
                failing_headers[header_name] = first_sentence

    # Print results table
    table = Table(show_header=True, header_style="bold", box=box.SIMPLE)
    table.add_column("STATUS", width=6)
    table.add_column("HEADER", style="cyan", width=28)
    table.add_column("EVIDENCE", overflow="fold")

    status_to_style = {"PASS": "green", "FAIL": "red", "INFO": "yellow"}

    for r in results:
        status = r["status"]
        style = status_to_style.get(status, "white")
        table.add_row(f"[{style}]{status}[/{style}]", r["name"], r.get("evidence", ""))

    console.print(f"[bold]Security header check for:[/bold] {url}")
    console.print(table)
    console.print()

    # Print raw headers with highlighting
    console.print("[bold]Raw Response Headers:[/bold]")
    console.print("─" * 80)
    console.print()
    
    # Sort headers into groups: problematic and ok
    problem_headers = []
    ok_headers = []
    for k in sorted(headers.keys(), key=str.lower):
        v = headers[k]
        k_lower = k.lower()
        if k_lower in failing_headers:
            problem_headers.append((k, v, failing_headers[k_lower]))
        else:
            ok_headers.append((k, v))

    # Print problematic headers first with clear separation
    if problem_headers:
        console.print("[bold red]⚠ Problematic Headers:[/bold red]")
        console.print()
        for k, v, note in problem_headers:
            # Header with issues - show name in bold red and value in normal red
            console.print(f"[bold red]{k}:[/bold red][red] {v}[/red]")
            console.print(f"[dim red]↳ {note}[/dim red]")
            # Find the specific issues for this header
            issue_detail = next((r.get("issue_detail", "") for r in results if r["name"].lower().replace(" header", "") == k.lower()), "")
            if issue_detail:
                console.print(f"[dim red]  ↳ Details: {issue_detail}[/dim red]")
            console.print()  # Extra line after each problematic header
    
    # Print ok headers with less spacing but still organized
    if ok_headers:
        if problem_headers:
            console.print("[bold green]✓ Other Headers:[/bold green]")
            console.print()
        
        # Group similar headers together (e.g., all security headers, all content headers)
        header_groups = {
            "security": ["x-", "content-security", "strict-transport", "access-control"],
            "content": ["content-"],
            "caching": ["cache-", "etag", "expires"],
            "other": []
        }
        
        grouped_headers = {k: [] for k in header_groups}
        for k, v in ok_headers:
            placed = False
            for group, prefixes in header_groups.items():
                if any(k.lower().startswith(p) for p in prefixes):
                    grouped_headers[group].append((k, v))
                    placed = True
                    break
            if not placed:
                grouped_headers["other"].append((k, v))
        
        # Print each group
        for group, headers_list in grouped_headers.items():
            if headers_list:
                if any(len(h) for h in grouped_headers.values()):
                    console.print()
                for k, v in sorted(headers_list, key=lambda x: x[0].lower()):
                    console.print(f"[cyan]{k}:[/cyan] {v}")
    
    console.print()
    console.print("─" * 80)
    console.print()

    # Print recommendations for FAILs
    if any(r["status"] == "FAIL" for r in results):
        console.print("[bold red]Security Issues Found:[/bold red]")
        for r in results:
            if r["status"] == "FAIL":
                console.print(f"[red]❌ {r['name']}:[/red] {r.get('recommendation', '')}")

    return 1 if any(r["status"] == "FAIL" for r in results) else 0


def _validate_urls(urls: List[str]) -> Tuple[List[str], List[str]]:
    """Separate valid-looking URLs from invalid ones.

    Returns (valid, invalid)
    """
    valid = []
    invalid = []
    for u in urls:
        if " " in u or u.strip() == "":
            invalid.append(u)
            continue
        # basic scheme check
        if "://" not in u:
            u = "https://" + u
        try:
            parsed = httpx.URL(u)
            if not parsed.host:
                invalid.append(u)
            else:
                valid.append(str(parsed))
        except Exception:
            invalid.append(u)
    return valid, invalid


def main() -> None:
    parser = argparse.ArgumentParser(description="Header security checker (httpx + rich).")
    parser.add_argument("urls", nargs="+", help="One or more target URLs")
    parser.add_argument("--timeout", type=float, default=8.0, help="Request timeout seconds (default 8)")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow redirects")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON report")
    args = parser.parse_args()

    valid, invalid = _validate_urls(args.urls)
    if invalid:
        console.print(f"[yellow]Warning:[/yellow] Invalid or unparsable URLs: {invalid}")

    # Print ASCII banner when running interactively (not JSON)
    if not args.json:
        print_banner()

    exit_code = 0
    any_fail = False

    for url in valid:
        console.print(f"[blue]INFO[/blue] {url} Fetching URL")
        resp, errors = fetch_url(url, timeout=args.timeout, follow_redirects=args.follow_redirects)
        if errors:
            console.print(f"[red]ERROR[/red] {url} {errors[0]}")
            sys.exit(2)
        if resp is None:
            console.print(f"[red]ERROR[/red] {url} No response received")
            sys.exit(2)
        results, raw_headers = analyze_headers(resp)
        rc = format_output(results, url, raw_headers, json_out=args.json)
        if rc == 2:
            sys.exit(2)
        if rc == 1:
            any_fail = True
        # if multiple URLs, separate
        if not args.json:
            console.print("")

    exit_code = 1 if any_fail else 0
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
