#!/usr/bin/env python3
"""Check provider base URLs and safely apply confirmed redirect changes."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from html import unescape
import json
import logging
from pathlib import Path
import re
from urllib.parse import urlsplit, urlunsplit

import requests


SCRIPT_PATH = Path(__file__).resolve()
_ROOT_CANDIDATES = (
    Path.cwd(),
    SCRIPT_PATH.parents[2] if len(SCRIPT_PATH.parents) > 2 else SCRIPT_PATH.parent,
    SCRIPT_PATH.parent,
)
REPO_ROOT = next(
    (candidate for candidate in _ROOT_CANDIDATES if (candidate / "urls.json").is_file()),
    Path.cwd(),
)
URLS_FILE = REPO_ROOT / "urls.json"
SKIP_PROVIDERS = {"nfmirror"}
MAX_WORKERS = 6
TIMEOUT = (5, 12)  # connect timeout, read timeout
BODY_SAMPLE_LIMIT = 32 * 1024

# ==========================================
# 🛡️ MAJBOOT HEADERS (Anti-Bot Bypass)
# ==========================================
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "en-US,en;q=0.9,hi-IN;q=0.8,hi;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Sec-Ch-Ua": '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Pragma": "no-cache",
    "Cache-Control": "no-cache",
}

CHALLENGE_MARKERS = (
    "checking your browser",
    "verify you are human",
    "verification required",
    "attention required! | cloudflare",
    "enable javascript and cookies to continue",
    "complete the security check",
    "cf-chl-",
)

PARKED_MARKERS = (
    "this domain is for sale",
    "domain is for sale",
    "buy this domain",
    "domain has expired",
    "this domain may be for sale",
    "parked domain",
    "domain parking",
    "account suspended",
    "website is coming soon",
)

LOG = logging.getLogger("url_checker")


def load_provider_urls():
    """Load and validate the provider map before making network requests."""
    try:
        with URLS_FILE.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not read {URLS_FILE}: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("urls.json must contain a JSON object of provider names and URLs.")

    for provider, url in data.items():
        if not isinstance(provider, str) or not isinstance(url, str):
            raise ValueError(f"Invalid provider entry: {provider!r}")
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"Invalid URL for {provider}: {url!r}")

    return data


def origin_parts(url):
    parsed = urlsplit(url)
    return parsed.scheme.lower(), (parsed.hostname or "").lower(), parsed.port


def site_host(host):
    """Treat www.example.com and example.com as the same host for update decisions."""
    return host[4:] if host.startswith("www.") else host


def has_domain_or_scheme_changed(old_url, final_url):
    old_scheme, old_host, old_port = origin_parts(old_url)
    new_scheme, new_host, new_port = origin_parts(final_url)
    return (
        old_scheme != new_scheme
        or site_host(old_host) != site_host(new_host)
        or old_port != new_port
    )


def replace_origin(old_url, destination_url):
    """Use the confirmed destination origin while retaining the configured path/query."""
    old = urlsplit(old_url)
    destination = urlsplit(destination_url)
    if destination.scheme not in {"http", "https"} or not destination.netloc:
        return None

    return urlunsplit((
        destination.scheme,
        destination.netloc,
        old.path,
        old.query,
        old.fragment,
    ))


def read_sample(response):
    """Read only a small response prefix, avoiding full-page or media downloads."""
    sample = bytearray()
    try:
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                sample.extend(chunk)
            if len(sample) >= BODY_SAMPLE_LIMIT:
                break
    except requests.RequestException:
        pass

    encoding = response.encoding or "utf-8"
    return bytes(sample[:BODY_SAMPLE_LIMIT]).decode(encoding, errors="ignore").lower()


def page_warning(body):
    """Flag common anti-bot or parked-domain pages that sometimes return HTTP 200."""
    if not body:
        return None

    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, flags=re.I | re.S)
    title = unescape(re.sub(r"\s+", " ", title_match.group(1))).strip().lower() if title_match else ""

    if any(marker in body for marker in CHALLENGE_MARKERS):
        return "page appears to be a security/anti-bot challenge"

    if any(marker in title or marker in body for marker in PARKED_MARKERS):
        return "page appears to be parked, expired, or suspended"

    return None


def redirect_trace(response):
    """Return a readable redirect chain for the action log."""
    hops = [f"{item.url} -> {item.headers.get('Location', '?')}" for item in response.history]
    if hops:
        LOG.info("🔗 Redirect chain: %s", " | ".join(hops))


def assess_response(provider, original_url, response, inspect_body=True):
    """Return a proposed replacement URL, or None when no safe change is proven."""
    status = response.status_code
    final_url = response.url

    if status < 200 or status >= 300:
        LOG.warning("⚠️ %s: HTTP %s after request to %s", provider, status, original_url)
        if response.history:
            redirect_trace(response)
            if has_domain_or_scheme_changed(original_url, final_url):
                LOG.warning(
                    "🛑 %s: redirect reached %s, but destination returned HTTP %s; not updating",
                    provider, final_url, status,
                )
        return None

    body = read_sample(response) if inspect_body else ""
    warning = page_warning(body)
    if warning:
        LOG.warning("⚠️ %s: HTTP %s, but %s; URL left unchanged", provider, status, warning)
        if response.history:
            redirect_trace(response)
        return None

    if response.history and has_domain_or_scheme_changed(original_url, final_url):
        redirect_trace(response)
        replacement = replace_origin(original_url, final_url)
        if replacement and replacement != original_url:
            LOG.info("✅ %s: verified redirect to %s", provider, final_url)
            return replacement

    LOG.info("✅ %s: reachable (HTTP %s); no domain redirect detected", provider, status)
    return None


def check_provider(provider, url):
    """Probe with GET first, then use HEAD as a limited fallback when needed."""
    if provider.lower() in SKIP_PROVIDERS:
        LOG.info("⏭️ Skipping %s (configured skip)", provider)
        return provider, url, None

    LOG.info("🔍 Checking %s: %s", provider, url)
    session = requests.Session()
    session.headers.update(HEADERS)

    try:
        try:
            with session.get(
                url,
                timeout=TIMEOUT,
                allow_redirects=True,
                stream=True,
            ) as response:
                if 200 <= response.status_code < 300:
                    new_url = assess_response(provider, url, response, inspect_body=True)
                    return provider, url, new_url

                LOG.warning("⚠️ %s: GET returned HTTP %s", provider, response.status_code)
                if response.history:
                    redirect_trace(response)

        except requests.TooManyRedirects as exc:
            LOG.error("❌ %s: redirect loop or too many redirects: %s", provider, exc)
        except requests.Timeout:
            LOG.warning("⏳ %s: GET timed out; trying HEAD", provider)
        except requests.ConnectionError as exc:
            LOG.warning("🔌 %s: GET connection/DNS error; trying HEAD (%s)", provider, exc)
        except requests.RequestException as exc:
            LOG.warning("⚠️ %s: GET request failed; trying HEAD (%s)", provider, exc)

        try:
            with session.head(
                url,
                timeout=TIMEOUT,
                allow_redirects=True,
            ) as response:
                if 200 <= response.status_code < 300:
                    if response.history and has_domain_or_scheme_changed(url, response.url):
                        redirect_trace(response)
                        replacement = replace_origin(url, response.url)
                        if replacement and replacement != url:
                            LOG.warning(
                                "⚠️ %s: redirect confirmed by HEAD only; content was not verified",
                                provider,
                            )
                            return provider, url, replacement
                    LOG.warning(
                        "⚠️ %s: HEAD returned HTTP %s, but page content was not verified; unchanged",
                        provider, response.status_code,
                    )
                else:
                    LOG.warning("⚠️ %s: HEAD returned HTTP %s", provider, response.status_code)
                    if response.history:
                        redirect_trace(response)

        except requests.Timeout:
            LOG.error("❌ %s: HEAD timed out", provider)
        except requests.ConnectionError as exc:
            LOG.error("❌ %s: connection/DNS error: %s", provider, exc)
        except requests.RequestException as exc:
            LOG.error("❌ %s: HEAD request failed: %s", provider, exc)

        return provider, url, None

    finally:
        session.close()


def save_provider_urls(data):
    """Write atomically so an interrupted run does not leave malformed JSON."""
    temporary_file = URLS_FILE.with_suffix(URLS_FILE.suffix + ".tmp")
    try:
        with temporary_file.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(data, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        temporary_file.replace(URLS_FILE)
    except OSError:
        try:
            temporary_file.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def main():
    providers = load_provider_urls()
    changes = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        futures = {
            pool.submit(check_provider, name, url): (name, url)
            for name, url in providers.items()
        }

        for future in as_completed(futures):
            provider, old_url = futures[future]
            try:
                _, _, new_url = future.result()
            except Exception:
                LOG.exception("💥 Unexpected error while checking %s", provider)
                continue

            if new_url and new_url != old_url:
                providers[provider] = new_url
                changes.append((provider, old_url, new_url))

    if not changes:
        LOG.info("🏁 Finished: no verified URL changes found.")
        return

    for provider, old_url, new_url in sorted(changes):
        LOG.info("🚀 UPDATED %s: %s -> %s", provider, old_url, new_url)

    save_provider_urls(providers)
    LOG.info("💾 Saved %d URL change(s) to %s", len(changes), URLS_FILE)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    try:
        main()
    except Exception as error:
        LOG.error("🚨 Checker stopped: %s", error)
        raise
