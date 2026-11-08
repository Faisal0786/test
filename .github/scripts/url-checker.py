#!/usr/bin/env python3
"""Check provider base URLs with CloudStream-like anti-bot protection.

CloudStream uses OkHttp (Android). curl_cffi impersonates OkHttp4/Android10's
TLS/JA3 fingerprint — this is the primary reason plain `requests` got 403.
On top of that, we replicate CloudStream's DDoS-Guard cookie retry and add a
cloudscraper fallback for Cloudflare-protected sites.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from html import unescape
import json
import logging
from pathlib import Path
import re
from urllib.parse import urlsplit, urlunsplit

from curl_cffi import requests as cffi_requests
from curl_cffi.requests.exceptions import (
    RequestException as CurlRequestException,
    Timeout as CurlTimeout,
    ConnectionError as CurlConnectionError,
    TooManyRedirects as CurlTooManyRedirects,
)

try:
    import cloudscraper  # optional fallback for Cloudflare
    _HAS_CLOUDSCRAPER = True
except ImportError:
    cloudscraper = None
    _HAS_CLOUDSCRAPER = False


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
TIMEOUT = (8, 20)  # connect, read — generous for slow anti-bot-protected sites
BODY_SAMPLE_LIMIT = 32 * 1024

# OkHttp4 (Android 10) TLS/JA3 fingerprint — same stack CloudStream uses.
IMPERSONATE_TARGET = "okhttp4_android10"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Linux; Android 10; K) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/127.0.0.0 Mobile Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8,"
        "application/signed-exchange;v=b3;q=0.7"
    ),
    "Accept-Language": "en-IN,en;q=0.9",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Sec-Ch-Ua": (
        '"Chromium";v="127", "Not)A;Brand";v="99", '
        '"Microsoft Edge Simulate";v="127", "Lemur";v="127"'
    ),
    "Sec-Ch-Ua-Mobile": "?1",
    "Sec-Ch-Ua-Platform": '"Android"',
    "Priority": "u=0, i",
    "Connection": "keep-alive",
}

CHALLENGE_MARKERS = (
    "checking your browser",
    "verify you are human",
    "verification required",
    "attention required! | cloudflare",
    "enable javascript and cookies to continue",
    "complete the security check",
    "cf-chl-",
    "ddos-guard",
    "ddos guard",
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


# ---------- validation / URL helpers ----------

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


# ---------- response inspection ----------

def _close_quietly(response):
    try:
        response.close()
    except Exception:
        pass


def read_sample(response):
    """Read only a small response prefix, avoiding full-page or media downloads."""
    sample = bytearray()
    try:
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                sample.extend(chunk)
            if len(sample) >= BODY_SAMPLE_LIMIT:
                break
    except Exception:
        pass

    encoding = getattr(response, "encoding", None) or "utf-8"
    try:
        return bytes(sample[:BODY_SAMPLE_LIMIT]).decode(encoding, errors="ignore").lower()
    except (LookupError, TypeError):
        return bytes(sample[:BODY_SAMPLE_LIMIT]).decode("utf-8", errors="ignore").lower()


def page_warning(body):
    """Flag common anti-bot or parked-domain pages that sometimes return HTTP 200."""
    if not body:
        return None

    title_match = re.search(r"<title[^>]*>(.*?)</title>", body, flags=re.I | re.S)
    title = (
        unescape(re.sub(r"\s+", " ", title_match.group(1))).strip().lower()
        if title_match else ""
    )

    if any(marker in body for marker in CHALLENGE_MARKERS):
        return "page appears to be a security/anti-bot challenge"

    if any(marker in title or marker in body for marker in PARKED_MARKERS):
        return "page appears to be parked, expired, or suspended"

    return None


def redirect_trace(response):
    """Return a readable redirect chain for the action log."""
    hops = [
        f"{item.url} -> {item.headers.get('Location', '?')}"
        for item in response.history
    ]
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


# ---------- anti-bot bypass (CloudStream-style) ----------

def _is_ddos_guard(response):
    server = (response.headers.get("Server", "") or "").lower()
    return "ddos-guard" in server or "ddos_guard" in server


def _is_cloudflare(response):
    server = (response.headers.get("Server", "") or "").lower()
    return "cloudflare" in server


def _ddos_guard_retry(session, url, provider):
    """CloudStream `DdosGuardKiller` equivalent.

    Hit the DDoS-Guard check endpoint first so the challenge cookie lands in the
    session jar, then retry the original URL.
    """
    LOG.info("🛡️ %s: DDoS-Guard detected — fetching challenge cookie", provider)
    try:
        session.get(
            "https://check.ddos-guard.net/check.js",
            timeout=TIMEOUT,
            allow_redirects=True,
        )
    except Exception as exc:
        LOG.warning("⚠️ %s: DDoS-Guard cookie fetch failed: %s", provider, exc)
        return None

    try:
        return session.get(url, timeout=TIMEOUT, allow_redirects=True, stream=True)
    except Exception as exc:
        LOG.warning("⚠️ %s: DDoS-Guard retry failed: %s", provider, exc)
        return None


def _cloudscraper_fallback(url, provider):
    """Last resort for Cloudflare-protected sites."""
    if not _HAS_CLOUDSCRAPER:
        return None
    LOG.info("☁️ %s: trying cloudscraper fallback", provider)
    try:
        scraper = cloudscraper.create_scraper(
            browser={"browser": "chrome", "platform": "android", "mobile": True},
            delay=5,
        )
        return scraper.get(url, timeout=TIMEOUT, allow_redirects=True, stream=True)
    except Exception as exc:
        LOG.warning("⚠️ %s: cloudscraper failed: %s", provider, exc)
        return None


# ---------- HEAD fallback (redirect-only confirmation) ----------

def _head_fallback(session, provider, url):
    """Try HEAD only when GET failed. Confirms redirects without downloading body."""
    response = None
    try:
        response = session.head(url, timeout=TIMEOUT, allow_redirects=True)
        if 200 <= response.status_code < 300:
            if response.history and has_domain_or_scheme_changed(url, response.url):
                redirect_trace(response)
                replacement = replace_origin(url, response.url)
                if replacement and replacement != url:
                    LOG.warning(
                        "⚠️ %s: redirect confirmed by HEAD only; content not verified",
                        provider,
                    )
                    return provider, url, replacement
            LOG.warning(
                "⚠️ %s: HEAD returned %s but content not verified; unchanged",
                provider, response.status_code,
            )
        else:
            LOG.warning("⚠️ %s: HEAD returned HTTP %s", provider, response.status_code)
            if response.history:
                redirect_trace(response)
    except CurlTimeout:
        LOG.error("❌ %s: HEAD timed out", provider)
    except CurlConnectionError as exc:
        LOG.error("❌ %s: HEAD connection error: %s", provider, exc)
    except CurlRequestException as exc:
        LOG.error("❌ %s: HEAD failed: %s", provider, exc)
    except Exception as exc:
        LOG.error("❌ %s: HEAD unexpected error: %s", provider, exc)
    finally:
        if response is not None:
            _close_quietly(response)
    return provider, url, None


# ---------- per-provider check ----------

def check_provider(provider, url):
    if provider.lower() in SKIP_PROVIDERS:
        LOG.info("⏭️ Skipping %s (configured skip)", provider)
        return provider, url, None

    LOG.info("🔍 Checking %s: %s", provider, url)

    session = cffi_requests.Session(impersonate=IMPERSONATE_TARGET)
    session.headers.update(HEADERS)

    try:
        # --- primary GET ---
        try:
            response = session.get(
                url,
                timeout=TIMEOUT,
                allow_redirects=True,
                stream=True,
            )
        except CurlTooManyRedirects as exc:
            LOG.error("❌ %s: redirect loop: %s", provider, exc)
            return provider, url, None
        except CurlTimeout:
            LOG.warning("⏳ %s: GET timed out; trying HEAD", provider)
            return _head_fallback(session, provider, url)
        except CurlConnectionError as exc:
            LOG.warning("🔌 %s: GET connection error; trying HEAD (%s)", provider, exc)
            return _head_fallback(session, provider, url)
        except CurlRequestException as exc:
            LOG.warning("⚠️ %s: GET failed; trying HEAD (%s)", provider, exc)
            return _head_fallback(session, provider, url)
        except Exception as exc:
            LOG.warning("⚠️ %s: GET unexpected error; trying HEAD (%s)", provider, exc)
            return _head_fallback(session, provider, url)

        # --- anti-bot retry on 403 ---
        if response.status_code == 403 and _is_ddos_guard(response):
            _close_quietly(response)
            response = _ddos_guard_retry(session, url, provider)
            if response is None:
                LOG.error("🚫 %s: DDoS-Guard 403 (retry failed)", provider)
                return _head_fallback(session, provider, url)

        if response.status_code == 403 and _is_cloudflare(response):
            _close_quietly(response)
            response = _cloudscraper_fallback(url, provider)
            if response is None:
                LOG.error("🚫 %s: Cloudflare 403 (no bypass available)", provider)
                return _head_fallback(session, provider, url)

        # --- assess ---
        if 200 <= response.status_code < 300:
            try:
                new_url = assess_response(provider, url, response, inspect_body=True)
            finally:
                _close_quietly(response)
            return provider, url, new_url

        LOG.warning("⚠️ %s: GET returned HTTP %s", provider, response.status_code)
        if response.history:
            redirect_trace(response)
        _close_quietly(response)

        return _head_fallback(session, provider, url)

    finally:
        session.close()


# ---------- persistence ----------

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