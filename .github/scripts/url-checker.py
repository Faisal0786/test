#!/usr/bin/env python3
"""Check provider base URLs with CloudStream-like anti-bot protection.

Anti-bot chain (all layers tried until one returns 2xx):
  Layer 1: curl_cffi TLS impersonation (chrome_android / chrome131 / safari17_0)
  Layer 2: DDoS-Guard cookie retry
  Layer 3: cloudscraper (Cloudflare JS challenge)
  Layer 4: FlareSolverr (headless Chrome — beats Cloudflare IP blocks)
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
    import cloudscraper
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
TIMEOUT = (8, 20)
BODY_SAMPLE_LIMIT = 32 * 1024

IMPERSONATE_TARGETS = ("chrome_android", "chrome131", "safari17_0")

FLARESOLVERR_URL = "http://localhost:8191/v1"
FLARESOLVERR_TIMEOUT = 90

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
    old = urlsplit(old_url)
    destination = urlsplit(destination_url)
    if destination.scheme not in {"http", "https"} or not destination.netloc:
        return None
    return urlunsplit((
        destination.scheme, destination.netloc,
        old.path, old.query, old.fragment,
    ))


# ---------- response inspection ----------

def _close_quietly(response):
    try:
        response.close()
    except Exception:
        pass


def read_sample(response):
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
    hops = [
        f"{item.url} -> {item.headers.get('Location', '?')}"
        for item in response.history
    ]
    if hops:
        LOG.info("🔗 Redirect chain: %s", " | ".join(hops))


def _is_security_block(response):
    if response.status_code not in (403, 503):
        return False
    headers = response.headers or {}
    server = (headers.get("Server", "") or "").lower()
    if any(marker in server for marker in ("cloudflare", "ddos-guard", "sucuri", "akamai")):
        return True
    if "cf-ray" in headers or "cf-mitigated" in headers:
        return True
    return False


def assess_response(provider, original_url, response, inspect_body=True):
    status = response.status_code
    final_url = response.url
    redirect_changed = bool(
        response.history and has_domain_or_scheme_changed(original_url, final_url)
    )

    if redirect_changed:
        redirect_trace(response)

    if status < 200 or status >= 300:
        LOG.warning("⚠️ %s: HTTP %s after request to %s", provider, status, original_url)
        if redirect_changed and _is_security_block(response):
            replacement = replace_origin(original_url, final_url)
            if replacement and replacement != original_url:
                LOG.warning(
                    "🟡 %s: trusting redirect to %s "
                    "(destination is security-blocked, but redirect is legitimate)",
                    provider, final_url,
                )
                return replacement
        if redirect_changed:
            LOG.warning(
                "🛑 %s: redirect reached %s, but destination returned HTTP %s; not updating",
                provider, final_url, status,
            )
        return None

    body = read_sample(response) if inspect_body else ""
    warning = page_warning(body)
    if warning:
        LOG.warning("⚠️ %s: HTTP %s, but %s; URL left unchanged", provider, status, warning)
        return None

    if redirect_changed:
        replacement = replace_origin(original_url, final_url)
        if replacement and replacement != original_url:
            LOG.info("✅ %s: verified redirect to %s", provider, final_url)
            return replacement

    LOG.info("✅ %s: reachable (HTTP %s); no domain redirect detected", provider, status)
    return None


# ---------- anti-bot layer 2: DDoS-Guard ----------

def _is_ddos_guard(response):
    server = (response.headers.get("Server", "") or "").lower()
    return "ddos-guard" in server or "ddos_guard" in server


def _ddos_guard_retry(session, url, provider):
    LOG.info("🛡️ %s: DDoS-Guard detected — fetching challenge cookie", provider)
    try:
        session.get(
            "https://check.ddos-guard.net/check.js",
            timeout=TIMEOUT, allow_redirects=True,
        )
    except Exception as exc:
        LOG.warning("⚠️ %s: DDoS-Guard cookie fetch failed: %s", provider, exc)
        return None
    try:
        return session.get(url, timeout=TIMEOUT, allow_redirects=True, stream=True)
    except Exception as exc:
        LOG.warning("⚠️ %s: DDoS-Guard retry failed: %s", provider, exc)
        return None


# ---------- anti-bot layer 3: cloudscraper ----------

def _cloudscraper_fallback(url, provider):
    if not _HAS_CLOUDSCRAPER:
        return None
    LOG.info("☁️ %s: trying cloudscraper", provider)
    try:
        scraper = cloudscraper.create_scraper(
            browser={"browser": "chrome", "platform": "android", "mobile": True},
            delay=5,
        )
        return scraper.get(url, timeout=TIMEOUT, allow_redirects=True, stream=True)
    except Exception as exc:
        LOG.warning("⚠️ %s: cloudscraper failed: %s", provider, exc)
        return None


# ---------- anti-bot layer 4: FlareSolverr ----------

class _FakeRedirectHop:
    def __init__(self, url, location):
        self.url = url
        self.headers = {"Location": location}


class _FlareSolverrResponse:
    """Adapter that mimics a requests Response for our assessor."""

    def __init__(self, original_url, solution):
        self.status_code = int(solution.get("status", 200) or 200)
        self.url = solution.get("url") or original_url
        self.encoding = "utf-8"
        self.headers = {"Server": "flaresolverr"}
        self._body = (solution.get("response") or "").encode("utf-8", errors="ignore")
        self.history = []
        if self.url != original_url:
            self.history = [_FakeRedirectHop(original_url, self.url)]

    def iter_content(self, chunk_size=8192):
        for i in range(0, len(self._body), chunk_size):
            yield self._body[i:i + chunk_size]

    def close(self):
        pass


def _flaresolverr_fallback(url, provider):
    LOG.info("🎭 %s: trying FlareSolverr (headless Chrome)", provider)
    try:
        resp = cffi_requests.post(
            FLARESOLVERR_URL,
            json={
                "cmd": "request.get",
                "url": url,
                "maxTimeout": FLARESOLVERR_TIMEOUT * 1000,
            },
            timeout=FLARESOLVERR_TIMEOUT,
        )
    except CurlConnectionError as exc:
        LOG.warning("🚫 %s: FlareSolverr not reachable at %s (%s)", provider, FLARESOLVERR_URL, exc)
        return None
    except Exception as exc:
        LOG.warning("⚠️ %s: FlareSolverr request failed: %s", provider, exc)
        return None

    try:
        data = resp.json()
    except Exception:
        LOG.warning("⚠️ %s: FlareSolverr returned non-JSON", provider)
        return None

    if data.get("status") != "ok":
        msg = (data.get("message") or "")[:160]
        LOG.warning("⚠️ %s: FlareSolverr could not solve (%s)", provider, msg)
        return None

    solution = data.get("solution") or {}
    LOG.info(
        "🎭 %s: FlareSolverr solved — final URL %s (HTTP %s)",
        provider, solution.get("url"), solution.get("status"),
    )
    return _FlareSolverrResponse(url, solution)


# ---------- HEAD fallback ----------

def _head_fallback(session, provider, url):
    if session is None:
        return provider, url, None
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


# ---------- anti-bot orchestration ----------

def _try_anti_bot_layers(url, provider, sessions_by_target, saw_403):
    """Try remaining anti-bot layers after TLS impersonation failed.

    FIX: Each layer is tried until one returns a 2xx. Previously, cloudscraper
    returning a 403 response (not None) caused FlareSolverr to be skipped.
    """
    if not saw_403:
        return None

    # Layer 3: cloudscraper
    resp = _cloudscraper_fallback(url, provider)
    if resp is not None:
        if 200 <= resp.status_code < 300:
            LOG.info("☁️ %s: cloudscraper solved (HTTP %s)", provider, resp.status_code)
            return resp
        LOG.info("☁️ %s: cloudscraper still blocked (HTTP %s)", provider, resp.status_code)
        _close_quietly(resp)

    # Layer 4: FlareSolverr
    resp = _flaresolverr_fallback(url, provider)
    if resp is not None:
        if 200 <= resp.status_code < 300:
            return resp
        LOG.warning(
            "🎭 %s: FlareSolverr returned HTTP %s — trying DDoS-Guard via solved session",
            provider, resp.status_code,
        )
        _close_quietly(resp)

    return None


# ---------- per-provider check ----------

def _new_session(impersonate):
    session = cffi_requests.Session(impersonate=impersonate)
    session.headers.update(HEADERS)
    return session


def check_provider(provider, url):
    if provider.lower() in SKIP_PROVIDERS:
        LOG.info("⏭️ Skipping %s (configured skip)", provider)
        return provider, url, None

    LOG.info("🔍 Checking %s: %s", provider, url)

    opened_sessions = []
    chosen_response = None
    saw_403 = False

    try:
        # --- Layer 1 & 2: TLS impersonation + DDoS-Guard ---
        for target in IMPERSONATE_TARGETS:
            try:
                session = _new_session(target)
                opened_sessions.append(session)
            except Exception as exc:
                LOG.debug("%s: impersonate=%s unavailable (%s)", provider, target, exc)
                continue

            try:
                response = session.get(
                    url, timeout=TIMEOUT, allow_redirects=True, stream=True,
                )
            except CurlTooManyRedirects as exc:
                LOG.error("❌ %s: redirect loop: %s", provider, exc)
                return provider, url, None
            except CurlConnectionError as exc:
                err = str(exc).lower()
                if "resolve host" in err or "name not found" in err or "could not resolve" in err:
                    LOG.error(
                        "❌ %s: DNS resolution failed for %s — domain likely dead, "
                        "manual update required",
                        provider, url,
                    )
                    return provider, url, None
                LOG.warning("⚠️ %s: %s connection failed: %s", provider, target, exc)
                continue
            except CurlTimeout:
                LOG.warning("⏳ %s: %s timed out", provider, target)
                continue
            except CurlRequestException as exc:
                LOG.warning("⚠️ %s: %s failed: %s", provider, target, exc)
                continue

            if 200 <= response.status_code < 300:
                chosen_response = response
                break

            if response.status_code == 403:
                saw_403 = True
                if _is_ddos_guard(response):
                    _close_quietly(response)
                    response = _ddos_guard_retry(session, url, provider)
                    if response is not None and 200 <= response.status_code < 300:
                        chosen_response = response
                        break
                    if response is not None:
                        _close_quietly(response)
                    continue

            if (
                response.history
                and has_domain_or_scheme_changed(url, response.url)
                and _is_security_block(response)
            ):
                LOG.info(
                    "🟡 %s: %s got redirect + security block; keeping for assessment",
                    provider, target,
                )
                chosen_response = response
                break

            _close_quietly(response)

        # --- Layers 3 & 4: cloudscraper -> FlareSolverr ---
        if chosen_response is None:
            chosen_response = _try_anti_bot_layers(
                url, provider, opened_sessions, saw_403,
            )

        # --- Assess ---
        if chosen_response is not None:
            try:
                new_url = assess_response(
                    provider, url, chosen_response,
                    inspect_body=(200 <= chosen_response.status_code < 300),
                )
            finally:
                _close_quietly(chosen_response)
            return provider, url, new_url

        first_session = opened_sessions[0] if opened_sessions else None
        return _head_fallback(first_session, provider, url)

    finally:
        for s in opened_sessions:
            try:
                s.close()
            except Exception:
                pass


# ---------- persistence ----------

def save_provider_urls(data):
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