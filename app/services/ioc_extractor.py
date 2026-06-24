import re
from app.schemas.scan import IoC

IP_RE = re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\b')
DOMAIN_RE = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b')
URL_RE = re.compile(r'https?://[^\s<>"\']+')
HASH_MD5 = re.compile(r'\b[a-fA-F0-9]{32}\b')
HASH_SHA1 = re.compile(r'\b[a-fA-F0-9]{40}\b')
HASH_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b')
DEFANG_RE = re.compile(r'\[\.\]|\[dot\]|\(dot\)', re.IGNORECASE)

TRUSTED_DOMAINS = {
    "google.com", "gmail.com", "googleapis.com", "gstatic.com", "googleusercontent.com",
    "microsoft.com", "microsoftonline.com", "office.com", "office365.com", "live.com",
    "outlook.com", "hotmail.com", "azure.com", "azurewebsites.net", "windowsazure.com",
    "engage.microsoft.com", "cdn-dynmedia-1.microsoft.com",
    "apple.com", "icloud.com",
    "amazon.com", "amazonaws.com", "amazonses.com",
    "facebook.com", "instagram.com", "twitter.com", "x.com",
    "linkedin.com", "youtube.com", "tiktok.com",
    "cloudflare.com", "cloudfront.net",
    "yahoo.com", "yahoodns.net",
    "protonmail.com", "proton.me",
    "github.com", "githubusercontent.com",
    "w3.org", "schema.org"
}

# Junk domains/IOCs to skip
IGNORED_SUFFIXES = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.pdf', '.dtd', '.css', '.js', '.woff', '.woff2', '.ttf', '.eot'}
IGNORED_DOMAINS = {'smtp.mailfrom', 'header.from', 'header.to', 'reply.to', 'mailfrom', 'return.path'}

TRACKING_PATTERNS = re.compile(
    r'(track\.|pixel\.|click\.|open\.|beacon\.|t\d+\.|img\.|mail\.)',
    re.IGNORECASE
)

PRIVATE_IP_RE = re.compile(
    r'^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.0\.0\.0)'
)


def _is_trusted(url: str) -> bool:
    try:
        import tldextract
        ext = tldextract.extract(url)
        registered = ext.registered_domain.lower()
        return registered in TRUSTED_DOMAINS
    except Exception:
        return False


def _is_tracking_url(url: str) -> bool:
    return bool(TRACKING_PATTERNS.search(url))


def _get_root_domain(url: str) -> str:
    try:
        import tldextract
        ext = tldextract.extract(url)
        return ext.registered_domain.lower()
    except Exception:
        return url


def _defang(text: str) -> str:
    return DEFANG_RE.sub('.', text)


def _is_junk_domain(domain: str) -> bool:
    """Filter out garbage domains from code fragments, broken URLs, and DNS artifacts."""
    lower = domain.lower().strip().rstrip('.')

    # Skip empty or too short
    if len(lower) < 4:
        return True

    # Skip if it's a known junk entry
    if lower in IGNORED_DOMAINS:
        return True

    # Skip if it looks like an email auth fragment
    if lower.startswith('smtp.') or lower.startswith('header.'):
        return True

    # Skip file extensions picked up as domains
    if any(lower.endswith(ext) for ext in IGNORED_SUFFIXES):
        return True

    # Skip single-word "domains" (no dot)
    if '.' not in lower:
        return True

    # Skip domains with suspicious characters
    if re.search(r'[<>\(\)\[\]@\s]', lower):
        return True

    # Skip JavaScript/HTML fragments
    js_patterns = [
        r'\.submit$',           # ends with .submit
        r'\.join$',             # ends with .join
        r'\.length$',           # ends with .length
        r'\.setstate$',         # ends with .setstate
        r'\.set$',              # ends with .set
        r'\.value$',            # ends with .value
        r'\.php$',              # PHP files
        r'\.html$',             # HTML files
        r'\.asp$',              # ASP files
        r'\.aspx$',             # ASPX files
        r'^amp\.',              # AMP fragments
        r'^www\.[a-z]{2,3}$',  # www.xx (broken domain)
    ]
    for pattern in js_patterns:
        if re.search(pattern, lower):
            return True

    # Skip domains that look like they were split from a longer URL
    # e.g., "s.com", "g.com", "ads.com" without proper context
    parts = lower.split('.')
    if len(parts) == 2:
        # Two-part domain like "s.com" or "g.com" — check if SLD is too short
        if len(parts[0]) <= 1:
            return True
        # Check if it looks like a TLD fragment: "co.in", "com.au" are fine
        # but "ds.com", "mg.com" are probably fragments
        if len(parts[0]) == 2 and parts[0] not in {'my', 'go', 'we', 'it', 'so', 'me', 'us', 'be'}:
            # Two-letter domains are rare — likely fragments
            return True

    # Skip domains containing "naukri" fragments that don't match the real domain
    # (These are usually broken pieces of naukri.com URLs)
    if 'nauk' in lower and lower not in {'naukri.com'} and not lower.endswith('.naukri.com'):
        return True

    return False
IGNORED_SUFFIXES = {
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
    '.pdf', '.dtd', '.css', '.js', '.woff', '.woff2', '.ttf', '.eot',
    '.php', '.html', '.asp', '.aspx', '.jsp', '.xml', '.json',
    '.submit', '.join', '.length', '.setstate', '.set', '.value',
    '.co', '.gi', '.len'
}

def extract(text: str) -> list[IoC]:
    text = _defang(text)
    iocs: list[IoC] = []
    seen = set()
    seen_domains = set()

    def add(type_: str, value: str):
        key = f"{type_}:{value}"
        if key not in seen:
            seen.add(key)
            iocs.append(IoC(type=type_, value=value))

    for m in HASH_SHA256.finditer(text):
        add("sha256", m.group())

    for m in HASH_SHA1.finditer(text):
        add("sha1", m.group())

    for m in HASH_MD5.finditer(text):
        add("md5", m.group())

    for m in URL_RE.finditer(text):
        url = m.group().rstrip('.,;)')
        if _is_trusted(url):
            continue
        if _is_tracking_url(url):
            continue
        root = _get_root_domain(url)
        if root and root not in seen_domains and not _is_junk_domain(root):
            seen_domains.add(root)
            add("url", url[:200])

    for m in IP_RE.finditer(text):
        ip = m.group()
        if not PRIVATE_IP_RE.match(ip):
            add("ip", ip)

    for m in EMAIL_RE.finditer(text):
        val = m.group()
        domain = val.split("@")[-1].lower()
        if domain not in TRUSTED_DOMAINS and not _is_junk_domain(domain):
            add("email", val)

    for m in DOMAIN_RE.finditer(text):
        val = m.group().lower().rstrip('.')
        if val in TRUSTED_DOMAINS:
            continue
        if any(val.endswith(f".{d}") for d in TRUSTED_DOMAINS):
            continue
        if _is_junk_domain(val):
            continue
        if not any(ioc.value == val for ioc in iocs):
            add("domain", val)

    return iocs