import httpx
import tldextract
import asyncio
import re
from urllib.parse import urlparse

HOMOGRAPH_CHARS = re.compile(r'[^\x00-\x7F]')

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz",
    ".top", ".click", ".work", ".loan", ".win",
    ".download", ".stream", ".gdn", ".racing",
    ".date", ".faith", ".review", ".trade", ".cricket"
}

COMMON_BRANDS = {
    # Big Tech
    "google.com", "microsoft.com", "apple.com", "amazon.com", "meta.com",
    "facebook.com", "instagram.com", "whatsapp.com", "twitter.com", "x.com",
    "youtube.com", "tiktok.com", "snapchat.com", "pinterest.com", "reddit.com",
    "tumblr.com", "discord.com", "telegram.org", "signal.org", "viber.com",
    "skype.com", "zoom.us", "slack.com", "teams.microsoft.com", "webex.com",
    "gotomeeting.com", "whereby.com", "meet.google.com",

    # Microsoft Ecosystem
    "office.com", "office365.com", "outlook.com", "hotmail.com", "live.com",
    "microsoftonline.com", "sharepoint.com", "onedrive.com", "azure.com",
    "bing.com", "xbox.com", "msn.com", "windowsazure.com", "visualstudio.com",
    "github.com", "nuget.org", "powerapps.com", "dynamics.com",

    # Google Ecosystem
    "gmail.com", "drive.google.com", "docs.google.com", "calendar.google.com",
    "photos.google.com", "play.google.com", "maps.google.com", "news.google.com",
    "translate.google.com", "cloud.google.com", "firebase.google.com",
    "analytics.google.com", "ads.google.com", "classroom.google.com",

    # Apple Ecosystem
    "icloud.com", "apple.com", "itunes.com", "appstore.com", "facetime.apple.com",
    "imessage.apple.com", "appleid.apple.com",

    # Amazon Ecosystem
    "amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.co.jp",
    "aws.amazon.com", "kindle.com", "audible.com", "twitch.tv", "imdb.com",
    "zappos.com", "wholefoodsmarket.com", "amazonprime.com",

    # Finance & Banking — Global
    "paypal.com", "stripe.com", "square.com", "wise.com", "payoneer.com",
    "venmo.com", "zelle.com", "cashapp.com", "revolut.com", "monzo.com",
    "n26.com", "transferwise.com", "skrill.com", "neteller.com", "paysafecard.com",
    "americanexpress.com", "visa.com", "mastercard.com", "discover.com",
    "bankofamerica.com", "wellsfargo.com", "chase.com", "citibank.com",
    "capitalone.com", "usbank.com", "tdbank.com", "pnc.com", "suntrust.com",
    "regions.com", "fifththird.com", "ally.com", "schwab.com", "fidelity.com",
    "vanguard.com", "etrade.com", "robinhood.com", "webull.com", "sofi.com",

    # Finance & Banking — UK/Europe
    "barclays.com", "hsbc.com", "lloydsbank.com", "natwest.com", "rbs.co.uk",
    "santander.com", "deutschebank.com", "bnpparibas.com", "societegenerale.com",
    "creditsuisse.com", "ubs.com", "ing.com", "abnamro.com", "rabobank.com",

    # Finance & Banking — India
    "hdfcbank.com", "icicibank.com", "sbi.co.in", "axisbank.com", "kotak.com",
    "yesbank.in", "indusind.com", "pnbindia.in", "canarabank.com", "unionbankofindia.co.in",
    "paytm.com", "phonepe.com", "razorpay.com", "zerodha.com", "groww.in",
    "upstox.com", "angelbroking.com", "icicidirect.com", "hdfcsec.com",
    "mobikwik.com", "freecharge.com", "bharatpe.com", "cred.club",

    # Crypto
    "coinbase.com", "binance.com", "kraken.com", "bitfinex.com", "bitstamp.net",
    "gemini.com", "crypto.com", "kucoin.com", "okx.com", "huobi.com",
    "bybit.com", "ftx.com", "blockchain.com", "exodus.com", "metamask.io",
    "trustwallet.com", "ledger.com", "trezor.io", "coinmarketcap.com",

    # E-commerce — Global
    "ebay.com", "etsy.com", "shopify.com", "walmart.com", "target.com",
    "bestbuy.com", "costco.com", "homedepot.com", "lowes.com", "ikea.com",
    "aliexpress.com", "alibaba.com", "taobao.com", "jd.com", "rakuten.com",
    "newegg.com", "overstock.com", "wayfair.com", "chewy.com", "wish.com",
    "shein.com", "asos.com", "zara.com", "hm.com", "uniqlo.com",
    "nike.com", "adidas.com", "puma.com", "reebok.com", "underarmour.com",

    # E-commerce — India
    "flipkart.com", "snapdeal.com", "myntra.com", "meesho.com", "nykaa.com",
    "ajio.com", "tatacliq.com", "reliancedigital.in", "croma.com",
    "bigbasket.com", "blinkit.com", "zepto.in", "jiomart.com", "grofers.com",
    "swiggy.com", "zomato.com", "dunzo.com", "magicbricks.com", "99acres.com",
    "housing.com", "commonfloor.com", "quikr.com", "olx.in",

    # Delivery & Logistics
    "fedex.com", "ups.com", "dhl.com", "usps.com", "royalmail.com",
    "dpd.com", "hermes.com", "parcelforce.com", "dtdc.com", "bluedart.com",
    "delhivery.com", "ecom-express.com", "xpressbees.com",

    # Cloud & Dev
    "github.com", "gitlab.com", "bitbucket.org", "stackoverflow.com",
    "heroku.com", "netlify.com", "vercel.com", "digitalocean.com",
    "linode.com", "vultr.com", "cloudflare.com", "fastly.com", "akamai.com",
    "docker.com", "kubernetes.io", "terraform.io", "ansible.com",
    "jenkins.io", "circleci.com", "travisci.com", "jfrog.com",
    "sonarqube.org", "datadog.com", "newrelic.com", "splunk.com",
    "elastic.co", "mongodb.com", "mysql.com", "postgresql.org",
    "redis.io", "kafka.apache.org", "rabbitmq.com",

    # Productivity & SaaS
    "dropbox.com", "box.com", "notion.so", "airtable.com", "trello.com",
    "asana.com", "monday.com", "clickup.com", "basecamp.com", "todoist.com",
    "evernote.com", "onenote.com", "confluence.atlassian.com",
    "jira.atlassian.com", "atlassian.com", "zendesk.com", "freshdesk.com",
    "intercom.com", "hubspot.com", "salesforce.com", "zoho.com",
    "pipedrive.com", "servicenow.com", "sap.com", "oracle.com",
    "docusign.com", "hellosign.com", "adobe.com", "canva.com",
    "figma.com", "sketch.com", "invision.com", "zeplin.io",
    "miro.com", "lucidchart.com", "draw.io", "smartsheet.com",
    "typeform.com", "surveymonkey.com", "mailchimp.com", "sendgrid.com",
    "constantcontact.com", "activecampaign.com", "klaviyo.com",

    # HR & Payroll
    "workday.com", "successfactors.com", "bamboohr.com", "adp.com",
    "paychex.com", "gusto.com", "rippling.com", "namely.com",
    "hibob.com", "personio.com", "greenhouse.io", "lever.co",
    "workable.com", "recruiterbox.com", "linkedin.com",

    # Security & IT
    "okta.com", "duo.com", "lastpass.com", "1password.com", "dashlane.com",
    "bitwarden.com", "keepass.info", "nordpass.com",
    "crowdstrike.com", "paloaltonetworks.com", "fortinet.com",
    "cisco.com", "juniper.net", "checkpoint.com", "sophos.com",
    "symantec.com", "mcafee.com", "norton.com", "kaspersky.com",
    "malwarebytes.com", "avast.com", "avg.com", "bitdefender.com",
    "eset.com", "trendmicro.com", "webroot.com", "cylance.com",
    "sentinelone.com", "carbonblack.com", "cybereason.com",
    "qualys.com", "rapid7.com", "tenable.com", "nessus.com",
    "imperva.com", "f5.com", "zscaler.com", "netskope.com",
    "proofpoint.com", "mimecast.com", "barracuda.com", "ironscales.com",

    # Telecom — Global
    "att.com", "verizon.com", "tmobile.com", "comcast.com", "spectrum.com",
    "sprint.com", "boost.com", "cricket.com", "uscellular.com",
    "vodafone.com", "orange.com", "deutsche-telekom.com", "telefonicca.com",
    "bt.com", "sky.com", "virgin.com", "three.co.uk", "o2.co.uk",

    # Telecom — India
    "airtel.in", "jio.com", "vodafone.in", "bsnl.co.in", "mtnl.net.in",
    "idea.net.in", "tata.com", "reliancejio.com",

    # Travel & Hospitality
    "booking.com", "airbnb.com", "expedia.com", "hotels.com", "agoda.com",
    "tripadvisor.com", "kayak.com", "skyscanner.com", "priceline.com",
    "hotwire.com", "trivago.com", "orbitz.com", "travelocity.com",
    "marriott.com", "hilton.com", "hyatt.com", "ihg.com", "accor.com",
    "wyndham.com", "radisson.com", "bestwestern.com", "fourseasons.com",
    "uber.com", "lyft.com", "ola.com", "grab.com", "gojek.com",
    "makemytrip.com", "goibibo.com", "yatra.com", "cleartrip.com",
    "irctc.co.in", "railyatri.in", "redbus.in",
    "indigo.com", "airasia.com", "spicejet.com", "airindia.in",
    "britishairways.com", "emirates.com", "qatarairways.com",
    "lufthansa.com", "airfrance.com", "klm.com", "united.com",
    "delta.com", "aa.com", "southwestairlines.com",

    # Healthcare
    "cvs.com", "walgreens.com", "riteaid.com", "uhc.com", "aetna.com",
    "cigna.com", "anthem.com", "bluecross.com", "humana.com",
    "webmd.com", "mayoclinic.org", "medlineplus.gov", "healthline.com",
    "practo.com", "1mg.com", "netmeds.com", "pharmeasy.in", "apollo247.com",
    "fortishealthcare.com", "maxhealthcare.in", "manipalhospitals.com",

    # Government — US
    "irs.gov", "ssa.gov", "usps.gov", "medicare.gov", "medicaid.gov",
    "va.gov", "dhs.gov", "fbi.gov", "cia.gov", "nsa.gov",
    "whitehouse.gov", "senate.gov", "house.gov", "supremecourt.gov",
    "cdc.gov", "fda.gov", "epa.gov", "ftc.gov", "sec.gov",

    # Government — India
    "gov.in", "india.gov.in", "incometax.gov.in", "gst.gov.in",
    "uidai.gov.in", "passport.gov.in", "mca.gov.in", "epfindia.gov.in",
    "digilocker.gov.in", "cowin.gov.in", "umang.gov.in",
    "irctc.co.in", "indianrailways.gov.in", "nhai.gov.in",

    # Government — UK/Other
    "gov.uk", "hmrc.gov.uk", "dvla.gov.uk", "nhs.uk",
    "australia.gov.au", "canada.ca", "service.gov.uk",

    # Education
    "coursera.org", "udemy.com", "edx.org", "khanacademy.org",
    "skillshare.com", "linkedin.com", "pluralsight.com", "udacity.com",
    "codecademy.com", "freecodecamp.org", "w3schools.com", "mit.edu",
    "harvard.edu", "stanford.edu", "ox.ac.uk", "cam.ac.uk",
    "iit.ac.in", "iim.ac.in", "bits-pilani.ac.in", "vtu.ac.in",
    "byju.com", "unacademy.com", "vedantu.com", "toppr.com",
    "chegg.com", "quizlet.com", "grammarly.com", "turnitin.com",

    # Media & Entertainment
    "netflix.com", "hulu.com", "disneyplus.com", "hbomax.com",
    "primevideos.com", "peacocktv.com", "paramountplus.com",
    "appletv.com", "crunchyroll.com", "funimation.com",
    "spotify.com", "apple.com", "soundcloud.com", "deezer.com",
    "pandora.com", "tidal.com", "amazon.com", "bandcamp.com",
    "hotstar.com", "sonyliv.com", "zee5.com", "voot.com",
    "mxplayer.in", "altbalaji.com", "erosnow.com",
    "twitch.tv", "steam.com", "epicgames.com", "ea.com",
    "playstation.com", "xbox.com", "nintendo.com", "ubisoft.com",
    "activision.com", "blizzard.com", "riotgames.com", "valvesoftware.com",

    # News & Media
    "nytimes.com", "washingtonpost.com", "wsj.com", "bloomberg.com",
    "reuters.com", "apnews.com", "bbc.com", "bbc.co.uk", "cnn.com",
    "foxnews.com", "nbcnews.com", "abcnews.go.com", "cbsnews.com",
    "theguardian.com", "ft.com", "economist.com", "time.com",
    "forbes.com", "fortune.com", "businessinsider.com", "techcrunch.com",
    "wired.com", "theverge.com", "engadget.com", "arstechnica.com",
    "ndtv.com", "timesofindia.com", "hindustantimes.com", "thehindu.com",
    "indiatimes.com", "indianexpress.com", "livemint.com", "moneycontrol.com",

    # Recruitment & Jobs
    "linkedin.com", "indeed.com", "glassdoor.com", "monster.com",
    "careerbuilder.com", "ziprecruiter.com", "dice.com", "hired.com",
    "naukri.com", "shine.com", "timesjobs.com", "freshersworld.com",
    "internshala.com", "unstop.com", "foundit.in",

    # Legal & Compliance
    "docusign.com", "hellosign.com", "pandadoc.com", "echosign.com",
    "legalzoom.com", "rocketlawyer.com", "clerky.com",

    # Real Estate
    "zillow.com", "trulia.com", "realtor.com", "redfin.com",
    "century21.com", "coldwellbanker.com", "remax.com",
    "magicbricks.com", "99acres.com", "housing.com", "nobroker.in",

    # Food & Grocery
    "doordash.com", "ubereats.com", "grubhub.com", "postmates.com",
    "instacart.com", "seamless.com", "deliveroo.com", "justeat.com",
    "swiggy.com", "zomato.com", "dunzo.com",

    # Automotive
    "tesla.com", "ford.com", "gm.com", "bmw.com", "mercedes-benz.com",
    "toyota.com", "honda.com", "volkswagen.com", "audi.com", "hyundai.com",
    "kia.com", "nissan.com", "carfax.com", "autotrader.com", "cars.com",
    "carvana.com", "vroom.com", "carwale.com", "cardekho.com",

    # Miscellaneous trusted
    "wikipedia.org", "archive.org", "wolframalpha.com",
    "weather.com", "accuweather.com", "wunderground.com",
    "yelp.com", "yellowpages.com", "angi.com", "thumbtack.com",
    "fiverr.com", "upwork.com", "freelancer.com", "toptal.com",
    "99designs.com", "envato.com", "shutterstock.com", "getty.com",
    "unsplash.com", "pexels.com", "pixabay.com",
    "wordpress.com", "wix.com", "squarespace.com", "weebly.com",
    "godaddy.com", "namecheap.com", "hostgator.com", "bluehost.com",
    "siteground.com", "dreamhost.com", "cloudflare.com",
    "paypal.com", "cash.app", "google.com",
}

NUMBER_MAP = {
    '0': 'o', '1': 'i', '2': 'z', '3': 'e',
    '4': 'a', '5': 's', '6': 'g', '7': 't',
    '8': 'b', '9': 'g'
}


LETTER_SUBS = [
    ('rn', 'm'), ('vv', 'w'), ('cl', 'd'), ('ri', 'n'),
    ('ni', 'm'), ('ma', 'mi'), ('nn', 'm'), ('oo', 'o'),
]

def _detect_typosquatting(domain: str) -> dict:
    findings = []
    lower = domain.lower()

    try:
        ext = tldextract.extract(lower)
        domain_name = ext.domain.lower()
        domain_root = ext.registered_domain.lower()
    except Exception:
        domain_name = lower
        domain_root = lower

    if domain_root in COMMON_BRANDS:
        return {"detected": False, "findings": []}
    for brand in COMMON_BRANDS:
        if lower.endswith(f".{brand}"):
            return {"detected": False, "findings": []}

    brand_names = {b.split('.')[0] for b in COMMON_BRANDS if len(b.split('.')[0]) >= 4}

    # Number substitution
    normalized = ''.join(NUMBER_MAP.get(c, c) for c in domain_name)
    for brand in brand_names:
        if len(brand) < 6:
            continue
        if abs(len(domain_name) - len(brand)) <= 2:
            distance = _edit_distance(domain_name, brand)
            if 0 < distance <= 1:
                findings.append(f"Close misspelling: '{domain_name}' is {distance} edit(s) from '{brand}'")
                return {"detected": True, "findings": findings}

    # Letter substitution
    letter_normalized = domain_name
    for wrong, right in LETTER_SUBS:
        letter_normalized = letter_normalized.replace(wrong, right)
    for brand in brand_names:
        if brand in letter_normalized and brand not in domain_name:
            findings.append(f"Letter substitution: '{domain_name}' resembles '{brand}'")
            return {"detected": True, "findings": findings}

    # Brand embedded in domain
    for brand in brand_names:
        if brand in domain_name and domain_root not in COMMON_BRANDS:
            findings.append(f"Brand '{brand}' embedded in non-brand domain '{domain_root}'")
            return {"detected": True, "findings": findings}

    # Edit distance check for short domains
    for brand in brand_names:
        if abs(len(domain_name) - len(brand)) <= 2:
            distance = _edit_distance(domain_name, brand)
            if 0 < distance <= 2:
                findings.append(f"Close misspelling: '{domain_name}' is {distance} edit(s) from '{brand}'")
                return {"detected": True, "findings": findings}

    return {"detected": bool(findings), "findings": findings}


def _edit_distance(s1: str, s2: str) -> int:
    m, n = len(s1), len(s2)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[0]
        dp[0] = i
        for j in range(1, n + 1):
            temp = dp[j]
            if s1[i-1] == s2[j-1]:
                dp[j] = prev
            else:
                dp[j] = 1 + min(prev, dp[j], dp[j-1])
            prev = temp
    return dp[n]

def _detect_homograph(url: str) -> bool:
    return bool(HOMOGRAPH_CHARS.search(url))


async def _follow_redirects(url: str) -> dict:
    chain = []
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True, max_redirects=10) as client:
            resp = await client.get(url)
            for r in resp.history:
                chain.append(str(r.url))
            chain.append(str(resp.url))
            return {"chain": chain, "final_url": str(resp.url), "redirect_count": len(chain) - 1}
    except Exception as e:
        return {"chain": chain, "final_url": url, "redirect_count": 0, "error": str(e)}


async def analyze(url: str) -> dict:
    if not url.startswith('http://') and not url.startswith('https://'):
        url_to_parse = f'https://{url}'
    else:
        url_to_parse = url

    parsed = urlparse(url_to_parse)
    extracted = tldextract.extract(url)
    domain = extracted.registered_domain
    subdomain = extracted.subdomain
    suffix = f".{extracted.suffix}" if extracted.suffix else ""

    loop = asyncio.get_event_loop()
    typo_result, homograph, redirects = await asyncio.gather(
        loop.run_in_executor(None, _detect_typosquatting, domain),
        loop.run_in_executor(None, _detect_homograph, url),
        _follow_redirects(url_to_parse)
    )

    suspicious_tld = suffix.lower() in SUSPICIOUS_TLDS

    return {
        "url": url,
        "domain": domain,
        "subdomain": subdomain,
        "scheme": parsed.scheme,
        "path": parsed.path,
        "typosquatting": typo_result,
        "homograph_detected": bool(homograph),
        "suspicious_tld": suspicious_tld,
        "redirects": redirects
    }