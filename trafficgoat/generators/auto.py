"""Auto traffic generators - multi-destination, multi-protocol for load generation.

These generators send varied traffic to thousands of destinations across many
protocols without requiring any target configuration. Designed for high
performance using batch packet sending via scapy.

Includes generators for:
- Raw packets (TCP, UDP, ICMP, DNS, NTP, and exotic protocols)
- Bulk bandwidth (large UDP payloads)
- HTTP/HTTPS requests
- Curl-based heavy HTTP load (subprocess curl for parallel connections)
- SaaS application traffic (top SaaS APIs and services)
- TCP connect scans
"""

import os
import random
import socket
import struct
import subprocess
import time

from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, NTP, Raw

from trafficgoat.generators.base import BaseGenerator
from trafficgoat.generators._netio import packet_sender
from trafficgoat.config import GeneratorConfig
from trafficgoat.stats import StatsCollector


# ---------------------------------------------------------------------------
# Destination pools
# ---------------------------------------------------------------------------

POPULAR_DOMAINS = [
    # Top websites
    "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
    "twitter.com", "instagram.com", "linkedin.com", "reddit.com", "netflix.com",
    "microsoft.com", "apple.com", "github.com", "stackoverflow.com", "yahoo.com",
    "bing.com", "twitch.tv", "cnn.com", "bbc.com", "nytimes.com",
    "cloudflare.com", "dropbox.com", "spotify.com", "zoom.us", "slack.com",
    "discord.com", "medium.com", "quora.com", "ebay.com", "paypal.com",
    "stripe.com", "shopify.com", "wordpress.com", "tumblr.com", "pinterest.com",
    # Developer / infra
    "docker.com", "npmjs.com", "pypi.org", "rubygems.org", "kernel.org",
    "debian.org", "ubuntu.com", "fedoraproject.org", "archlinux.org",
    "mozilla.org", "apache.org", "nginx.org", "php.net", "python.org",
    "golang.org", "rust-lang.org", "nodejs.org", "vuejs.org", "angular.io",
    "jquery.com", "gitlab.com", "bitbucket.org", "heroku.com",
    "digitalocean.com", "linode.com", "vultr.com", "ovh.com", "hetzner.com",
    "akamai.com", "fastly.com",
    # Productivity / SaaS
    "office.com", "live.com", "outlook.com", "icloud.com", "protonmail.com",
    "duckduckgo.com", "brave.com", "opera.com", "whatsapp.com", "telegram.org",
    "signal.org", "skype.com", "trello.com", "asana.com", "notion.so",
    "figma.com", "canva.com", "adobe.com", "salesforce.com", "hubspot.com",
    "zendesk.com", "datadog.com", "newrelic.com", "splunk.com", "grafana.com",
    "elastic.co", "mongodb.com", "redis.io", "postgresql.org", "mysql.com",
    "terraform.io", "kubernetes.io", "prometheus.io", "envoyproxy.io",
    # Media / entertainment
    "hulu.com", "disneyplus.com", "hbomax.com", "peacocktv.com",
    "soundcloud.com", "bandcamp.com", "vimeo.com", "dailymotion.com",
    "flickr.com", "deviantart.com", "behance.net", "dribbble.com",
    # E-commerce / finance
    "alibaba.com", "aliexpress.com", "wish.com", "etsy.com", "walmart.com",
    "target.com", "bestbuy.com", "newegg.com", "costco.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citigroup.com",
    "coinbase.com", "binance.com", "kraken.com",
    # News / information
    "washingtonpost.com", "theguardian.com", "reuters.com", "apnews.com",
    "bloomberg.com", "forbes.com", "wired.com", "techcrunch.com",
    "arstechnica.com", "theverge.com", "engadget.com", "mashable.com",
    # Education / reference
    "khanacademy.org", "coursera.org", "edx.org", "udemy.com",
    "w3schools.com", "mdn.dev", "docs.python.org", "docs.oracle.com",
    # Government / org
    "nasa.gov", "nih.gov", "cdc.gov", "who.int", "un.org",
    "europa.eu", "gov.uk", "canada.ca",
    # Misc
    "craigslist.org", "yelp.com", "tripadvisor.com", "booking.com",
    "airbnb.com", "uber.com", "lyft.com", "doordash.com", "grubhub.com",
    "zillow.com", "realtor.com", "weather.com", "accuweather.com",
]

PUBLIC_DNS_SERVERS = [
    "8.8.8.8", "8.8.4.4",                          # Google
    "1.1.1.1", "1.0.0.1",                          # Cloudflare
    "9.9.9.9", "149.112.112.112",                  # Quad9
    "208.67.222.222", "208.67.220.220",             # OpenDNS
    "64.6.64.6", "64.6.65.6",                      # Verisign
    "76.76.2.0", "76.76.10.0",                     # Control D
    "94.140.14.14", "94.140.15.15",                # AdGuard
    "185.228.168.9", "185.228.169.9",              # CleanBrowsing
    "77.88.8.8", "77.88.8.1",                      # Yandex
    "156.154.70.1", "156.154.71.1",                # Neustar
]

PUBLIC_NTP_SERVERS = [
    "129.6.15.28", "129.6.15.29",                  # NIST
    "132.163.97.1", "132.163.97.2",                # NIST
    "132.163.96.1", "132.163.96.2",                # NIST
    "128.138.141.172",                              # University of Colorado
    "198.60.22.240",                                # Utah
    "64.113.32.5",                                  # Midwest
]

WELL_KNOWN_IPS = [
    # Google
    "142.250.80.46", "142.250.80.47", "142.250.185.206", "172.217.14.206",
    "216.58.214.206", "142.251.33.174", "142.251.40.46",
    # Cloudflare
    "104.16.132.229", "104.16.133.229", "104.18.32.7", "104.18.33.7",
    "172.67.182.31", "104.21.234.56",
    # Amazon
    "52.94.236.248", "54.239.28.85", "176.32.103.205",
    "205.251.242.103", "52.46.139.168",
    # Microsoft
    "20.70.246.20", "13.107.42.14", "204.79.197.200",
    "20.189.173.1", "52.168.112.66",
    # Facebook/Meta
    "157.240.1.35", "157.240.3.35", "31.13.65.36",
    "31.13.66.35", "157.240.12.35",
    # Others
    "151.101.1.140", "151.101.65.140",              # Reddit
    "104.244.42.65", "104.244.42.193",              # Twitter
    "140.82.121.4", "140.82.121.3",                 # GitHub
    "199.232.69.194", "185.199.108.133",            # GitHub Pages
    "93.184.216.34",                                 # example.com
    "208.80.154.224",                                # Wikipedia
    "198.35.26.96",                                  # Wikipedia
    "103.102.166.224",                               # Cloudflare
    "151.101.0.176", "151.101.128.176",             # Various CDN
]

# Ports
TCP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
    465, 587, 636, 993, 995, 1433, 1521, 2049, 3306, 3389,
    5432, 5900, 5985, 6379, 8080, 8443, 8888, 9090, 9200, 9300,
    27017, 6443, 2379, 10250, 11211, 15672, 5672, 4369,
]

UDP_PORTS = [
    53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514,
    520, 1194, 1900, 4500, 5353, 5060, 5061, 33434,
]

DNS_QUERY_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV"]

# Top SaaS application domains (APIs, dashboards, CDNs)
SAAS_DOMAINS = [
    # CRM / Sales
    "api.salesforce.com", "login.salesforce.com", "app.hubspot.com",
    "api.hubapi.com", "api.pipedrive.com", "app.close.com",
    # Collaboration / Productivity
    "api.slack.com", "slack.com", "teams.microsoft.com",
    "api.zoom.us", "zoom.us", "app.asana.com", "api.notion.so",
    "api.monday.com", "app.clickup.com", "api.trello.com",
    "api.airtable.com", "api.basecamp.com",
    # Cloud / Infrastructure
    "console.aws.amazon.com", "s3.amazonaws.com", "ec2.amazonaws.com",
    "portal.azure.com", "management.azure.com", "login.microsoftonline.com",
    "console.cloud.google.com", "storage.googleapis.com",
    "api.cloudflare.com", "api.digitalocean.com", "api.linode.com",
    "api.heroku.com", "api.vercel.com", "api.netlify.com",
    "registry.terraform.io",
    # DevOps / CI-CD
    "api.github.com", "gitlab.com", "api.bitbucket.org",
    "circleci.com", "app.travis-ci.com", "api.buildkite.com",
    "app.jenkins.io", "api.codecov.io", "sonarcloud.io",
    "app.snyk.io", "hub.docker.com", "registry.npmjs.org",
    "pypi.org", "rubygems.org",
    # Monitoring / Observability
    "api.datadoghq.com", "app.datadoghq.com",
    "api.newrelic.com", "api.pagerduty.com", "api.opsgenie.com",
    "app.signalfx.com", "grafana.com", "api.honeycomb.io",
    "sentry.io", "api.statuspage.io",
    # Security
    "api.crowdstrike.com", "api.okta.com", "login.okta.com",
    "api.auth0.com", "api.1password.com", "api.lastpass.com",
    "api.cloudflare.com", "api.zscaler.com",
    # Analytics / Data
    "api.mixpanel.com", "api.amplitude.com", "api.segment.io",
    "api.snowflake.com", "api.looker.com", "api.tableau.com",
    "api.powerbi.com", "bigquery.googleapis.com",
    # Payments / Finance
    "api.stripe.com", "api.paypal.com", "api.square.com",
    "api.braintreegateway.com", "api.wise.com", "api.plaid.com",
    "api.coinbase.com", "api.binance.com",
    # Marketing / Email
    "api.mailchimp.com", "api.sendgrid.com", "api.mailgun.net",
    "api.twilio.com", "api.intercom.io", "api.zendesk.com",
    "api.freshdesk.com", "api.drift.com",
    # Storage / CDN
    "api.box.com", "api.dropboxapi.com", "www.googleapis.com",
    "api.backblazeb2.com", "cdn.jsdelivr.net", "unpkg.com",
    "cdnjs.cloudflare.com", "fastly.com",
    # AI / ML SaaS
    "api.openai.com", "api.anthropic.com", "api.cohere.ai",
    "api.replicate.com", "huggingface.co", "api.stability.ai",
    "api.deepl.com", "api.assemblyai.com",
    # E-commerce / Logistics
    "api.shopify.com", "api.woocommerce.com", "api.bigcommerce.com",
    "api.ship-station.com", "api.easypost.com",
    # HR / Recruiting
    "api.workday.com", "api.bamboohr.com", "api.greenhouse.io",
    "api.lever.co", "api.gusto.com",
]

HTTP_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edge/120.0.0.0",
    "curl/8.4.0",
    "python-requests/2.31.0",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
]

HTTP_PATHS = [
    "/", "/index.html", "/login", "/api/v1/status", "/api/health",
    "/robots.txt", "/sitemap.xml", "/favicon.ico", "/.well-known/security.txt",
    "/about", "/contact", "/search?q=test", "/api/v1/users",
    "/wp-admin", "/wp-login.php", "/.env", "/config", "/admin",
    "/api/v1/data", "/dashboard", "/static/js/app.js", "/assets/main.css",
    "/graphql", "/api/v2/query", "/health", "/metrics", "/status",
]


def _generate_random_public_ip():
    """Generate a random routable public IP address."""
    while True:
        a = random.randint(1, 223)
        b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(1, 254)
        if a == 10:
            continue
        if a == 127:
            continue
        if a == 172 and 16 <= b <= 31:
            continue
        if a == 192 and b == 168:
            continue
        if a == 169 and b == 254:
            continue
        if a == 0 or a >= 224:
            continue
        if a == 100 and 64 <= b <= 127:
            continue  # CGNAT
        return f"{a}.{b}.{c}.{d}"


def build_destination_pool(count=1000):
    """Build a large pool of destination IPs combining known and random IPs."""
    pool = list(set(PUBLIC_DNS_SERVERS + PUBLIC_NTP_SERVERS + WELL_KNOWN_IPS))
    seen = set(pool)
    while len(pool) < count:
        ip = _generate_random_public_ip()
        if ip not in seen:
            seen.add(ip)
            pool.append(ip)
    random.shuffle(pool)
    return pool


# ---------------------------------------------------------------------------
# Generators
# ---------------------------------------------------------------------------

class AutoRawGenerator(BaseGenerator):
    """High-performance multi-destination raw packet generator.

    Sends TCP SYN, UDP, ICMP, DNS, and NTP packets in batches to a large pool
    of destinations with high protocol and port variation. Uses large payloads
    to maximize bandwidth throughput.
    """

    name = "auto:raw"

    def __init__(self, config: GeneratorConfig, stats: StatsCollector,
                 dry_run: bool = False, destinations: list[str] | None = None,
                 batch_size: int = 10, label: str = ""):
        super().__init__(config, stats, dry_run)
        self.destinations = destinations or build_destination_pool()
        self.batch_size = batch_size
        # Adjust delay for batch sending: send batch_size packets per cycle
        self._delay = self.batch_size / max(self.rate, 1)
        if label:
            self.name = f"auto:raw:{label}"

    def generate(self):
        self.stats.log(
            f"{self.name}: Multi-target raw traffic to "
            f"{len(self.destinations)} destinations at {self.rate} pps"
        )
        start = time.monotonic()

        protocols = [
            'tcp_syn', 'udp', 'icmp', 'dns', 'ntp',
            'snmp', 'sip', 'ldap', 'radius', 'mqtt',
            'syslog', 'memcached', 'modbus', 'bgp',
            'quic', 'stun', 'kerberos', 'netflow',
        ]
        weights = [
            0.15, 0.15, 0.08, 0.10, 0.05,
            0.05, 0.04, 0.04, 0.03, 0.04,
            0.04, 0.03, 0.03, 0.02,
            0.05, 0.03, 0.03, 0.04,
        ]

        with packet_sender(self.dry_run) as send_pkt:
            while not self.should_stop():
                if self.deadline_reached(start):
                    break

                packets = []
                for _ in range(self.batch_size):
                    proto = random.choices(protocols, weights=weights, k=1)[0]
                    dst = random.choice(self.destinations)
                    pkt = self._build_packet(dst, proto)
                    if pkt is not None:
                        packets.append(pkt)

                if packets:
                    try:
                        send_pkt(packets)
                    except Exception:
                        self.stats.update(self.name, errors=1)
                    total_bytes = sum(len(p) for p in packets)
                    self.stats.update(self.name, packets=len(packets), bytes_sent=total_bytes)

                self.throttle()

    def _build_packet(self, dst, proto):
        """Build a single packet for the given destination and protocol.

        Supports standard protocols (TCP, UDP, ICMP, DNS, NTP) and exotic
        protocols (SNMP, SIP, LDAP, RADIUS, MQTT, Syslog, Memcached, Modbus,
        BGP, QUIC, STUN, Kerberos, NetFlow).
        """
        try:
            if proto == 'tcp_syn':
                return IP(dst=dst) / TCP(
                    sport=random.randint(1024, 65535),
                    dport=random.choice(TCP_PORTS),
                    flags="S",
                    seq=random.randint(0, 2**32 - 1),
                    options=[('MSS', 1460), ('NOP', None), ('WScale', 7)],
                )
            elif proto == 'udp':
                payload = os.urandom(random.randint(512, 1400))
                return IP(dst=dst) / UDP(
                    sport=random.randint(1024, 65535),
                    dport=random.choice(UDP_PORTS),
                ) / payload
            elif proto == 'icmp':
                payload = os.urandom(random.randint(256, 1400))
                return IP(dst=dst) / ICMP(
                    type=8, code=0,
                    id=random.randint(1, 65535),
                    seq=random.randint(0, 65535),
                ) / payload
            elif proto == 'dns':
                domain = random.choice(POPULAR_DOMAINS)
                qtype = random.choice(DNS_QUERY_TYPES[:5])
                return IP(dst=random.choice(PUBLIC_DNS_SERVERS)) / UDP(
                    dport=53, sport=random.randint(1024, 65535),
                ) / DNS(
                    id=random.randint(0, 65535), rd=1,
                    qd=DNSQR(qname=domain, qtype=qtype),
                )
            elif proto == 'ntp':
                return IP(dst=random.choice(PUBLIC_NTP_SERVERS)) / UDP(
                    dport=123
                ) / NTP(version=3)
            elif proto == 'snmp':
                # SNMPv1 GET request for sysDescr.0
                snmp_get = bytes([
                    0x30, 0x29, 0x02, 0x01, 0x00,  # version: v1
                    0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,  # community: "public"
                    0xa0, 0x1c, 0x02, 0x04,  # GetRequest PDU
                ]) + os.urandom(4) + bytes([
                    0x02, 0x01, 0x00, 0x02, 0x01, 0x00,  # error status/index
                    0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08,
                    0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,  # OID 1.3.6.1.2.1.1.1.0
                    0x05, 0x00,
                ])
                return IP(dst=dst) / UDP(
                    sport=random.randint(1024, 65535), dport=161,
                ) / Raw(load=snmp_get)
            elif proto == 'sip':
                # SIP INVITE request
                call_id = f"{random.randint(100000, 999999)}@{dst}"
                sip_msg = (
                    f"INVITE sip:user@{dst} SIP/2.0\r\n"
                    f"Via: SIP/2.0/UDP {_generate_random_public_ip()}:5060;branch=z9hG4bK{random.randint(100000, 999999)}\r\n"
                    f"From: <sip:caller@trafficgoat.local>;tag={random.randint(1000, 9999)}\r\n"
                    f"To: <sip:user@{dst}>\r\n"
                    f"Call-ID: {call_id}\r\n"
                    f"CSeq: 1 INVITE\r\n"
                    f"Contact: <sip:caller@trafficgoat.local>\r\n"
                    f"Content-Length: 0\r\n\r\n"
                ).encode()
                return IP(dst=dst) / UDP(
                    sport=random.randint(1024, 65535), dport=5060,
                ) / Raw(load=sip_msg)
            elif proto == 'ldap':
                # LDAP BindRequest (anonymous)
                ldap_bind = bytes([
                    0x30, 0x0c,  # SEQUENCE
                    0x02, 0x01, 0x01,  # messageID: 1
                    0x60, 0x07,  # BindRequest
                    0x02, 0x01, 0x03,  # version: 3
                    0x04, 0x00,  # name: ""
                    0x80, 0x00,  # simple auth: ""
                ])
                return IP(dst=dst) / TCP(
                    sport=random.randint(1024, 65535), dport=389, flags="PA",
                ) / Raw(load=ldap_bind)
            elif proto == 'radius':
                # RADIUS Access-Request
                authenticator = os.urandom(16)
                radius_pkt = bytes([
                    0x01,  # Code: Access-Request
                    random.randint(0, 255),  # Identifier
                    0x00, 0x2c,  # Length: 44
                ]) + authenticator + bytes([
                    0x01, 0x08, 0x74, 0x65, 0x73, 0x74, 0x65, 0x72,  # User-Name: "tester"
                    0x04, 0x06,  # NAS-IP-Address
                ]) + bytes([10, 0, 0, random.randint(1, 254)]) + bytes([
                    0x05, 0x06, 0x00, 0x00, 0x00, random.randint(1, 254),  # NAS-Port
                ])
                return IP(dst=dst) / UDP(
                    sport=random.randint(1024, 65535), dport=1812,
                ) / Raw(load=radius_pkt)
            elif proto == 'mqtt':
                # MQTT CONNECT packet
                client_id = f"tg-{random.randint(10000, 99999)}".encode()
                remaining = 12 + len(client_id)
                mqtt_connect = bytes([
                    0x10, remaining,  # CONNECT, remaining length
                    0x00, 0x04, 0x4d, 0x51, 0x54, 0x54,  # "MQTT"
                    0x04,  # Protocol Level 4 (MQTT 3.1.1)
                    0x02,  # Connect flags: Clean session
                    0x00, 0x3c,  # Keep Alive: 60s
                    0x00, len(client_id),
                ]) + client_id
                return IP(dst=dst) / TCP(
                    sport=random.randint(1024, 65535), dport=1883, flags="PA",
                ) / Raw(load=mqtt_connect)
            elif proto == 'syslog':
                # Syslog message (RFC 5424)
                facilities = ['kern', 'user', 'mail', 'daemon', 'auth', 'local0', 'local7']
                severities = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug']
                pri = random.randint(0, 23) * 8 + random.randint(0, 7)
                syslog_msg = (
                    f"<{pri}>1 2026-03-24T12:{random.randint(0,59):02d}:{random.randint(0,59):02d}Z "
                    f"host-{random.randint(1, 999)} trafficgoat - - - "
                    f"Test {random.choice(severities)} message from {random.choice(facilities)} "
                    f"facility id={random.randint(10000, 99999)}"
                ).encode()
                return IP(dst=dst) / UDP(
                    sport=random.randint(1024, 65535), dport=514,
                ) / Raw(load=syslog_msg)
            elif proto == 'memcached':
                # Memcached binary GET request
                key = f"key_{random.randint(1, 100000)}".encode()
                # Binary protocol header
                mc_get = struct.pack(
                    '!BBHBBHIIQ',
                    0x80,  # magic
                    0x00,  # opcode: GET
                    len(key),  # key length
                    0x00,  # extras length
                    0x00,  # data type
                    0x0000,  # reserved
                    len(key),  # total body
                    random.randint(0, 2**32 - 1),  # opaque
                    0,  # CAS
                ) + key
                return IP(dst=dst) / TCP(
                    sport=random.randint(1024, 65535), dport=11211, flags="PA",
                ) / Raw(load=mc_get)
            elif proto == 'modbus':
                # Modbus TCP Read Holding Registers (function code 0x03)
                transaction_id = random.randint(0, 65535)
                modbus_pkt = struct.pack(
                    '!HHHBBHH',
                    transaction_id,  # Transaction ID
                    0x0000,  # Protocol ID (Modbus)
                    0x0006,  # Length
                    0x01,  # Unit ID
                    0x03,  # Function: Read Holding Registers
                    random.randint(0, 999),  # Start address
                    random.randint(1, 125),  # Quantity
                )
                return IP(dst=dst) / TCP(
                    sport=random.randint(1024, 65535), dport=502, flags="PA",
                ) / Raw(load=modbus_pkt)
            elif proto == 'bgp':
                # BGP OPEN message
                bgp_marker = b'\xff' * 16
                my_as = random.randint(64512, 65534)  # Private ASN range
                bgp_open = struct.pack(
                    '!16sHBBHHIB',
                    bgp_marker,
                    29,  # Length
                    1,   # Type: OPEN
                    4,   # Version
                    my_as,  # My AS
                    180,  # Hold Time
                    random.randint(1, 2**32 - 1),  # BGP Identifier
                    0,   # Opt Param Length
                )
                return IP(dst=dst) / TCP(
                    sport=random.randint(1024, 65535), dport=179, flags="PA",
                ) / Raw(load=bgp_open)
            elif proto == 'quic':
                # QUIC Initial packet (simplified)
                quic_header = bytes([
                    0xc0 | random.randint(0, 3),  # Long header, Initial
                    0x00, 0x00, 0x00, 0x01,  # Version: 1
                    0x08,  # DCID length
                ]) + os.urandom(8) + bytes([  # DCID
                    0x00,  # SCID length: 0
                ]) + os.urandom(random.randint(100, 1200))  # payload
                return IP(dst=dst) / UDP(
                    sport=random.randint(1024, 65535), dport=443,
                ) / Raw(load=quic_header)
            elif proto == 'stun':
                # STUN Binding Request (RFC 5389)
                stun_pkt = struct.pack(
                    '!HHI',
                    0x0001,  # Type: Binding Request
                    0x0000,  # Length: 0
                    0x2112A442,  # Magic Cookie
                ) + os.urandom(12)  # Transaction ID
                return IP(dst=dst) / UDP(
                    sport=random.randint(1024, 65535), dport=3478,
                ) / Raw(load=stun_pkt)
            elif proto == 'kerberos':
                # Kerberos AS-REQ (simplified)
                krb_data = bytes([
                    0x6a, 0x81, 0x80,  # APPLICATION 10
                    0x30, 0x7e,  # SEQUENCE
                    0xa1, 0x03, 0x02, 0x01, 0x05,  # pvno: 5
                    0xa2, 0x03, 0x02, 0x01, 0x0a,  # msg-type: AS-REQ (10)
                ]) + os.urandom(random.randint(80, 200))
                return IP(dst=dst) / UDP(
                    sport=random.randint(1024, 65535), dport=88,
                ) / Raw(load=krb_data)
            elif proto == 'netflow':
                # NetFlow v9 header + template flowset
                nf_header = struct.pack(
                    '!HHIIIH',
                    9,  # Version
                    1,  # Count
                    random.randint(1000, 999999),  # SysUptime
                    int(time.time()),  # Unix Secs
                    random.randint(1, 2**32 - 1),  # Sequence
                    random.randint(0, 65535),  # Source ID
                )
                # Template flowset
                template = struct.pack('!HH', 0, 24)  # FlowSet ID=0, Length=24
                template += struct.pack('!HH', 256, 4)  # Template ID=256, Field Count=4
                template += struct.pack('!HH', 8, 4)   # IPv4 Src Addr
                template += struct.pack('!HH', 12, 4)  # IPv4 Dst Addr
                template += struct.pack('!HH', 7, 2)   # L4 Src Port
                template += struct.pack('!HH', 11, 2)  # L4 Dst Port
                return IP(dst=dst) / UDP(
                    sport=random.randint(1024, 65535), dport=2055,
                ) / Raw(load=nf_header + template)
        except Exception:
            return None
        return None


class AutoBulkGenerator(BaseGenerator):
    """High-bandwidth bulk data generator using large UDP packets.

    Sends maximum-size UDP packets (1400 bytes payload, near MTU) in large
    batches to generate gigabytes of traffic quickly. Designed for bandwidth
    testing rather than protocol variety.
    """

    name = "auto:bulk"

    def __init__(self, config: GeneratorConfig, stats: StatsCollector,
                 dry_run: bool = False, destinations: list[str] | None = None,
                 batch_size: int = 50, label: str = ""):
        super().__init__(config, stats, dry_run)
        self.destinations = destinations or build_destination_pool()
        self.batch_size = batch_size
        self._delay = self.batch_size / max(self.rate, 1)
        if label:
            self.name = f"auto:bulk:{label}"
        # Pre-generate payloads for speed (avoid per-packet urandom overhead)
        self._payloads = [os.urandom(1400) for _ in range(64)]

    def generate(self):
        self.stats.log(
            f"{self.name}: Bulk bandwidth to "
            f"{len(self.destinations)} destinations at {self.rate} pps "
            f"(batch={self.batch_size}, ~{self.batch_size * 1400} bytes/batch)"
        )
        start = time.monotonic()

        with packet_sender(self.dry_run) as send_pkt:
            while not self.should_stop():
                if self.deadline_reached(start):
                    break

                packets = []
                for _ in range(self.batch_size):
                    dst = random.choice(self.destinations)
                    port = random.choice(UDP_PORTS)
                    payload = random.choice(self._payloads)
                    pkt = IP(dst=dst) / UDP(
                        sport=random.randint(1024, 65535),
                        dport=port,
                    ) / payload
                    packets.append(pkt)

                try:
                    send_pkt(packets)
                except Exception:
                    self.stats.update(self.name, errors=1)
                total_bytes = sum(len(p) for p in packets)
                self.stats.update(self.name, packets=len(packets), bytes_sent=total_bytes)

                self.throttle()


class AutoHTTPGenerator(BaseGenerator):
    """Multi-destination HTTP generator for auto mode.

    Makes HTTP/HTTPS requests to a large pool of real websites with varied
    methods, user agents, and paths.
    """

    name = "auto:http"

    def __init__(self, config: GeneratorConfig, stats: StatsCollector,
                 dry_run: bool = False, domains: list[str] | None = None,
                 label: str = ""):
        super().__init__(config, stats, dry_run)
        self.domains = domains or POPULAR_DOMAINS
        if label:
            self.name = f"auto:http:{label}"

    def generate(self):
        import requests as req_lib
        from urllib3.exceptions import InsecureRequestWarning
        req_lib.packages.urllib3.disable_warnings(InsecureRequestWarning)

        self.stats.log(
            f"{self.name}: HTTP traffic to {len(self.domains)} domains at {self.rate} pps"
        )
        methods = ["GET", "HEAD", "POST"]
        start = time.monotonic()

        with req_lib.Session() as session:
            session.verify = False

            while not self.should_stop():
                if self.deadline_reached(start):
                    break

                domain = random.choice(self.domains)
                scheme = random.choice(["http", "https"])
                path = random.choice(HTTP_PATHS)
                method = random.choice(methods)
                url = f"{scheme}://{domain}{path}"

                headers = {
                    "User-Agent": random.choice(HTTP_USER_AGENTS),
                    "Accept": "text/html,application/json,*/*",
                    "Accept-Language": random.choice([
                        "en-US,en;q=0.9", "de-DE,de;q=0.9", "fr-FR,fr;q=0.9",
                        "es-ES,es;q=0.9", "ja-JP,ja;q=0.9", "zh-CN,zh;q=0.9",
                    ]),
                    "Connection": random.choice(["keep-alive", "close"]),
                }

                body = None
                if method == "POST":
                    body = f'{{"user":"test{random.randint(1,9999)}","ts":{int(time.time())}}}'
                    headers["Content-Type"] = "application/json"

                try:
                    if not self.dry_run:
                        resp = session.request(
                            method, url, headers=headers, data=body,
                            timeout=3, allow_redirects=False,
                        )
                        size = len(resp.content) + len(str(resp.headers))
                        self.stats.update(self.name, packets=1, bytes_sent=size, connections=1)
                    else:
                        self.stats.update(self.name, packets=1, bytes_sent=512)
                except Exception:
                    self.stats.update(self.name, packets=1, errors=1)

                self.throttle()


class AutoTCPConnectGenerator(BaseGenerator):
    """Multi-destination TCP connect generator for auto mode.

    Makes full TCP connections to many destinations on varied ports,
    simulating real application traffic.
    """

    name = "auto:tcp"

    def __init__(self, config: GeneratorConfig, stats: StatsCollector,
                 dry_run: bool = False, destinations: list[str] | None = None,
                 label: str = ""):
        super().__init__(config, stats, dry_run)
        self.destinations = destinations or build_destination_pool(500)
        if label:
            self.name = f"auto:tcp:{label}"

    def generate(self):
        self.stats.log(
            f"{self.name}: TCP connect to {len(self.destinations)} destinations at {self.rate} pps"
        )
        start = time.monotonic()

        while not self.should_stop():
            if self.deadline_reached(start):
                break

            dst = random.choice(self.destinations)
            port = random.choice(TCP_PORTS)
            sock: socket.socket | None = None
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                if not self.dry_run:
                    sock.connect((dst, port))
                    self.stats.update(self.name, packets=1, bytes_sent=64, connections=1)
                else:
                    self.stats.update(self.name, packets=1, bytes_sent=64)
            except (ConnectionRefusedError, socket.timeout, socket.gaierror, OSError):
                self.stats.update(self.name, packets=1, errors=1)
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass

            self.throttle()


class AutoCurlGenerator(BaseGenerator):
    """Heavy-load HTTP generator using curl subprocesses for parallel connections.

    Uses curl for high-performance HTTP/HTTPS requests with HTTP/2 support,
    connection reuse, and parallel transfers. Designed for heavy load scenarios
    where the Python requests library becomes a bottleneck.
    """

    name = "auto:curl"

    # Curl-specific user agents
    CURL_USER_AGENTS = [
        "curl/8.5.0", "curl/8.4.0", "curl/7.88.1", "curl/7.81.0",
        "Mozilla/5.0 (compatible; TrafficGoat/2.0)",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3) AppleWebKit/605.1.15 Safari/605.1.15",
        "python-httpx/0.27.0",
        "Go-http-client/2.0",
        "okhttp/4.12.0",
    ]

    def __init__(self, config: GeneratorConfig, stats: StatsCollector,
                 dry_run: bool = False, domains: list[str] | None = None,
                 parallel: int = 8, label: str = ""):
        super().__init__(config, stats, dry_run)
        self.domains = domains or (POPULAR_DOMAINS + SAAS_DOMAINS)
        self.parallel = parallel
        if label:
            self.name = f"auto:curl:{label}"

    def _build_curl_cmd(self, url, method="GET", body=None):
        """Build a curl command with realistic options."""
        cmd = [
            "curl", "-s", "-o", "/dev/null",
            "-w", "%{http_code} %{size_download} %{time_total}",
            "--max-time", "5",
            "--connect-timeout", "3",
            "-k",  # Allow insecure (for testing)
            "-A", random.choice(self.CURL_USER_AGENTS),
            "-H", f"Accept: text/html,application/json,application/xml;q=0.9,*/*;q=0.8",
            "-H", f"Accept-Language: {random.choice(['en-US', 'de-DE', 'fr-FR', 'ja-JP', 'zh-CN'])}",
            "-H", f"Accept-Encoding: gzip, deflate, br",
            "-H", f"X-Request-ID: tg-{random.randint(100000, 999999)}",
        ]

        if method == "POST":
            cmd.extend(["-X", "POST"])
            if body:
                cmd.extend(["-d", body, "-H", "Content-Type: application/json"])
        elif method == "PUT":
            cmd.extend(["-X", "PUT"])
            if body:
                cmd.extend(["-d", body, "-H", "Content-Type: application/json"])
        elif method == "DELETE":
            cmd.extend(["-X", "DELETE"])
        elif method == "PATCH":
            cmd.extend(["-X", "PATCH"])
            if body:
                cmd.extend(["-d", body, "-H", "Content-Type: application/json"])
        elif method == "HEAD":
            cmd.extend(["-I"])

        # Randomly enable HTTP/2
        if random.random() < 0.4:
            cmd.append("--http2")

        # Randomly add cookies
        if random.random() < 0.3:
            cmd.extend(["-H", f"Cookie: session=tg{random.randint(100000, 999999)}; _ga=GA1.2.{random.randint(1000000, 9999999)}.{int(time.time())}"])

        # Randomly add auth header
        if random.random() < 0.2:
            token = os.urandom(16).hex()
            cmd.extend(["-H", f"Authorization: Bearer {token}"])

        # Randomly add referer
        if random.random() < 0.25:
            ref_domain = random.choice(self.domains)
            cmd.extend(["-H", f"Referer: https://{ref_domain}/"])

        cmd.append(url)
        return cmd

    def generate(self):
        self.stats.log(
            f"{self.name}: Curl-based heavy HTTP load to {len(self.domains)} domains "
            f"at {self.rate} rps (parallel={self.parallel})"
        )
        start = time.monotonic()

        methods = ["GET", "GET", "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"]
        api_paths = HTTP_PATHS + [
            "/api/v1/users", "/api/v1/orders", "/api/v2/products",
            "/api/v1/search?q=test", "/api/v1/auth/token",
            "/api/v1/webhooks", "/api/v1/events", "/api/v2/analytics",
            "/graphql", "/api/v1/upload", "/api/v1/export",
            "/api/v1/notifications", "/api/v1/settings", "/api/v1/billing",
            "/.well-known/openid-configuration", "/oauth2/token",
            "/api/v1/health", "/api/v1/metrics", "/api/v1/logs",
        ]

        while not self.should_stop():
            if self.deadline_reached(start):
                break

            # Launch parallel curl processes
            procs = []
            for _ in range(self.parallel):
                domain = random.choice(self.domains)
                scheme = random.choice(["https", "https", "http"])  # Bias towards HTTPS
                path = random.choice(api_paths)
                method = random.choice(methods)
                url = f"{scheme}://{domain}{path}"

                body = None
                if method in ("POST", "PUT", "PATCH"):
                    body = f'{{"id":{random.randint(1,99999)},"action":"test","ts":{int(time.time())}}}'

                if self.dry_run:
                    self.stats.update(self.name, packets=1, bytes_sent=1024)
                    continue

                cmd = self._build_curl_cmd(url, method, body)
                try:
                    proc = subprocess.Popen(
                        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    )
                    procs.append(proc)
                except Exception:
                    self.stats.update(self.name, errors=1)

            # Collect results
            for proc in procs:
                try:
                    stdout, _ = proc.communicate(timeout=6)
                    output = stdout.decode().strip()
                    if output:
                        parts = output.split()
                        status_code = int(parts[0]) if parts else 0
                        size = int(parts[1]) if len(parts) > 1 else 0
                        self.stats.update(
                            self.name, packets=1,
                            bytes_sent=max(size, 256),
                            connections=1,
                        )
                        if status_code >= 500:
                            self.stats.update(self.name, errors=1)
                    else:
                        self.stats.update(self.name, packets=1, bytes_sent=256)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate()
                    self.stats.update(self.name, packets=1, errors=1)
                except Exception:
                    self.stats.update(self.name, packets=1, errors=1)

            self.throttle()


class AutoSaaSGenerator(BaseGenerator):
    """SaaS application traffic generator.

    Simulates realistic traffic patterns to top SaaS applications including
    API calls, OAuth flows, webhook deliveries, and typical SaaS workflows.
    Covers CRM, collaboration, cloud, DevOps, monitoring, security, analytics,
    payments, marketing, storage, AI/ML, e-commerce, and HR platforms.
    """

    name = "auto:saas"

    # SaaS API paths by category
    SAAS_API_PATHS = {
        "crm": [
            "/api/v1/contacts", "/api/v1/deals", "/api/v1/companies",
            "/api/v1/pipelines", "/api/v1/activities", "/api/v1/leads",
            "/api/v1/tasks", "/api/v1/notes",
        ],
        "collab": [
            "/api/v1/channels", "/api/v1/messages", "/api/v1/users",
            "/api/v1/files", "/api/v1/reactions", "/api/v1/threads",
            "/api/v1/workspaces", "/api/v1/teams",
        ],
        "cloud": [
            "/api/v1/instances", "/api/v1/volumes", "/api/v1/networks",
            "/api/v1/loadbalancers", "/api/v1/databases", "/api/v1/domains",
            "/api/v1/firewalls", "/api/v1/images", "/api/v1/snapshots",
            "/api/v1/keys",
        ],
        "devops": [
            "/api/v1/repos", "/api/v1/pipelines", "/api/v1/builds",
            "/api/v1/deployments", "/api/v1/releases", "/api/v1/artifacts",
            "/api/v1/environments", "/api/v1/variables",
        ],
        "monitoring": [
            "/api/v1/metrics", "/api/v1/alerts", "/api/v1/dashboards",
            "/api/v1/incidents", "/api/v1/services", "/api/v1/monitors",
            "/api/v1/logs/query", "/api/v1/traces",
        ],
        "payments": [
            "/v1/charges", "/v1/customers", "/v1/invoices",
            "/v1/subscriptions", "/v1/payment_intents", "/v1/refunds",
            "/v1/payouts", "/v1/products", "/v1/prices",
        ],
        "auth": [
            "/oauth2/token", "/oauth2/authorize", "/oauth2/revoke",
            "/api/v1/users", "/api/v1/groups", "/api/v1/apps",
            "/.well-known/openid-configuration", "/api/v1/sessions",
        ],
        "ai": [
            "/v1/chat/completions", "/v1/embeddings", "/v1/completions",
            "/v1/models", "/v1/images/generations", "/v1/audio/transcriptions",
            "/v1/fine-tuning/jobs", "/v1/moderations",
        ],
    }

    def __init__(self, config: GeneratorConfig, stats: StatsCollector,
                 dry_run: bool = False, domains: list[str] | None = None,
                 label: str = ""):
        super().__init__(config, stats, dry_run)
        self.domains = domains or SAAS_DOMAINS
        if label:
            self.name = f"auto:saas:{label}"

    def generate(self):
        import requests as req_lib
        from urllib3.exceptions import InsecureRequestWarning
        req_lib.packages.urllib3.disable_warnings(InsecureRequestWarning)

        self.stats.log(
            f"{self.name}: SaaS API traffic to {len(self.domains)} services at {self.rate} rps"
        )
        categories = list(self.SAAS_API_PATHS.keys())
        start = time.monotonic()

        with req_lib.Session() as session:
            session.verify = False
            self._saas_loop(session, categories, start)

    def _saas_loop(self, session, categories, start):
        while not self.should_stop():
            if self.deadline_reached(start):
                break

            domain = random.choice(self.domains)
            category = random.choice(categories)
            path = random.choice(self.SAAS_API_PATHS[category])
            method = random.choices(
                ["GET", "POST", "PUT", "PATCH", "DELETE"],
                weights=[0.50, 0.25, 0.10, 0.10, 0.05],
                k=1,
            )[0]

            # Build realistic SaaS request headers
            headers = {
                "User-Agent": random.choice(HTTP_USER_AGENTS),
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Authorization": f"Bearer {os.urandom(20).hex()}",
                "X-Request-ID": f"req-{os.urandom(8).hex()}",
                "X-Correlation-ID": f"corr-{os.urandom(6).hex()}",
            }

            # Add API version header (common in SaaS APIs)
            if random.random() < 0.5:
                headers["X-API-Version"] = random.choice(["2024-01-01", "2025-03-01", "2026-01-15"])

            # Add workspace/org header
            if random.random() < 0.4:
                headers["X-Org-ID"] = f"org_{random.randint(10000, 99999)}"

            body = None
            if method in ("POST", "PUT", "PATCH"):
                body = self._generate_saas_payload(category)

            url = f"https://{domain}{path}"

            # Sometimes append query params
            if method == "GET" and random.random() < 0.5:
                params = random.choice([
                    f"?page={random.randint(1, 100)}&per_page=50",
                    f"?since={int(time.time()) - random.randint(3600, 86400)}",
                    f"?status={random.choice(['active', 'pending', 'archived'])}",
                    f"?q={random.choice(['test', 'user', 'prod', 'staging'])}",
                    f"?sort={random.choice(['created_at', 'updated_at', 'name'])}&order=desc",
                ])
                url += params

            try:
                if not self.dry_run:
                    resp = session.request(
                        method, url, headers=headers, data=body,
                        timeout=5, allow_redirects=False,
                    )
                    size = len(resp.content) + len(str(resp.headers))
                    self.stats.update(self.name, packets=1, bytes_sent=size, connections=1)
                else:
                    self.stats.update(self.name, packets=1, bytes_sent=768)
            except Exception:
                self.stats.update(self.name, packets=1, errors=1)

            self.throttle()

    @staticmethod
    def _generate_saas_payload(category):
        """Generate realistic JSON payloads for SaaS API requests."""
        ts = int(time.time())
        payloads = {
            "crm": f'{{"name":"Contact {random.randint(1,9999)}","email":"user{random.randint(1,9999)}@example.com","company":"Acme Inc","phone":"+1555{random.randint(1000000,9999999)}","stage":"qualified","value":{random.randint(100,50000)}}}',
            "collab": f'{{"channel":"general","text":"Automated test message {random.randint(1,9999)}","thread_ts":"{ts}.{random.randint(100000,999999)}","mrkdwn":true}}',
            "cloud": f'{{"name":"instance-{random.randint(1,999)}","size":"s-2vcpu-4gb","region":"{random.choice(["us-east-1","eu-west-1","ap-southeast-1","us-west-2"])}","image":"ubuntu-24-04-x64","tags":["test","trafficgoat"]}}',
            "devops": f'{{"ref":"main","environment":"staging","auto_merge":false,"required_contexts":[],"payload":{{"deploy_user":"tg-bot","version":"2.0.{random.randint(0,999)}"}}}}',
            "monitoring": f'{{"series":[{{"metric":"system.cpu.user","points":[[{ts},{random.uniform(0,100):.1f}]],"type":"gauge","host":"web-{random.randint(1,50)}","tags":["env:prod","service:api"]}}]}}',
            "payments": f'{{"amount":{random.randint(500,500000)},"currency":"{random.choice(["usd","eur","gbp","jpy"])}","customer":"cus_{os.urandom(8).hex()}","description":"Order #{random.randint(10000,99999)}","metadata":{{"order_id":"{random.randint(10000,99999)}"}}}}',
            "auth": f'{{"grant_type":"client_credentials","client_id":"app_{os.urandom(8).hex()}","scope":"read write","audience":"https://api.example.com"}}',
            "ai": f'{{"model":"{random.choice(["gpt-4","claude-3","command-r","mixtral-8x7b"])}","messages":[{{"role":"user","content":"Generate test data for load testing scenario {random.randint(1,999)}"}}],"max_tokens":{random.randint(100,2000)},"temperature":{random.uniform(0,1):.1f}}}',
        }
        return payloads.get(category, f'{{"test":true,"ts":{ts}}}')
