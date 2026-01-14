#!/usr/bin/env python3
"""
SEO Crawlability Tester
Testar SEO-crawlbarhet - Googlebot, Mobile-First, Resources, Sitemaps, etc.
För säkerhetstester, använd security_bot_tester.py
"""

import requests
import time
import json
import hashlib
import random
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
import sys
import urllib3
from urllib.parse import urlparse

# Disable SSL warnings för testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@dataclass
class TestResult:
    """Resultat från ett test"""
    test_name: str
    passed: bool
    details: str
    response_code: Optional[int] = None
    response_time: Optional[float] = None
    protection_type: Optional[str] = None
    severity: str = "INFO"  # INFO, LOW, MEDIUM, HIGH, CRITICAL

@dataclass
class BotProtectionReport:
    """Komplett rapport över bot-skydd och SEO crawlbarhet"""
    target_url: str
    timestamp: str
    total_score: int
    rating: str
    tests_passed: int
    tests_failed: int
    protection_layers: List[str]
    vulnerabilities: List[str]
    seo_issues: List[str]
    recommendations: List[str]
    test_results: List[Dict]
    bot_accessibility_details: List[Dict] = None  # Detaljerad bot-status för PDF
    server_performance_details: Dict = None  # Detaljerad server-prestanda för PDF
    server_diagnostics: Dict = None  # Fas-för-fas server diagnostik

class AdvancedBotProtectionTester:
    def __init__(self, target_url: str, timeout: int = 10, verbose: bool = True):
        self.target_url = self._normalize_url(target_url)
        self.timeout = timeout
        self.verbose = verbose
        self.results: List[TestResult] = []
        self.protection_layers: set = set()
        self.vulnerabilities: List[str] = []
        
        # User agents pool
        self.user_agents = {
            'legitimate': [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0'
            ],
            'suspicious': [
                'python-requests/2.31.0',
                'curl/7.68.0',
                'Wget/1.21.2',
                'Go-http-client/1.1',
                'scrapy/2.11.0'
            ],
            'search_engine_bots': [
                'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
                'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
                'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)'
            ],
            'seo_bots': [
                'Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)',
                'Mozilla/5.0 (compatible; SemrushBot/7~bl; +http://www.semrush.com/bot.html)',
                'Mozilla/5.0 (compatible; MJ12bot/v1.4.8; http://mj12bot.com/)',
                'facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)',
                'Mozilla/5.0 (compatible; DotBot/1.2; +https://opensiteexplorer.org/dotbot)',
                'Screaming Frog SEO Spider/19.0',
                'Mozilla/5.0 (compatible; SiteAuditBot/0.97; +http://www.semrush.com/bot.html)',
                'Mozilla/5.0 (compatible; MojeekBot/0.11; +https://www.mojeek.com/bot.html)',
                'LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient +http://www.linkedin.com)',
                'Twitterbot/1.0',
                'Pinterest/0.2 (+http://www.pinterest.com/)',
                'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)'
            ],
            'generic_bots': [
                'Googlebot/2.1',
                'bingbot/2.0',
                'Baiduspider/2.0',
                'YandexBot/3.0'
            ],
            'ai_bots': [
                'GPTBot/1.0 (+https://openai.com/gptbot)',  # OpenAI
                'ChatGPT-User/1.0',  # ChatGPT browsing
                'Claude-Web/1.0',  # Anthropic Claude
                'Google-Extended/1.0',  # Google AI training
                'CCBot/2.0 (+https://commoncrawl.org/faq/)',  # Common Crawl (used by many AI)
                'anthropic-ai/1.0',  # Anthropic
                'Bytespider/1.0',  # ByteDance/TikTok AI
                'PerplexityBot/1.0 (+https://perplexity.ai/bot)',  # Perplexity AI
                'Applebot-Extended/1.0',  # Apple AI
                'FacebookBot/1.0',  # Meta AI
                'Omgilibot/1.0'  # Omgili AI
            ],
            'googlebot_mobile': [
                'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
                'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'
            ],
            'googlebot_desktop': [
                'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
                'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Googlebot/2.1; +http://www.google.com/bot.html) Chrome/120.0.0.0 Safari/537.36'
            ]
        }

        # SEO-specific tracking
        self.seo_issues = []
        self.seo_score = 0

        # Bot treatment tracking
        self.bot_responses = {}

        # Server performance tracking
        self.server_performance_issues = []
        self.server_info = {}

        # Detaljerad bot-åtkomst tracking (för PDF-rapport)
        self.bot_accessibility_details = []

        # Detaljerad server performance tracking (för PDF-rapport)
        self.server_performance_details = {
            'ttfb': {'value': None, 'status': 'unknown', 'label': 'TTFB'},
            'ssl': {'value': None, 'status': 'unknown', 'label': 'SSL-certifikat'},
            'compression': {'value': None, 'status': 'unknown', 'label': 'Komprimering'},
            'cache': {'value': None, 'status': 'unknown', 'label': 'Cache'},
            'http_version': {'value': None, 'status': 'unknown', 'label': 'HTTP-version'},
            'server': {'value': None, 'status': 'info', 'label': 'Server'}
        }

        # Detaljerad server-diagnostik (fas för fas)
        self.server_diagnostics = {
            'dns': {'time': None, 'status': 'unknown', 'label': 'DNS Lookup', 'description': 'Domän → IP-adress'},
            'tcp': {'time': None, 'status': 'unknown', 'label': 'TCP Connect', 'description': 'Anslutning till server'},
            'ssl': {'time': None, 'status': 'unknown', 'label': 'SSL Handshake', 'description': 'HTTPS-förhandling'},
            'ttfb': {'time': None, 'status': 'unknown', 'label': 'Time to First Byte', 'description': 'Servern processar request'},
            'download': {'time': None, 'status': 'unknown', 'label': 'Content Download', 'description': 'Ladda ner HTML'},
            'total': {'time': None, 'status': 'unknown', 'label': 'Total', 'description': 'Total laddningstid'},
            'bottleneck': None,  # Vilken fas som är problemet
            'bottleneck_cause': None  # Förklaring av problemet
        }
    
    def _normalize_url(self, url: str) -> str:
        """Normaliserar URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    def _log(self, message: str, emoji: str = ""):
        """Loggar meddelande om verbose är aktivt"""
        if self.verbose:
            print(f"{emoji} {message}" if emoji else message)

    def _measure_server_diagnostics(self) -> dict:
        """Mäter detaljerad server-diagnostik fas för fas"""
        import socket
        import ssl

        parsed = urlparse(self.target_url)
        hostname = parsed.netloc
        port = 443 if parsed.scheme == 'https' else 80
        path = parsed.path if parsed.path else '/'

        diagnostics = {
            'dns': {'time': None, 'status': 'unknown'},
            'tcp': {'time': None, 'status': 'unknown'},
            'ssl': {'time': None, 'status': 'unknown'},
            'ttfb': {'time': None, 'status': 'unknown'},
            'download': {'time': None, 'status': 'unknown'},
            'total': {'time': None, 'status': 'unknown'},
            'bottleneck': None,
            'bottleneck_cause': None,
            'error': None
        }

        total_start = time.time()

        try:
            # 1. DNS Lookup
            dns_start = time.time()
            try:
                ip_addresses = socket.getaddrinfo(hostname, port, socket.AF_INET, socket.SOCK_STREAM)
                ip_address = ip_addresses[0][4][0]
                dns_time = time.time() - dns_start
                diagnostics['dns']['time'] = dns_time
                diagnostics['dns']['status'] = 'good' if dns_time < 0.1 else ('ok' if dns_time < 0.5 else 'warning')
            except socket.gaierror as e:
                diagnostics['dns']['time'] = time.time() - dns_start
                diagnostics['dns']['status'] = 'critical'
                diagnostics['error'] = f"DNS-fel: {str(e)}"
                diagnostics['bottleneck'] = 'dns'
                diagnostics['bottleneck_cause'] = 'DNS-uppslagning misslyckades. Kontrollera domännamnet.'
                return diagnostics

            # 2. TCP Connect
            tcp_start = time.time()
            try:
                sock = socket.create_connection((ip_address, port), timeout=self.timeout)
                tcp_time = time.time() - tcp_start
                diagnostics['tcp']['time'] = tcp_time
                diagnostics['tcp']['status'] = 'good' if tcp_time < 0.2 else ('ok' if tcp_time < 0.5 else 'warning')
            except socket.timeout:
                diagnostics['tcp']['time'] = self.timeout
                diagnostics['tcp']['status'] = 'critical'
                diagnostics['error'] = "TCP timeout - servern svarar inte"
                diagnostics['bottleneck'] = 'tcp'
                diagnostics['bottleneck_cause'] = 'Servern svarar inte på anslutningsförsök. Kan vara nere eller blockerar din IP.'
                return diagnostics
            except Exception as e:
                diagnostics['tcp']['time'] = time.time() - tcp_start
                diagnostics['tcp']['status'] = 'critical'
                diagnostics['error'] = f"TCP-fel: {str(e)}"
                diagnostics['bottleneck'] = 'tcp'
                diagnostics['bottleneck_cause'] = 'Kunde inte ansluta till servern.'
                return diagnostics

            # 3. SSL Handshake (endast för HTTPS)
            if parsed.scheme == 'https':
                ssl_start = time.time()
                try:
                    context = ssl.create_default_context()
                    ssl_sock = context.wrap_socket(sock, server_hostname=hostname)
                    ssl_time = time.time() - ssl_start
                    diagnostics['ssl']['time'] = ssl_time
                    diagnostics['ssl']['status'] = 'good' if ssl_time < 0.3 else ('ok' if ssl_time < 1.0 else 'warning')
                    sock = ssl_sock
                except ssl.SSLError as e:
                    diagnostics['ssl']['time'] = time.time() - ssl_start
                    diagnostics['ssl']['status'] = 'critical'
                    diagnostics['error'] = f"SSL-fel: {str(e)[:50]}"
                    diagnostics['bottleneck'] = 'ssl'
                    diagnostics['bottleneck_cause'] = 'SSL-certifikat problem. Certifikatet kan vara ogiltigt eller utgånget.'
                    sock.close()
                    return diagnostics
            else:
                diagnostics['ssl']['time'] = 0
                diagnostics['ssl']['status'] = 'skip'

            # 4. HTTP Request + TTFB
            ttfb_start = time.time()
            try:
                request = f"GET {path} HTTP/1.1\r\nHost: {hostname}\r\nUser-Agent: Mozilla/5.0 (compatible; Googlebot/2.1)\r\nAccept: */*\r\nConnection: close\r\n\r\n"
                sock.sendall(request.encode())

                # Vänta på första byte med select
                import select
                sock.setblocking(False)

                ready = select.select([sock], [], [], self.timeout)
                ttfb_time = time.time() - ttfb_start

                if not ready[0]:
                    # Timeout - ingen data mottagen
                    diagnostics['ttfb']['time'] = ttfb_time
                    diagnostics['ttfb']['status'] = 'critical'
                    diagnostics['error'] = "TTFB timeout - servern svarar inte"
                    diagnostics['bottleneck'] = 'ttfb'
                    diagnostics['bottleneck_cause'] = 'Servern tar för lång tid att svara. Trolig orsak: långsam backend, databas eller PHP.'
                    sock.close()
                    return diagnostics

                diagnostics['ttfb']['time'] = ttfb_time
                if ttfb_time < 0.2:
                    diagnostics['ttfb']['status'] = 'good'
                elif ttfb_time < 0.6:
                    diagnostics['ttfb']['status'] = 'ok'
                elif ttfb_time < 2.0:
                    diagnostics['ttfb']['status'] = 'warning'
                else:
                    diagnostics['ttfb']['status'] = 'critical'
                    diagnostics['bottleneck'] = 'ttfb'
                    diagnostics['bottleneck_cause'] = f'TTFB är {ttfb_time:.1f}s - Serverns backend/databas är långsam.'

            except Exception as e:
                diagnostics['ttfb']['time'] = time.time() - ttfb_start
                diagnostics['ttfb']['status'] = 'critical'
                diagnostics['error'] = f"TTFB-fel: {str(e)[:50]}"
                diagnostics['bottleneck'] = 'ttfb'
                diagnostics['bottleneck_cause'] = 'Kunde inte få svar från servern.'
                sock.close()
                return diagnostics

            # 5. Content Download
            download_start = time.time()
            try:
                sock.setblocking(True)
                sock.settimeout(self.timeout)
                content = b""
                while True:
                    try:
                        chunk = sock.recv(8192)
                        if not chunk:
                            break
                        content += chunk
                        if len(content) > 500000:  # Max 500KB
                            break
                    except socket.timeout:
                        break

                download_time = time.time() - download_start
                diagnostics['download']['time'] = download_time
                diagnostics['download']['status'] = 'good' if download_time < 1.0 else ('ok' if download_time < 3.0 else 'warning')
                diagnostics['content_size'] = len(content)

            except Exception as e:
                diagnostics['download']['time'] = time.time() - download_start
                diagnostics['download']['status'] = 'warning'

            sock.close()

        except Exception as e:
            diagnostics['error'] = f"Oväntat fel: {str(e)[:100]}"

        # Total tid
        total_time = time.time() - total_start
        diagnostics['total']['time'] = total_time
        if total_time < 1.0:
            diagnostics['total']['status'] = 'good'
        elif total_time < 3.0:
            diagnostics['total']['status'] = 'ok'
        elif total_time < 5.0:
            diagnostics['total']['status'] = 'warning'
        else:
            diagnostics['total']['status'] = 'critical'

        # Hitta flaskhals om ingen redan är satt
        if not diagnostics['bottleneck']:
            phases = ['dns', 'tcp', 'ssl', 'ttfb', 'download']
            thresholds = {
                'dns': (0.5, 'Långsam DNS - överväg att byta DNS-provider (ex: Cloudflare 1.1.1.1)'),
                'tcp': (0.5, 'Långsam anslutning - servern är geografiskt långt bort eller överbelastad'),
                'ssl': (1.0, 'Långsam SSL - servern har gammal/långsam SSL-konfiguration'),
                'ttfb': (2.0, 'Långsam TTFB - serverns backend/databas/PHP är långsam'),
                'download': (3.0, 'Långsam nedladdning - stor sida eller ingen komprimering')
            }

            for phase in phases:
                t = diagnostics[phase].get('time')
                if t and phase in thresholds:
                    threshold, cause = thresholds[phase]
                    if t > threshold:
                        diagnostics['bottleneck'] = phase
                        diagnostics['bottleneck_cause'] = cause
                        break

        return diagnostics

    def _update_server_diagnostics(self, diag: dict):
        """Uppdaterar self.server_diagnostics från mätresultat"""
        phases = ['dns', 'tcp', 'ssl', 'ttfb', 'download', 'total']

        for phase in phases:
            if phase in diag and diag[phase].get('time') is not None:
                self.server_diagnostics[phase]['time'] = diag[phase]['time']
                self.server_diagnostics[phase]['status'] = diag[phase]['status']

        self.server_diagnostics['bottleneck'] = diag.get('bottleneck')
        self.server_diagnostics['bottleneck_cause'] = diag.get('bottleneck_cause')

        if diag.get('error'):
            self.server_diagnostics['error'] = diag['error']

        if diag.get('content_size'):
            self.server_diagnostics['content_size'] = diag['content_size']

        # Logga diagnostik
        self._log("   Server-diagnostik:", "")
        for phase in ['dns', 'tcp', 'ssl', 'ttfb', 'download']:
            t = self.server_diagnostics[phase].get('time')
            status = self.server_diagnostics[phase].get('status', 'unknown')
            label = self.server_diagnostics[phase].get('label', phase)
            if t is not None:
                emoji = '✅' if status in ['good', 'ok'] else ('⚠️' if status == 'warning' else '❌')
                self._log(f"   {emoji} {label}: {t*1000:.0f}ms", "")

        if self.server_diagnostics['bottleneck']:
            self._log(f"   ⚠️ Flaskhals: {self.server_diagnostics['bottleneck_cause']}", "")

    def print_header(self):
        """Skriver ut header"""
        print("\n" + "="*70)
        print("🔍  SEO CRAWLABILITY TESTER v1.0")
        print("="*70)
        print(f"Target: {self.target_url}")
        print(f"Tid: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Testar: Googlebot, Mobile-First, Resources, Sitemaps, Cloaking")
        print(f"Antal tester: 15")
        print("="*70 + "\n")
    
    def test_basic_connectivity(self) -> TestResult:
        """Test 0: Grundläggande connectivity med avancerad diagnostik"""
        self._log("Test 0: Basic Connectivity & Diagnostics...", "🔌")

        # Försök 1: Standard request med legitim browser user-agent
        try:
            start_time = time.time()
            response = requests.get(
                self.target_url,
                headers={'User-Agent': self.user_agents['legitimate'][0]},
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            response_time = time.time() - start_time

            return TestResult(
                test_name="Basic Connectivity",
                passed=True,
                details=f"✅ Server svarar (HTTP {response.status_code}, {response_time:.2f}s)",
                response_code=response.status_code,
                response_time=response_time,
                severity="INFO"
            )
        except requests.exceptions.Timeout:
            self._log("  ⚠️ Timeout med standard request, kör diagnostik...", "")
            return self._diagnose_connection_failure("TIMEOUT")
        except requests.exceptions.ConnectionError as e:
            self._log("  ⚠️ Connection error, kör diagnostik...", "")
            return self._diagnose_connection_failure("CONNECTION_ERROR", str(e))
        except Exception as e:
            self._log("  ⚠️ Oväntat fel, kör diagnostik...", "")
            return self._diagnose_connection_failure("UNKNOWN", str(e))

    def _diagnose_connection_failure(self, error_type: str, error_msg: str = "") -> TestResult:
        """Avancerad diagnostik när connection failar"""
        self._log("  🔍 Kör avancerad connection diagnostik...", "")

        diagnostics = []
        cloudflare_detected = False
        connection_possible = False

        # Test 1: Försök med full browser headers
        try:
            full_headers = {
                "User-Agent": self.user_agents['legitimate'][0],
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "sv-SE,sv;q=0.9,en-US;q=0.8,en;q=0.7",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Cache-Control": "max-age=0"
            }

            response = requests.get(
                self.target_url,
                headers=full_headers,
                timeout=self.timeout + 5,  # Lite längre timeout
                verify=False,
                allow_redirects=True
            )

            connection_possible = True
            diagnostics.append("✅ Connection fungerar med kompletta browser headers")

            # Kolla efter Cloudflare
            if 'cloudflare' in response.text.lower() or 'cf-ray' in str(response.headers).lower():
                cloudflare_detected = True
                diagnostics.append("⚠️ Cloudflare detekterat - Kan blockera Python requests")

        except requests.exceptions.Timeout:
            diagnostics.append("❌ Timeout även med kompletta headers (>15s)")
        except Exception as e:
            diagnostics.append(f"❌ Connection failure: {str(e)[:50]}")

        # Test 2: Testa DNS resolution
        try:
            parsed = urlparse(self.target_url)
            hostname = parsed.netloc
            import socket
            ip = socket.gethostbyname(hostname)
            diagnostics.append(f"✅ DNS fungerar: {hostname} → {ip}")
        except Exception as e:
            diagnostics.append(f"❌ DNS failure: Kan inte resolva {hostname}")
            self.seo_issues.append("DNS resolution failure - KRITISKT för SEO")

        # Test 3: Försök med curl-liknande headers (minimal)
        if not connection_possible:
            try:
                curl_headers = {
                    "User-Agent": "curl/7.68.0",
                    "Accept": "*/*"
                }

                response = requests.get(
                    self.target_url,
                    headers=curl_headers,
                    timeout=self.timeout + 5,
                    verify=False
                )

                connection_possible = True
                diagnostics.append("✅ Connection fungerar som 'curl' - Python requests blockeras specifikt")

            except:
                diagnostics.append("❌ Connection failure även som 'curl'")

        # Generera SEO-impact analys
        if not connection_possible:
            self.seo_issues.append("Server nås inte alls - KRITISKT: Googlebot kan inte crawla sidan")
            severity = "CRITICAL"
            impact = "🚨 KRITISKT FÖR SEO: Om verktyget inte kan nå sidan, kan troligen inte Googlebot heller"
        elif cloudflare_detected:
            self.seo_issues.append("Cloudflare blockerar Python requests - kan påverka vissa crawlers")
            severity = "HIGH"
            impact = "⚠️ Cloudflare blockerar script-baserade requests - Kontrollera att Googlebot är whitelistad"
        else:
            severity = "MEDIUM"
            impact = "⚠️ Connection-problem detekterat - Kan påverka crawlbarhet"

        # Bygg detaljerat felmeddelande
        details_parts = [impact]
        if error_type == "TIMEOUT":
            details_parts.append(f"Timeout ({self.timeout}s) - Server svarar för långsamt")
        details_parts.extend(diagnostics[:3])  # Visa max 3 diagnostik-rader

        details = "\n   ".join(details_parts)

        return TestResult(
            test_name="Basic Connectivity",
            passed=False,
            details=details,
            severity=severity
        )
    
    def _extract_bot_name(self, user_agent: str) -> str:
        """Extraherar läsbart bot-namn från User-Agent sträng"""
        # Känd mapping av User-Agents till läsbara namn
        bot_mapping = {
            # Sökmotorbotar
            'Googlebot': 'Googlebot',
            'bingbot': 'Bingbot',
            'Yahoo! Slurp': 'Yahoo Slurp',
            # SEO-verktyg
            'AhrefsBot': 'Ahrefs',
            'SemrushBot': 'Semrush',
            'MJ12bot': 'Majestic',
            'facebookexternalhit': 'Facebook',
            'DotBot': 'Moz/DotBot',
            'Screaming Frog': 'Screaming Frog',
            'SiteAuditBot': 'Semrush Site Audit',
            'MojeekBot': 'Mojeek',
            'LinkedInBot': 'LinkedIn',
            'Twitterbot': 'Twitter/X',
            'Pinterest': 'Pinterest',
            'Slackbot': 'Slack',
            # AI-botar
            'GPTBot': 'GPTBot (OpenAI)',
            'ChatGPT-User': 'ChatGPT',
            'Claude-Web': 'Claude (Anthropic)',
            'Google-Extended': 'Google AI',
            'CCBot': 'Common Crawl',
            'anthropic-ai': 'Anthropic',
            'Bytespider': 'ByteDance/TikTok',
            'PerplexityBot': 'Perplexity AI',
            'Applebot-Extended': 'Apple AI',
            'FacebookBot': 'Meta AI',
            'Omgilibot': 'Omgili',
        }

        for key, name in bot_mapping.items():
            if key in user_agent:
                return name

        # Fallback: försök extrahera namn
        if '(compatible;' in user_agent:
            return user_agent.split('(compatible; ')[-1].split('/')[0].split(';')[0]
        return user_agent.split('/')[0][:20]

    def test_seo_bot_accessibility(self) -> TestResult:
        """Test 1: SEO Bot Accessibility - Kritiskt för SEO

        Testar om sökmotorbotar (Googlebot, Bingbot, etc.) och SEO-verktyg
        (Ahrefs, Semrush, Screaming Frog) kan nå sidan genom att simulera
        deras User-Agent strings.
        """
        self._log("Test 1: SEO Bot Accessibility...", "🔍")
        self._log("   Testar: Sökmotorbotar, SEO-verktyg och AI-botar (26 st)", "")

        # Rensa tidigare resultat
        self.bot_accessibility_details = []

        try:
            accessible_bots = []
            blocked_bots = []

            # Test sökmotorbotar
            for bot_ua in self.user_agents['search_engine_bots']:
                try:
                    response = requests.get(
                        self.target_url,
                        headers={'User-Agent': bot_ua},
                        timeout=self.timeout,
                        verify=False
                    )

                    bot_name = self._extract_bot_name(bot_ua)
                    status_code = response.status_code
                    passed = status_code == 200

                    # Spara detaljerad info för PDF-rapport
                    self.bot_accessibility_details.append({
                        'name': bot_name,
                        'category': 'Sökmotor',
                        'passed': passed,
                        'status_code': status_code
                    })

                    if passed:
                        accessible_bots.append(bot_name)
                    elif status_code in [403, 406, 503]:
                        blocked_bots.append(bot_name)
                        self.seo_issues.append(f"Sökmotorbot blockerad: {bot_name}")

                except Exception as e:
                    bot_name = self._extract_bot_name(bot_ua)
                    self.bot_accessibility_details.append({
                        'name': bot_name,
                        'category': 'Sökmotor',
                        'passed': False,
                        'status_code': None,
                        'error': str(e)[:50]
                    })
                    continue

                time.sleep(0.5)

            # Test SEO-verktygsbotar (testa alla, inte bara 3)
            for bot_ua in self.user_agents['seo_bots']:
                try:
                    response = requests.get(
                        self.target_url,
                        headers={'User-Agent': bot_ua},
                        timeout=self.timeout,
                        verify=False
                    )

                    bot_name = self._extract_bot_name(bot_ua)
                    status_code = response.status_code
                    passed = status_code == 200

                    # Spara detaljerad info för PDF-rapport
                    self.bot_accessibility_details.append({
                        'name': bot_name,
                        'category': 'SEO-verktyg',
                        'passed': passed,
                        'status_code': status_code
                    })

                    if passed:
                        accessible_bots.append(bot_name)
                    elif status_code in [403, 406, 503]:
                        blocked_bots.append(bot_name)

                except Exception as e:
                    bot_name = self._extract_bot_name(bot_ua)
                    self.bot_accessibility_details.append({
                        'name': bot_name,
                        'category': 'SEO-verktyg',
                        'passed': False,
                        'status_code': None,
                        'error': str(e)[:50]
                    })
                    continue

                time.sleep(0.5)

            # Test AI-botar
            for bot_ua in self.user_agents['ai_bots']:
                try:
                    response = requests.get(
                        self.target_url,
                        headers={'User-Agent': bot_ua},
                        timeout=self.timeout,
                        verify=False
                    )

                    bot_name = self._extract_bot_name(bot_ua)
                    status_code = response.status_code
                    passed = status_code == 200

                    # Spara detaljerad info för PDF-rapport
                    self.bot_accessibility_details.append({
                        'name': bot_name,
                        'category': 'AI-bot',
                        'passed': passed,
                        'status_code': status_code
                    })

                    # AI-botar räknas inte mot SEO-score (det kan vara OK att blockera dem)
                    if passed:
                        accessible_bots.append(bot_name)

                except Exception as e:
                    bot_name = self._extract_bot_name(bot_ua)
                    self.bot_accessibility_details.append({
                        'name': bot_name,
                        'category': 'AI-bot',
                        'passed': False,
                        'status_code': None,
                        'error': str(e)[:50]
                    })
                    continue

                time.sleep(0.5)

            # Bedömning med lista över testade botar
            bot_list = ', '.join(accessible_bots[:5])
            if len(accessible_bots) > 5:
                bot_list += f" +{len(accessible_bots)-5} till"

            if len(blocked_bots) == 0:
                return TestResult(
                    test_name="SEO Bot Accessibility",
                    passed=True,
                    details=f"✅ Alla SEO-botar ({len(accessible_bots)}) kan nå sidan: {bot_list}",
                    severity="INFO"
                )
            elif len(blocked_bots) <= 2:
                return TestResult(
                    test_name="SEO Bot Accessibility",
                    passed=False,
                    details=f"⚠️ Vissa SEO-botar blockerade: {', '.join(blocked_bots)}. Tillåtna: {bot_list}",
                    severity="MEDIUM"
                )
            else:
                return TestResult(
                    test_name="SEO Bot Accessibility",
                    passed=False,
                    details=f"❌ Många SEO-botar blockerade ({len(blocked_bots)}): {', '.join(blocked_bots[:3])} - DÅLIGT för SEO",
                    severity="HIGH"
                )

        except Exception as e:
            return TestResult(
                test_name="SEO Bot Accessibility",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)[:100]}",
                severity="MEDIUM"
            )

    def test_robots_txt(self) -> TestResult:
        """Test 2: Robots.txt Analysis"""
        self._log("Test 2: Robots.txt Analysis...", "🤖")

        try:
            parsed = urlparse(self.target_url)
            robots_url = f"{parsed.scheme}://{parsed.netloc}/robots.txt"

            response = requests.get(
                robots_url,
                timeout=self.timeout,
                verify=False,
                headers={'User-Agent': self.user_agents['legitimate'][0]}
            )

            if response.status_code == 200:
                robots_content = response.text.lower()

                # Analysera robots.txt
                issues = []

                # Kolla om viktiga botar blockeras
                critical_bots = ['googlebot', 'bingbot', 'slurp']
                for bot in critical_bots:
                    if f'user-agent: {bot}' in robots_content and 'disallow: /' in robots_content:
                        issues.append(f"{bot} blockerad")
                        self.seo_issues.append(f"robots.txt blockerar {bot}")

                # Kolla efter sitemap
                has_sitemap = 'sitemap:' in robots_content

                if issues:
                    return TestResult(
                        test_name="Robots.txt Analysis",
                        passed=False,
                        details=f"⚠️ robots.txt finns men har problem: {', '.join(issues)}. Sitemap: {'Ja' if has_sitemap else 'Nej'}",
                        severity="HIGH"
                    )
                else:
                    return TestResult(
                        test_name="Robots.txt Analysis",
                        passed=True,
                        details=f"✅ robots.txt korrekt konfigurerad. Sitemap: {'Ja' if has_sitemap else 'Nej'}",
                        severity="INFO"
                    )
            elif response.status_code == 404:
                return TestResult(
                    test_name="Robots.txt Analysis",
                    passed=True,
                    details="ℹ️ Ingen robots.txt (tillåter alla botar som standard)",
                    severity="INFO"
                )
            else:
                return TestResult(
                    test_name="Robots.txt Analysis",
                    passed=False,
                    details=f"⚠️ robots.txt inte tillgänglig (HTTP {response.status_code})",
                    severity="LOW"
                )

        except Exception as e:
            return TestResult(
                test_name="Robots.txt Analysis",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)[:100]}",
                severity="LOW"
            )

    def test_sitemap_accessibility(self) -> TestResult:
        """Test 3: Sitemap.xml Accessibility"""
        self._log("Test 3: Sitemap Accessibility...", "🗺️")

        try:
            parsed = urlparse(self.target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            sitemap_urls = [
                f"{base_url}/sitemap.xml",
                f"{base_url}/sitemap_index.xml",
                f"{base_url}/sitemap-index.xml"
            ]

            found_sitemap = None

            for sitemap_url in sitemap_urls:
                try:
                    response = requests.get(
                        sitemap_url,
                        timeout=self.timeout,
                        verify=False,
                        headers={'User-Agent': self.user_agents['search_engine_bots'][0]}
                    )

                    if response.status_code == 200 and ('<?xml' in response.text or '<urlset' in response.text):
                        found_sitemap = sitemap_url
                        break

                except:
                    continue

                time.sleep(0.3)

            if found_sitemap:
                return TestResult(
                    test_name="Sitemap Accessibility",
                    passed=True,
                    details=f"✅ Sitemap tillgänglig: {found_sitemap.split('/')[-1]} - BRA för SEO",
                    severity="INFO"
                )
            else:
                self.seo_issues.append("Ingen sitemap.xml hittades")
                return TestResult(
                    test_name="Sitemap Accessibility",
                    passed=False,
                    details="⚠️ Ingen sitemap.xml hittades - rekommenderas starkt för SEO",
                    severity="MEDIUM"
                )

        except Exception as e:
            return TestResult(
                test_name="Sitemap Accessibility",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)[:100]}",
                severity="LOW"
            )

    def test_cloaking_detection(self) -> TestResult:
        """Test 4: Cloaking Detection - Bot vs User Content"""
        self._log("Test 4: Cloaking Detection...", "👁️")

        try:
            # Hämta som vanlig användare
            user_response = requests.get(
                self.target_url,
                headers={'User-Agent': self.user_agents['legitimate'][0]},
                timeout=self.timeout,
                verify=False
            )

            time.sleep(1)

            # Hämta som Googlebot
            bot_response = requests.get(
                self.target_url,
                headers={'User-Agent': self.user_agents['search_engine_bots'][0]},
                timeout=self.timeout,
                verify=False
            )

            # Jämför content
            user_length = len(user_response.content)
            bot_length = len(bot_response.content)

            # Beräkna skillnad i procent
            if user_length > 0:
                diff_percent = abs(user_length - bot_length) / user_length * 100
            else:
                diff_percent = 0

            # Cloaking om stor skillnad (>10%)
            if diff_percent > 10:
                self.seo_issues.append(f"Möjlig cloaking detekterad ({diff_percent:.1f}% skillnad)")
                return TestResult(
                    test_name="Cloaking Detection",
                    passed=False,
                    details=f"⚠️ Stor skillnad mellan user/bot content ({diff_percent:.1f}%) - möjlig cloaking",
                    severity="HIGH"
                )
            elif diff_percent > 5:
                return TestResult(
                    test_name="Cloaking Detection",
                    passed=True,
                    details=f"ℹ️ Liten skillnad mellan user/bot content ({diff_percent:.1f}%)",
                    severity="INFO"
                )
            else:
                return TestResult(
                    test_name="Cloaking Detection",
                    passed=True,
                    details=f"✅ Ingen cloaking - samma content för users och botar ({diff_percent:.1f}% skillnad)",
                    severity="INFO"
                )

        except Exception as e:
            return TestResult(
                test_name="Cloaking Detection",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)[:100]}",
                severity="LOW"
            )

    def test_ai_bot_accessibility(self) -> TestResult:
        """Test 5: AI Bot Accessibility - GPTBot, Claude, etc."""
        self._log("Test 5: AI Bot Accessibility...", "🤖")

        try:
            accessible_bots = []
            blocked_bots = []

            # Test AI-botar
            for bot_ua in self.user_agents['ai_bots'][:6]:  # Testa de 6 viktigaste
                try:
                    response = requests.get(
                        self.target_url,
                        headers={'User-Agent': bot_ua},
                        timeout=self.timeout,
                        verify=False
                    )

                    bot_name = bot_ua.split('/')[0]

                    if response.status_code == 200:
                        accessible_bots.append(bot_name)
                    elif response.status_code in [403, 406, 503]:
                        blocked_bots.append(bot_name)

                except:
                    continue

                time.sleep(0.5)

            # Bedömning
            if len(blocked_bots) == 0:
                return TestResult(
                    test_name="AI Bot Accessibility",
                    passed=True,
                    details=f"ℹ️ Alla AI-botar ({len(accessible_bots)}) kan nå sidan (GPTBot, Claude, etc.)",
                    severity="INFO"
                )
            elif len(blocked_bots) <= 2:
                return TestResult(
                    test_name="AI Bot Accessibility",
                    passed=True,
                    details=f"ℹ️ Vissa AI-botar blockerade: {', '.join(blocked_bots)} (OK för content protection)",
                    severity="INFO"
                )
            else:
                return TestResult(
                    test_name="AI Bot Accessibility",
                    passed=True,
                    details=f"ℹ️ Många AI-botar blockerade ({len(blocked_bots)}): {', '.join(blocked_bots[:3])}",
                    severity="INFO"
                )

        except Exception as e:
            return TestResult(
                test_name="AI Bot Accessibility",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)[:100]}",
                severity="LOW"
            )

    def test_response_time_comparison(self) -> TestResult:
        """Test 6: Response Time Comparison - Bot vs User"""
        self._log("Test 6: Response Time Comparison (Bot Throttling)...", "⏱️")

        try:
            # Test som vanlig användare
            user_times = []
            for _ in range(3):
                start = time.time()
                response = requests.get(
                    self.target_url,
                    headers={'User-Agent': self.user_agents['legitimate'][0]},
                    timeout=self.timeout,
                    verify=False
                )
                user_times.append(time.time() - start)
                time.sleep(0.5)

            avg_user_time = sum(user_times) / len(user_times)

            # Test som Googlebot
            bot_times = []
            for _ in range(3):
                start = time.time()
                response = requests.get(
                    self.target_url,
                    headers={'User-Agent': self.user_agents['search_engine_bots'][0]},
                    timeout=self.timeout,
                    verify=False
                )
                bot_times.append(time.time() - start)
                time.sleep(0.5)

            avg_bot_time = sum(bot_times) / len(bot_times)

            # Jämför
            if avg_bot_time > avg_user_time * 1.5:  # 50% långsammare
                self.seo_issues.append(f"Googlebot får {((avg_bot_time/avg_user_time - 1) * 100):.0f}% långsammare svar (bot throttling)")
                return TestResult(
                    test_name="Response Time Comparison",
                    passed=False,
                    details=f"⚠️ Googlebot throttlas: User {avg_user_time:.2f}s, Bot {avg_bot_time:.2f}s ({((avg_bot_time/avg_user_time - 1) * 100):.0f}% långsammare) - DÅLIGT för crawl budget",
                    severity="HIGH"
                )
            elif avg_bot_time > avg_user_time * 1.2:  # 20% långsammare
                return TestResult(
                    test_name="Response Time Comparison",
                    passed=False,
                    details=f"ℹ️ Googlebot något långsammare: User {avg_user_time:.2f}s, Bot {avg_bot_time:.2f}s ({((avg_bot_time/avg_user_time - 1) * 100):.0f}% långsammare)",
                    severity="MEDIUM"
                )
            else:
                return TestResult(
                    test_name="Response Time Comparison",
                    passed=True,
                    details=f"✅ Ingen bot throttling: User {avg_user_time:.2f}s, Bot {avg_bot_time:.2f}s - BRA för SEO",
                    severity="INFO"
                )

        except Exception as e:
            return TestResult(
                test_name="Response Time Comparison",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)[:100]}",
                severity="LOW"
            )

    def test_googlebot_stress_test(self) -> TestResult:
        """Test 7: Googlebot Stress Test - Rate limiting för SEO-botar"""
        self._log("Test 7: Googlebot Stress Test (Rate Limiting)...", "🚨")

        try:
            googlebot_ua = self.user_agents['search_engine_bots'][0]
            blocked_at = None
            requests_sent = 0
            max_requests = 25

            for i in range(max_requests):
                try:
                    response = requests.get(
                        self.target_url,
                        headers={'User-Agent': googlebot_ua},
                        timeout=self.timeout,
                        verify=False
                    )
                    requests_sent += 1

                    if response.status_code in [429, 403, 503]:
                        blocked_at = requests_sent
                        break

                except requests.exceptions.Timeout:
                    blocked_at = requests_sent
                    break
                except:
                    continue

                time.sleep(0.1)  # Snabb frekvens

            if blocked_at and blocked_at < 15:
                self.seo_issues.append(f"Googlebot rate-limitad efter endast {blocked_at} requests")
                return TestResult(
                    test_name="Googlebot Stress Test",
                    passed=False,
                    details=f"❌ Googlebot blockerad efter {blocked_at} requests - MYCKET DÅLIGT för SEO (för aggressiv rate limiting)",
                    severity="CRITICAL"
                )
            elif blocked_at and blocked_at < 20:
                self.seo_issues.append(f"Googlebot rate-limitad efter {blocked_at} requests")
                return TestResult(
                    test_name="Googlebot Stress Test",
                    passed=False,
                    details=f"⚠️ Googlebot blockerad efter {blocked_at} requests - Kan påverka crawl budget negativt",
                    severity="HIGH"
                )
            else:
                return TestResult(
                    test_name="Googlebot Stress Test",
                    passed=True,
                    details=f"✅ Googlebot klarar {requests_sent} requests utan blockering - BRA för SEO",
                    severity="INFO"
                )

        except Exception as e:
            return TestResult(
                test_name="Googlebot Stress Test",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)[:100]}",
                severity="MEDIUM"
            )

    def test_bot_differential_treatment(self) -> TestResult:
        """Test 8: SEO Bot Differential Treatment - Jämför bot vs user behandling"""
        self._log("Test 8: Bot Differential Treatment...", "⚖️")

        try:
            results = {}

            # Test som vanlig användare
            user_response = requests.get(
                self.target_url,
                headers={'User-Agent': self.user_agents['legitimate'][0]},
                timeout=self.timeout,
                verify=False
            )
            results['user'] = {
                'code': user_response.status_code,
                'length': len(user_response.content),
                'time': user_response.elapsed.total_seconds()
            }

            time.sleep(1)

            # Test som Googlebot
            googlebot_response = requests.get(
                self.target_url,
                headers={'User-Agent': self.user_agents['search_engine_bots'][0]},
                timeout=self.timeout,
                verify=False
            )
            results['googlebot'] = {
                'code': googlebot_response.status_code,
                'length': len(googlebot_response.content),
                'time': googlebot_response.elapsed.total_seconds()
            }

            time.sleep(1)

            # Test som Bingbot
            bingbot_response = requests.get(
                self.target_url,
                headers={'User-Agent': self.user_agents['search_engine_bots'][1]},
                timeout=self.timeout,
                verify=False
            )
            results['bingbot'] = {
                'code': bingbot_response.status_code,
                'length': len(bingbot_response.content),
                'time': bingbot_response.elapsed.total_seconds()
            }

            # Analysera behandling
            issues = []

            # Kolla statuskoder
            if results['googlebot']['code'] != results['user']['code']:
                issues.append(f"Googlebot får {results['googlebot']['code']} men user får {results['user']['code']}")
                self.seo_issues.append(f"Server behandlar Googlebot annorlunda (HTTP {results['googlebot']['code']} vs {results['user']['code']})")

            if results['bingbot']['code'] != results['user']['code']:
                issues.append(f"Bingbot får {results['bingbot']['code']} men user får {results['user']['code']}")

            # Kolla content length skillnader
            user_len = results['user']['length']
            if abs(results['googlebot']['length'] - user_len) / user_len > 0.05:  # >5% skillnad
                issues.append(f"Content length skillnad: Googlebot {results['googlebot']['length']} vs User {user_len}")

            if issues:
                return TestResult(
                    test_name="Bot Differential Treatment",
                    passed=False,
                    details=f"⚠️ Server behandlar botar annorlunda: {'; '.join(issues[:2])} - KONTROLLERA WEBBHOTELL INSTÄLLNINGAR",
                    severity="HIGH"
                )
            else:
                return TestResult(
                    test_name="Bot Differential Treatment",
                    passed=True,
                    details=f"✅ Botar och användare behandlas lika (Google: {results['googlebot']['code']}, Bing: {results['bingbot']['code']}, User: {results['user']['code']})",
                    severity="INFO"
                )

        except Exception as e:
            return TestResult(
                test_name="Bot Differential Treatment",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)[:100]}",
                severity="MEDIUM"
            )

    def test_progressive_blocking(self) -> TestResult:
        """Test 9: Progressive Blocking Detection - Blir botten gradvis blockerad"""
        self._log("Test 9: Progressive Blocking Detection...", "📉")

        try:
            googlebot_ua = self.user_agents['search_engine_bots'][0]
            responses = []
            num_tests = 10

            for i in range(num_tests):
                try:
                    start = time.time()
                    response = requests.get(
                        self.target_url,
                        headers={'User-Agent': googlebot_ua},
                        timeout=self.timeout,
                        verify=False
                    )
                    response_time = time.time() - start

                    responses.append({
                        'index': i + 1,
                        'code': response.status_code,
                        'time': response_time,
                        'length': len(response.content)
                    })

                except requests.exceptions.Timeout:
                    responses.append({
                        'index': i + 1,
                        'code': 'TIMEOUT',
                        'time': self.timeout,
                        'length': 0
                    })
                except:
                    responses.append({
                        'index': i + 1,
                        'code': 'ERROR',
                        'time': 0,
                        'length': 0
                    })

                time.sleep(0.3)

            # Analysera progressiv försämring
            first_half = responses[:5]
            second_half = responses[5:]

            first_half_ok = sum(1 for r in first_half if r['code'] == 200)
            second_half_ok = sum(1 for r in second_half if r['code'] == 200)

            first_half_avg_time = sum(r['time'] for r in first_half if r['code'] == 200) / max(first_half_ok, 1)
            second_half_avg_time = sum(r['time'] for r in second_half if r['code'] == 200) / max(second_half_ok, 1)

            # Detektera progressiv blockering
            if second_half_ok < first_half_ok - 2:  # 2+ färre OK responses i andra halvan
                self.seo_issues.append(f"Progressiv blockering: {first_half_ok}/5 OK requests först, {second_half_ok}/5 OK sedan")
                return TestResult(
                    test_name="Progressive Blocking",
                    passed=False,
                    details=f"❌ Progressiv blockering detekterad: Request 1-5: {first_half_ok}/5 OK, Request 6-10: {second_half_ok}/5 OK - SERVER BLOCKERAR GOOGLEBOT PROGRESSIVT",
                    severity="CRITICAL"
                )
            elif second_half_avg_time > first_half_avg_time * 1.5:  # 50% långsammare
                return TestResult(
                    test_name="Progressive Blocking",
                    passed=False,
                    details=f"⚠️ Response times försämras: {first_half_avg_time:.2f}s → {second_half_avg_time:.2f}s (soft throttling)",
                    severity="HIGH"
                )
            else:
                return TestResult(
                    test_name="Progressive Blocking",
                    passed=True,
                    details=f"✅ Ingen progressiv blockering: {first_half_ok + second_half_ok}/{num_tests} requests OK",
                    severity="INFO"
                )

        except Exception as e:
            return TestResult(
                test_name="Progressive Blocking",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)[:100]}",
                severity="MEDIUM"
            )

    def test_mobile_vs_desktop_googlebot(self) -> TestResult:
        """Test 10: Mobile vs Desktop Googlebot - Mobile-First Indexing"""
        self._log("Test 10: Mobile vs Desktop Googlebot...", "📱")

        try:
            # Test med Desktop Googlebot
            desktop_response = requests.get(
                self.target_url,
                headers={'User-Agent': self.user_agents['googlebot_desktop'][0]},
                timeout=self.timeout,
                verify=False
            )
            desktop_code = desktop_response.status_code
            desktop_length = len(desktop_response.content)
            desktop_time = desktop_response.elapsed.total_seconds()

            time.sleep(1)

            # Test med Mobile Googlebot
            mobile_response = requests.get(
                self.target_url,
                headers={'User-Agent': self.user_agents['googlebot_mobile'][0]},
                timeout=self.timeout,
                verify=False
            )
            mobile_code = mobile_response.status_code
            mobile_length = len(mobile_response.content)
            mobile_time = mobile_response.elapsed.total_seconds()

            issues = []

            # Kolla statuskoder
            if desktop_code != mobile_code:
                issues.append(f"Olika statuskoder: Desktop {desktop_code}, Mobile {mobile_code}")
                self.seo_issues.append(f"Mobile Googlebot får annorlunda statuskod ({mobile_code}) än Desktop ({desktop_code})")

            # Kolla om mobile blockeras
            if mobile_code in [403, 406, 503] and desktop_code == 200:
                self.seo_issues.append("Mobile Googlebot BLOCKERAS - KRITISKT för Mobile-First Indexing")
                return TestResult(
                    test_name="Mobile vs Desktop Googlebot",
                    passed=False,
                    details=f"❌ Mobile Googlebot blockeras (HTTP {mobile_code}) men Desktop tillåts - KRITISKT för SEO",
                    severity="CRITICAL"
                )

            # Kolla content-skillnad
            if desktop_length > 0:
                content_diff = abs(desktop_length - mobile_length) / desktop_length * 100
                if content_diff > 20:
                    issues.append(f"Stor content-skillnad: {content_diff:.1f}%")
                    self.seo_issues.append(f"Mobile version har {content_diff:.1f}% annorlunda content - kan påverka Mobile-First Indexing")

            # Kolla response time skillnad
            if mobile_time > desktop_time * 1.5:
                issues.append(f"Mobile långsammare: {mobile_time:.2f}s vs {desktop_time:.2f}s")

            if issues:
                return TestResult(
                    test_name="Mobile vs Desktop Googlebot",
                    passed=False,
                    details=f"⚠️ Skillnader detekterade: {'; '.join(issues)}",
                    severity="HIGH"
                )
            else:
                return TestResult(
                    test_name="Mobile vs Desktop Googlebot",
                    passed=True,
                    details=f"✅ Mobile och Desktop Googlebot behandlas lika (båda HTTP {mobile_code}, ~{mobile_length} bytes) - BRA för Mobile-First Indexing",
                    severity="INFO"
                )

        except Exception as e:
            return TestResult(
                test_name="Mobile vs Desktop Googlebot",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)[:100]}",
                severity="MEDIUM"
            )

    def test_blocked_resources(self) -> TestResult:
        """Test 11: Blocked Resources Detection - CSS/JS tillgänglighet för botar

        Testar om CSS- och JavaScript-filer är tillgängliga för Googlebot.
        Om dessa blockeras kan Google inte rendera sidan korrekt, vilket
        påverkar hur sidan indexeras och rankas.
        """
        self._log("Test 11: Blocked Resources Detection...", "🚫")
        self._log("   Testar om CSS/JS-resurser är tillgängliga för Googlebot", "")

        try:
            import re

            # Hämta sidan som Googlebot
            response = requests.get(
                self.target_url,
                headers={'User-Agent': self.user_agents['googlebot_desktop'][0]},
                timeout=self.timeout,
                verify=False
            )

            if response.status_code != 200:
                return TestResult(
                    test_name="Blocked Resources",
                    passed=False,
                    details=f"⚠️ Kunde inte hämta sidan (HTTP {response.status_code})",
                    severity="MEDIUM"
                )

            html = response.text
            parsed = urlparse(self.target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # Hitta CSS och JS resurser
            css_pattern = r'<link[^>]+href=["\']([^"\']+\.css[^"\']*)["\']'
            js_pattern = r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']'

            css_urls = re.findall(css_pattern, html, re.IGNORECASE)
            js_urls = re.findall(js_pattern, html, re.IGNORECASE)

            all_resources = []
            tested_names = []

            for url in css_urls[:5]:  # Testa max 5 CSS
                if url.startswith('//'):
                    all_resources.append(('CSS', f"https:{url}"))
                elif url.startswith('/'):
                    all_resources.append(('CSS', f"{base_url}{url}"))
                elif url.startswith('http'):
                    all_resources.append(('CSS', url))

            for url in js_urls[:5]:  # Testa max 5 JS
                if url.startswith('//'):
                    all_resources.append(('JS', f"https:{url}"))
                elif url.startswith('/'):
                    all_resources.append(('JS', f"{base_url}{url}"))
                elif url.startswith('http'):
                    all_resources.append(('JS', url))

            if not all_resources:
                return TestResult(
                    test_name="Blocked Resources",
                    passed=True,
                    details="ℹ️ Inga externa CSS/JS-resurser hittades att testa (inline styles/scripts)",
                    severity="INFO"
                )

            blocked_resources = []
            accessible_resources = 0

            for resource_type, resource_url in all_resources:
                filename = resource_url.split('/')[-1].split('?')[0][:30]  # Korta ner filnamn
                try:
                    res_response = requests.get(
                        resource_url,
                        headers={'User-Agent': self.user_agents['googlebot_desktop'][0]},
                        timeout=5,
                        verify=False
                    )

                    if res_response.status_code in [403, 406, 503]:
                        blocked_resources.append(f"{resource_type}: {filename}")
                    elif res_response.status_code == 200:
                        accessible_resources += 1
                        tested_names.append(f"{resource_type}:{filename}")

                except:
                    blocked_resources.append(f"{resource_type}: {filename} (timeout)")

                time.sleep(0.2)

            # Skapa lista över testade resurser
            tested_list = ', '.join(tested_names[:4])
            if len(tested_names) > 4:
                tested_list += f" +{len(tested_names)-4} till"

            if blocked_resources:
                self.seo_issues.append(f"{len(blocked_resources)} CSS/JS-resurser blockerade för Googlebot - påverkar rendering")
                return TestResult(
                    test_name="Blocked Resources",
                    passed=False,
                    details=f"❌ {len(blocked_resources)} resurser blockerade: {', '.join(blocked_resources[:3])} - Google kan inte rendera sidan korrekt",
                    severity="HIGH"
                )
            else:
                return TestResult(
                    test_name="Blocked Resources",
                    passed=True,
                    details=f"✅ Alla {accessible_resources} resurser tillgängliga: {tested_list}",
                    severity="INFO"
                )

        except Exception as e:
            return TestResult(
                test_name="Blocked Resources",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)[:100]}",
                severity="LOW"
            )

    def test_protocol_consistency(self) -> TestResult:
        """Test 12: HTTP/HTTPS & WWW Consistency - Redirect-hantering

        Testar att alla URL-varianter (http/https, www/non-www) redirectar
        till samma destination. Duplicate content uppstår om flera URL:er
        serverar samma innehåll utan redirects.

        SEO-påverkan: Google kan indexera samma sida flera gånger,
        vilket späder ut länkkraft och skapar duplicate content.
        """
        self._log("Test 12: Protocol & WWW Consistency...", "🔗")
        self._log("   Testar: http vs https, www vs non-www redirects", "")

        try:
            parsed = urlparse(self.target_url)
            domain = parsed.netloc

            # Ta bort www. om det finns för att få "ren" domän
            clean_domain = domain.replace('www.', '')

            # Skapa alla varianter att testa
            variants = [
                f"http://{clean_domain}",
                f"https://{clean_domain}",
                f"http://www.{clean_domain}",
                f"https://www.{clean_domain}"
            ]

            results = {}
            issues = []
            detailed_results = []

            for variant in variants:
                try:
                    response = requests.get(
                        variant,
                        headers={'User-Agent': self.user_agents['googlebot_desktop'][0]},
                        timeout=self.timeout,
                        verify=False,
                        allow_redirects=False  # Följ inte redirects automatiskt
                    )

                    results[variant] = {
                        'code': response.status_code,
                        'location': response.headers.get('Location', None)
                    }

                    # Spara detaljerat resultat
                    short_variant = variant.replace('https://', '').replace('http://', '')
                    if response.status_code in [301, 302, 307, 308]:
                        loc = response.headers.get('Location', '?')
                        detailed_results.append(f"{short_variant} → {loc.split('/')[-1] if '/' in loc else loc}")
                    else:
                        detailed_results.append(f"{short_variant} = {response.status_code}")

                except requests.exceptions.ConnectionError:
                    results[variant] = {'code': 'CONNECTION_ERROR', 'location': None}
                except requests.exceptions.Timeout:
                    results[variant] = {'code': 'TIMEOUT', 'location': None}
                except Exception as e:
                    results[variant] = {'code': 'ERROR', 'location': None}

                time.sleep(0.3)

            # Analysera resultat

            # 1. Kolla att HTTP redirectar till HTTPS
            http_variant = f"http://{clean_domain}"

            if http_variant in results and results[http_variant]['code'] not in [301, 302, 307, 308]:
                if results[http_variant]['code'] == 200:
                    issues.append(f"http://{clean_domain} svarar 200 (borde redirecta till HTTPS)")
                    self.seo_issues.append(f"HTTP-version ({clean_domain}) redirectar INTE till HTTPS - duplicate content risk")

            # 2. Kolla att alla varianter pekar till samma destination
            final_destinations = set()
            destination_details = {}
            for variant, data in results.items():
                if data['location']:
                    final_destinations.add(data['location'])
                    destination_details[variant] = data['location']
                elif data['code'] == 200:
                    final_destinations.add(variant)
                    destination_details[variant] = variant

            if len(final_destinations) > 1:
                dest_list = list(final_destinations)[:3]
                issues.append(f"{len(final_destinations)} olika destinations: {', '.join([d.replace('https://', '').replace('http://', '') for d in dest_list])}")
                self.seo_issues.append("WWW/non-WWW pekar på olika destinations - duplicate content risk")

            # 3. Kolla redirect chains (mer än 1 redirect)
            for variant in variants:
                try:
                    chain_response = requests.get(
                        variant,
                        headers={'User-Agent': self.user_agents['googlebot_desktop'][0]},
                        timeout=self.timeout,
                        verify=False,
                        allow_redirects=True
                    )

                    redirect_count = len(chain_response.history)
                    if redirect_count > 2:
                        issues.append(f"Redirect chain: {redirect_count} hopp (max 2 rekommenderas)")
                        self.seo_issues.append(f"Redirect chain för lång ({redirect_count} hopp) - slösar crawl budget")
                        break  # Räcker att hitta ett problem

                except:
                    pass

                time.sleep(0.2)

            # Sammanfatta
            if issues:
                return TestResult(
                    test_name="Protocol & WWW Consistency",
                    passed=False,
                    details=f"⚠️ URL-konsistensproblem: {'; '.join(issues[:2])}",
                    severity="HIGH"
                )
            else:
                # Visa vilken som är "canonical"
                canonical = None
                for variant, data in results.items():
                    if data['code'] == 200:
                        canonical = variant.replace('https://', '').replace('http://', '')
                        break

                return TestResult(
                    test_name="Protocol & WWW Consistency",
                    passed=True,
                    details=f"✅ Alla varianter redirectar korrekt till {canonical or 'samma URL'} - ingen duplicate content risk",
                    severity="INFO"
                )

        except Exception as e:
            return TestResult(
                test_name="Protocol & WWW Consistency",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)[:100]}",
                severity="LOW"
            )

    def test_server_performance(self) -> TestResult:
        """Test 13: Server Performance Analysis - TTFB, SSL, Compression, Caching

        Testar server-prestanda ur ett SEO-perspektiv:
        - TTFB (Time To First Byte) - Google rekommenderar <200ms
        - SSL-certifikat - HTTPS är en rankingfaktor
        - Komprimering (gzip/brotli) - Påverkar sidladdning
        - Cache-headers - Påverkar crawl budget
        """
        self._log("Test 13: Server Performance Analysis...", "⚡")
        self._log("   Testar: TTFB, SSL-cert, komprimering, cache-headers", "")

        try:
            response_times = []
            ttfb_times = []
            features = []
            problems = []

            # Gör 5 requests för att få genomsnittlig performance
            for i in range(5):
                try:
                    start = time.time()
                    response = requests.get(
                        self.target_url,
                        headers={
                            'User-Agent': self.user_agents['legitimate'][0],
                            'Accept-Encoding': 'gzip, deflate, br'
                        },
                        timeout=self.timeout,
                        verify=True,  # Verifiera SSL
                        stream=True  # För att mäta TTFB
                    )

                    # Time To First Byte (TTFB)
                    ttfb = time.time() - start
                    ttfb_times.append(ttfb)

                    # Läs hela responsen
                    _ = response.content
                    total_time = time.time() - start
                    response_times.append(total_time)

                    # Endast på första request: kolla headers
                    if i == 0:
                        headers = response.headers

                        # Kolla komprimering
                        content_encoding = headers.get('Content-Encoding', '').lower()
                        if 'br' in content_encoding:
                            features.append(f"Komprimering: brotli")
                            self.server_performance_details['compression'] = {
                                'value': 'Brotli', 'status': 'good', 'label': 'Komprimering'
                            }
                        elif 'gzip' in content_encoding:
                            features.append(f"Komprimering: gzip")
                            self.server_performance_details['compression'] = {
                                'value': 'Gzip', 'status': 'good', 'label': 'Komprimering'
                            }
                        else:
                            problems.append("Ingen komprimering (gzip/brotli)")
                            self.server_performance_issues.append("Ingen gzip/brotli-komprimering - långsammare sidladdning")
                            self.server_performance_details['compression'] = {
                                'value': 'Saknas', 'status': 'critical', 'label': 'Komprimering'
                            }

                        # Kolla cache-headers
                        cache_control = headers.get('Cache-Control', '')
                        if cache_control and 'no-' not in cache_control.lower():
                            features.append("Cache aktivt")
                            self.server_performance_details['cache'] = {
                                'value': 'Aktivt', 'status': 'good', 'label': 'Cache'
                            }
                        elif 'no-cache' in cache_control.lower() or 'no-store' in cache_control.lower():
                            self.server_performance_details['cache'] = {
                                'value': 'Inaktivt', 'status': 'warning', 'label': 'Cache'
                            }
                        else:
                            problems.append("Inga cache-headers")
                            self.server_performance_details['cache'] = {
                                'value': 'Saknas', 'status': 'warning', 'label': 'Cache'
                            }

                        # Kolla HTTP-version
                        if hasattr(response.raw, 'version'):
                            if response.raw.version == 20:
                                features.append("HTTP/2")
                                self.server_performance_details['http_version'] = {
                                    'value': 'HTTP/2', 'status': 'good', 'label': 'Protokoll'
                                }
                            elif response.raw.version == 11:
                                self.server_performance_details['http_version'] = {
                                    'value': 'HTTP/1.1', 'status': 'ok', 'label': 'Protokoll'
                                }

                        # Kolla server-header
                        server_header = headers.get('Server', '')
                        if server_header:
                            self.server_performance_details['server'] = {
                                'value': server_header[:20], 'status': 'info', 'label': 'Server'
                            }

                except requests.exceptions.SSLError as e:
                    problems.append("SSL-certifikatfel")
                    self.server_performance_issues.append(f"SSL-certifikatproblem: {str(e)[:50]}")
                    self.seo_issues.append("SSL-certifikatfel - HTTPS är en Google rankingfaktor")
                except Exception as e:
                    continue

                time.sleep(0.5)

            # Testa SSL-certifikat separat
            try:
                import ssl
                import socket
                parsed = urlparse(self.target_url)
                hostname = parsed.netloc

                context = ssl.create_default_context()
                with socket.create_connection((hostname, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        # Kolla utgångsdatum
                        import datetime
                        not_after = cert.get('notAfter', '')
                        if not_after:
                            # Exempel: 'Dec 31 23:59:59 2024 GMT'
                            try:
                                expire_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                                days_left = (expire_date - datetime.datetime.now()).days
                                if days_left < 30:
                                    problems.append(f"SSL går ut om {days_left} dagar!")
                                    self.seo_issues.append(f"SSL-certifikat går ut om {days_left} dagar")
                                    self.server_performance_details['ssl'] = {
                                        'value': f'{days_left}d', 'status': 'critical', 'label': 'SSL'
                                    }
                                elif days_left < 90:
                                    features.append(f"SSL OK ({days_left}d kvar)")
                                    self.server_performance_details['ssl'] = {
                                        'value': f'{days_left}d', 'status': 'warning', 'label': 'SSL'
                                    }
                                else:
                                    features.append("SSL giltigt")
                                    self.server_performance_details['ssl'] = {
                                        'value': f'{days_left}d', 'status': 'good', 'label': 'SSL'
                                    }
                            except:
                                features.append("SSL OK")
                                self.server_performance_details['ssl'] = {
                                    'value': 'OK', 'status': 'good', 'label': 'SSL'
                                }
            except Exception as e:
                if "SSL" not in str(problems):
                    problems.append("Kunde inte verifiera SSL")
                    self.server_performance_details['ssl'] = {
                        'value': 'Fel', 'status': 'critical', 'label': 'SSL'
                    }

            if not response_times:
                return TestResult(
                    test_name="Server Performance",
                    passed=False,
                    details="❌ Kunde inte mäta server performance",
                    severity="HIGH"
                )

            avg_ttfb = sum(ttfb_times) / len(ttfb_times)
            avg_response = sum(response_times) / len(response_times)

            # Spara server info
            self.server_info['avg_ttfb'] = avg_ttfb
            self.server_info['avg_response_time'] = avg_response

            # Bedöm TTFB och spara detaljerad info för PDF
            severity = "INFO"
            if avg_ttfb > 1.0:
                problems.append(f"TTFB {avg_ttfb:.2f}s (KRITISKT, mål <0.2s)")
                self.server_performance_issues.append(f"TTFB {avg_ttfb:.2f}s - KRITISKT långsamt (Google rekommenderar <200ms)")
                severity = "CRITICAL"
                self.server_performance_details['ttfb'] = {
                    'value': f"{avg_ttfb:.2f}s", 'status': 'critical', 'label': 'TTFB'
                }
            elif avg_ttfb > 0.6:
                problems.append(f"TTFB {avg_ttfb:.2f}s (långsamt)")
                self.server_performance_issues.append(f"TTFB {avg_ttfb:.2f}s - Långsammare än Google's rekommendation (200ms)")
                severity = "HIGH"
                self.server_performance_details['ttfb'] = {
                    'value': f"{avg_ttfb:.2f}s", 'status': 'warning', 'label': 'TTFB'
                }
            elif avg_ttfb > 0.2:
                features.append(f"TTFB {avg_ttfb:.2f}s (OK)")
                severity = "MEDIUM"
                self.server_performance_details['ttfb'] = {
                    'value': f"{avg_ttfb:.2f}s", 'status': 'ok', 'label': 'TTFB'
                }
            else:
                features.append(f"TTFB {avg_ttfb:.3f}s (snabb)")
                self.server_performance_details['ttfb'] = {
                    'value': f"{avg_ttfb:.0f}ms", 'status': 'good', 'label': 'TTFB'
                }

            # Sammanställ resultat
            feature_str = ', '.join(features[:4]) if features else "inga optimeringar"
            problem_str = '; '.join(problems[:2]) if problems else ""

            if problems and severity in ["CRITICAL", "HIGH"]:
                return TestResult(
                    test_name="Server Performance",
                    passed=False,
                    details=f"⚠️ {problem_str}. Optimeringar: {feature_str}",
                    severity=severity
                )
            elif problems:
                return TestResult(
                    test_name="Server Performance",
                    passed=True,
                    details=f"✅ TTFB {avg_ttfb:.2f}s. {feature_str}. Tips: {problem_str}",
                    severity="INFO"
                )
            else:
                return TestResult(
                    test_name="Server Performance",
                    passed=True,
                    details=f"✅ Utmärkt! TTFB {avg_ttfb:.3f}s, {feature_str}",
                    severity="INFO"
                )

        except Exception as e:
            return TestResult(
                test_name="Server Performance",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)[:100]}",
                severity="MEDIUM"
            )

    def test_server_load_handling(self) -> TestResult:
        """Test 14: Server Load Handling - Klarar servern belastning?

        Simulerar hur servern presterar när Googlebot crawlar flera sidor
        samtidigt. Googlebot kan göra 2-10+ requests per sekund beroende
        på din servers kapacitet.

        SEO-påverkan:
        - Om servern blir långsam: Google minskar crawl rate
        - Om requests misslyckas: Sidor indexeras inte
        - Långsam server = sämre användarupplevelse = lägre ranking

        Testet skickar 10 samtidiga requests och jämför med baseline.
        """
        self._log("Test 14: Server Load Handling...", "💪")
        self._log("   Simulerar: 10 samtidiga requests (som Googlebot vid aktiv crawling)", "")

        try:
            import concurrent.futures

            def make_request():
                try:
                    start = time.time()
                    response = requests.get(
                        self.target_url,
                        headers={'User-Agent': self.user_agents['legitimate'][0]},
                        timeout=self.timeout,
                        verify=False
                    )
                    return {
                        'success': True,
                        'time': time.time() - start,
                        'code': response.status_code
                    }
                except Exception as e:
                    return {
                        'success': False,
                        'time': None,
                        'error': str(e)[:50]
                    }

            # Skicka 10 samtidiga requests (simulerar Googlebot crawling)
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(make_request) for _ in range(10)]
                results = [f.result() for f in concurrent.futures.as_completed(futures)]

            successful = [r for r in results if r['success']]
            failed = [r for r in results if not r['success']]

            if not successful:
                self.server_performance_issues.append("Server klarar inte concurrent requests - Googlebot kan inte crawla effektivt")
                return TestResult(
                    test_name="Server Load Handling",
                    passed=False,
                    details=f"❌ Server kollapsade: 0/10 requests lyckades - Googlebot kan inte crawla din sajt under normal belastning",
                    severity="CRITICAL"
                )

            avg_concurrent_time = sum(r['time'] for r in successful) / len(successful)
            success_rate = len(successful) / len(results) * 100

            # Jämför med baseline (en request i taget)
            baseline = self.server_info.get('avg_response_time', 0)
            if baseline > 0:
                slowdown = (avg_concurrent_time / baseline - 1) * 100
            else:
                slowdown = 0

            if success_rate < 70:
                self.server_performance_issues.append(f"Server för svag - {100-success_rate:.0f}% av requests misslyckades")
                return TestResult(
                    test_name="Server Load Handling",
                    passed=False,
                    details=f"❌ Server för svag: {len(failed)}/10 requests misslyckades. Google kommer minska crawl rate drastiskt",
                    severity="CRITICAL"
                )
            elif slowdown > 100:  # >100% långsammare under load
                self.server_performance_issues.append(f"Server {slowdown:.0f}% långsammare under belastning")
                return TestResult(
                    test_name="Server Load Handling",
                    passed=False,
                    details=f"⚠️ Server sackar vid belastning: {slowdown:.0f}% långsammare (baseline {baseline:.2f}s → {avg_concurrent_time:.2f}s vid 10 requests). Google anpassar crawl rate efter serverns kapacitet",
                    severity="HIGH"
                )
            elif slowdown > 50:
                return TestResult(
                    test_name="Server Load Handling",
                    passed=True,
                    details=f"ℹ️ Server något långsammare under load: +{slowdown:.0f}% ({baseline:.2f}s → {avg_concurrent_time:.2f}s) - Acceptabelt",
                    severity="MEDIUM"
                )
            else:
                return TestResult(
                    test_name="Server Load Handling",
                    passed=True,
                    details=f"✅ Server stabil under belastning: 10/10 lyckades, {avg_concurrent_time:.2f}s avg (+{slowdown:.0f}% vs baseline). Klarar Googlebot crawling bra",
                    severity="INFO"
                )

        except Exception as e:
            return TestResult(
                test_name="Server Load Handling",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)[:100]}",
                severity="MEDIUM"
            )

    def test_server_technology_detection(self) -> TestResult:
        """Test 15: Server Technology Detection"""
        self._log("Test 15: Server Technology Detection...", "🔧")

        try:
            response = requests.get(
                self.target_url,
                headers={'User-Agent': self.user_agents['legitimate'][0]},
                timeout=self.timeout,
                verify=False
            )

            headers = response.headers
            detected_tech = []

            # Server header
            server = headers.get('Server', 'Unknown')
            detected_tech.append(f"Server: {server}")
            self.server_info['server'] = server

            # Identifiera teknologier
            tech_indicators = {
                'Cloudflare': 'cloudflare' in server.lower() or 'cf-ray' in str(headers).lower(),
                'Nginx': 'nginx' in server.lower(),
                'Apache': 'apache' in server.lower(),
                'IIS': 'iis' in server.lower() or 'microsoft' in server.lower(),
                'WordPress': 'wp-' in str(headers).lower() or '/wp-' in response.text[:5000],
                'PHP': 'x-powered-by' in str(headers).lower() and 'php' in str(headers).lower(),
                'Plesk': 'plesk' in server.lower() or 'x-powered-by' in str(headers).lower() and 'plesk' in str(headers).lower()
            }

            detected = [tech for tech, detected in tech_indicators.items() if detected]

            if detected:
                detected_tech.append(f"Teknologier: {', '.join(detected)}")

            # Bedöm server quality
            weak_servers = []
            if 'Apache' in detected and '2.2' in server:
                weak_servers.append("Gammal Apache-version")
            if 'PHP' in detected:
                php_version = headers.get('X-Powered-By', '')
                if any(old in php_version for old in ['5.', '7.0', '7.1', '7.2']):
                    weak_servers.append("Gammal PHP-version")

            if weak_servers:
                self.server_performance_issues.append(f"Föråldrad server-teknologi: {', '.join(weak_servers)}")
                return TestResult(
                    test_name="Server Technology",
                    passed=False,
                    details=f"⚠️ {' | '.join(detected_tech)} | Föråldrat: {', '.join(weak_servers)}",
                    severity="MEDIUM"
                )
            else:
                return TestResult(
                    test_name="Server Technology",
                    passed=True,
                    details=f"ℹ️ {' | '.join(detected_tech)}",
                    severity="INFO"
                )

        except Exception as e:
            return TestResult(
                test_name="Server Technology",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)[:100]}",
                severity="LOW"
            )

    def calculate_security_score(self) -> Tuple[int, str]:
        """Beräknar SEO crawlbarhet-poäng baserat på testresultat"""
        # Vikter baserat på hur kritiskt testet är för SEO
        weights = {
            'CRITICAL': 25,  # Kritiska SEO-problem
            'HIGH': 15,      # Viktiga problem
            'MEDIUM': 10,    # Medelviktiga problem
            'LOW': 5,        # Mindre problem
            'INFO': 10       # Informativa tester (bra om de passerar)
        }

        total_tests = len(self.results)
        if total_tests == 0:
            return 0, "🔴 INGEN DATA"

        # Räkna poäng: varje test som passerar ger poäng
        passed_tests = sum(1 for r in self.results if r.passed)
        failed_critical = sum(1 for r in self.results if not r.passed and r.severity == 'CRITICAL')
        failed_high = sum(1 for r in self.results if not r.passed and r.severity == 'HIGH')

        # Baspoäng: procent av passerade tester
        base_score = (passed_tests / total_tests) * 100

        # Avdrag för kritiska och höga fel
        penalty = (failed_critical * 15) + (failed_high * 8)
        score = max(0, int(base_score - penalty))

        if score >= 85:
            rating = "🟢 UTMÄRKT SEO CRAWLBARHET"
        elif score >= 65:
            rating = "🟡 BRA SEO CRAWLBARHET"
        elif score >= 40:
            rating = "🟠 MEDEL SEO CRAWLBARHET"
        else:
            rating = "🔴 DÅLIG SEO CRAWLBARHET"

        return score, rating

    def generate_recommendations(self) -> List[str]:
        """Genererar rekommendationer baserat på resultat"""
        recommendations = []

        # CONNECTION/KRITISKA PROBLEM FÖRST
        critical_connection_issues = [issue for issue in self.seo_issues if "nås inte alls" in issue or "DNS" in issue]
        if critical_connection_issues:
            recommendations.append("🚨 KRITISKA CONNECTION-PROBLEM (ÅTGÄRDA OMEDELBART):")
            for issue in critical_connection_issues:
                if "nås inte alls" in issue:
                    recommendations.append("  🔴 Servern kan inte nås - Googlebot kan INTE crawla sidan")
                    recommendations.append("     → Kontrollera att servern är uppe")
                    recommendations.append("     → Testa manuellt: curl -I [URL]")
                    recommendations.append("     → Kolla Google Search Console för crawl errors")
                elif "DNS" in issue:
                    recommendations.append("  🔴 DNS-problem - Domänen kan inte resolvas")
                    recommendations.append("     → Kontrollera DNS-inställningar hos domänleverantör")
            recommendations.append("")

        # Cloudflare-specifika problem
        cloudflare_issues = [issue for issue in self.seo_issues if "Cloudflare" in issue]
        if cloudflare_issues:
            recommendations.append("☁️ CLOUDFLARE BOT-BLOCKERING:")
            recommendations.append("  ⚠️ Cloudflare blockerar Python requests men tillåter curl")
            recommendations.append("     → Whitelist Googlebot i Cloudflare (Security > Bots)")
            recommendations.append("     → Sänk 'Bot Fight Mode' eller använd 'Super Bot Fight Mode' med exceptions")
            recommendations.append("     → Verifiera att 'Verified Bots' är allowade")
            recommendations.append("")

        # SEO-REKOMMENDATIONER
        if self.seo_issues:
            recommendations.append("🔍 SEO CRAWLBARHET-REKOMMENDATIONER:")
            recommendations.append("")
            for issue in self.seo_issues:
                if "blockerad" in issue.lower() or "BLOCKERAS" in issue:
                    recommendations.append(f"  🔴 {issue}")
                    recommendations.append("     → Justera WAF/bot-filter för att tillåta legitima SEO-botar")
                elif "sitemap" in issue.lower():
                    recommendations.append(f"  ⚠️ {issue}")
                    recommendations.append("     → Skapa sitemap.xml för bättre indexering")
                elif "cloaking" in issue.lower():
                    recommendations.append(f"  🔴 {issue}")
                    recommendations.append("     → Risk för Google-bestraffning! Visa samma content för alla")
                elif "mobile" in issue.lower():
                    recommendations.append(f"  🔴 {issue}")
                    recommendations.append("     → Kritiskt för Mobile-First Indexing")
                elif "redirect" in issue.lower():
                    recommendations.append(f"  ⚠️ {issue}")
                    recommendations.append("     → Korta ner redirect-kedjor till max 1-2 hopp")
                elif "robots.txt" in issue.lower():
                    recommendations.append(f"  🔴 {issue}")
                    recommendations.append("     → Uppdatera robots.txt för att tillåta viktiga crawlers")
                elif "CSS/JS" in issue or "resurser" in issue.lower():
                    recommendations.append(f"  ⚠️ {issue}")
                    recommendations.append("     → Se till att CSS/JS är tillgängligt för Googlebot")
                elif "throttl" in issue.lower() or "långsam" in issue.lower():
                    recommendations.append(f"  ⚠️ {issue}")
                    recommendations.append("     → Optimera server-respons för botar")
                else:
                    recommendations.append(f"  ⚠️ {issue}")
            recommendations.append("")
        else:
            recommendations.append("🔍 SEO CRAWLBARHET-REKOMMENDATIONER:")
            recommendations.append("  ✅ Inga SEO-problem detekterade! Sidan är väl optimerad för crawlers.")
            recommendations.append("")

        # SERVER PERFORMANCE-REKOMMENDATIONER
        if self.server_performance_issues:
            recommendations.append("⚡ SERVER PERFORMANCE (påverkar SEO):")
            recommendations.append("")
            for issue in self.server_performance_issues:
                if "TTFB" in issue and "KRITISKT" in issue:
                    recommendations.append(f"  🔴 {issue}")
                    recommendations.append("     → Optimera server-respons (caching, CDN, server-upgrade)")
                    recommendations.append("     → Använd Cloudflare eller annat CDN för att förbättra TTFB")
                elif "TTFB" in issue:
                    recommendations.append(f"  ⚠️ {issue}")
                    recommendations.append("     → Implementera caching (Redis, Memcached)")
                    recommendations.append("     → Optimera databas-queries")
                elif "långsam" in issue.lower():
                    recommendations.append(f"  🔴 {issue}")
                    recommendations.append("     → Uppgradera server-resurser (CPU, RAM)")
                    recommendations.append("     → Långsam server påverkar SEO rankings negativt")
                elif "klarar inte" in issue.lower():
                    recommendations.append(f"  🔴 {issue}")
                    recommendations.append("     → Server för svag - kan inte hantera Googlebot crawling")
                    recommendations.append("     → Uppgradera hosting-plan OMEDELBART")
                elif "inkonsekvent" in issue.lower():
                    recommendations.append(f"  ⚠️ {issue}")
                    recommendations.append("     → Instabil server kan skada user experience och SEO")
                else:
                    recommendations.append(f"  ⚠️ {issue}")

        if not self.seo_issues and not self.server_performance_issues:
            recommendations = ["✅ Utmärkt SEO crawlbarhet! Googlebot och andra sökmotorbotar kan nå sidan utan problem."]

        return recommendations
    
    def run_all_tests(self) -> BotProtectionReport:
        """Kör alla tester och genererar rapport"""
        self.print_header()
        
        # Test 0: Connectivity (måste fungera för övriga tester)
        connectivity = self.test_basic_connectivity()
        self.results.append(connectivity)

        if not connectivity.passed:
            self._log("\n❌ Kunde inte nå servern. Avbryter tester.\n", "")
            # Kör diagnostik även vid fel för att visa var problemet är
            self._log("Kör detaljerad server-diagnostik...", "🔬")
            diag = self._measure_server_diagnostics()
            self._update_server_diagnostics(diag)
            return self.generate_report()

        # Kör detaljerad server-diagnostik
        self._log("Kör detaljerad server-diagnostik...", "🔬")
        diag = self._measure_server_diagnostics()
        self._update_server_diagnostics(diag)

        time.sleep(1)
        
        # Kör alla SEO-tester med delays
        test_methods = [
            # SEO Bot Accessibility tester
            self.test_seo_bot_accessibility,
            self.test_robots_txt,
            self.test_sitemap_accessibility,
            self.test_cloaking_detection,
            self.test_ai_bot_accessibility,
            # Googlebot-specifika tester
            self.test_response_time_comparison,
            self.test_googlebot_stress_test,
            self.test_bot_differential_treatment,
            self.test_progressive_blocking,
            # Mobile-First & Resource tester
            self.test_mobile_vs_desktop_googlebot,
            self.test_blocked_resources,
            self.test_protocol_consistency,
            # Server Performance tester
            self.test_server_performance,
            self.test_server_load_handling,
            self.test_server_technology_detection
        ]
        
        for test_method in test_methods:
            try:
                result = test_method()
                self.results.append(result)
                time.sleep(1)  # Delay mellan tester
            except Exception as e:
                self._log(f"  ⚠️ Test misslyckades: {str(e)[:50]}", "")
        
        return self.generate_report()
    
    def generate_report(self) -> BotProtectionReport:
        """Genererar slutlig rapport"""
        score, rating = self.calculate_security_score()
        recommendations = self.generate_recommendations()
        
        passed = sum(1 for r in self.results if r.passed)
        failed = len(self.results) - passed
        
        report = BotProtectionReport(
            target_url=self.target_url,
            timestamp=datetime.now().isoformat(),
            total_score=score,
            rating=rating,
            tests_passed=passed,
            tests_failed=failed,
            protection_layers=list(self.protection_layers),
            vulnerabilities=self.vulnerabilities,
            seo_issues=self.seo_issues,
            recommendations=recommendations,
            test_results=[asdict(r) for r in self.results],
            bot_accessibility_details=self.bot_accessibility_details,
            server_performance_details=self.server_performance_details,
            server_diagnostics=self.server_diagnostics
        )
        
        return report
    
    def print_report(self, report: BotProtectionReport):
        """Skriver ut rapport"""
        print("\n" + "="*70)
        print("📋 RESULTAT")
        print("="*70 + "\n")
        
        for result in self.results:
            severity_emoji = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🟢',
                'INFO': 'ℹ️'
            }
            emoji = severity_emoji.get(result.severity, '📊')
            
            print(f"{emoji} {result.test_name}:")
            print(f"   {result.details}")
            if result.protection_type:
                print(f"   Type: {result.protection_type}")
            print()
        
        print("="*70)
        print(f"🎯 SEO CRAWLBARHET POÄNG: {report.total_score}/100")
        print(f"📊 BEDÖMNING: {report.rating}")
        print(f"✅ Godkända tester: {report.tests_passed}")
        print(f"❌ Misslyckade tester: {report.tests_failed}")
        print("="*70 + "\n")

        if self.seo_issues:
            print("🔍 IDENTIFIERADE SEO-PROBLEM:")
            for issue in self.seo_issues:
                print(f"   • {issue}")
            print()

        if self.server_performance_issues:
            print("⚡ IDENTIFIERADE SERVER PERFORMANCE-PROBLEM:")
            for issue in self.server_performance_issues:
                print(f"   • {issue}")
            if self.server_info:
                if 'avg_ttfb' in self.server_info:
                    print(f"   → TTFB: {self.server_info['avg_ttfb']:.3f}s")
                if 'avg_response_time' in self.server_info:
                    print(f"   → Avg Response Time: {self.server_info['avg_response_time']:.3f}s")
                if 'server' in self.server_info:
                    print(f"   → Server: {self.server_info['server']}")
            print()

        print("💡 REKOMMENDATIONER:")
        for rec in report.recommendations:
            print(f"   {rec}")
        
        print("\n" + "="*70 + "\n")
    
    def export_json(self, report: BotProtectionReport, filename: str = None):
        """Exporterar rapport till JSON"""
        if filename is None:
            domain = urlparse(self.target_url).netloc.replace('.', '_')
            filename = f"seo_crawlability_report_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(asdict(report), f, indent=2, ensure_ascii=False)
        
        return filename

def main():
    if len(sys.argv) < 2:
        print("Usage: python advanced_bot_tester.py <URL> [--pdf] [--json] [--quiet]")
        print("\nSEO Crawlability Tester - Testar hur väl sökmotorbotar kan crawla din sida")
        print("\nExempel:")
        print("  python advanced_bot_tester.py https://example.com")
        print("  python advanced_bot_tester.py example.com --pdf      # Generera PDF-rapport")
        print("  python advanced_bot_tester.py example.com --json     # Exportera JSON")
        print("  python advanced_bot_tester.py example.com --quiet    # Mindre output")
        print("\nTestar:")
        print("  • Googlebot/Bingbot tillgänglighet")
        print("  • Mobile vs Desktop Googlebot")
        print("  • robots.txt & sitemap.xml")
        print("  • Cloaking detection")
        print("  • CSS/JS resurs-blockering")
        print("  • HTTP/HTTPS redirects")
        print("  • Server performance (TTFB, SSL, komprimering)")
        print("\nFör säkerhetstester, använd: python security_bot_tester.py <URL>")
        sys.exit(1)

    url = sys.argv[1]
    export_json_flag = '--json' in sys.argv
    export_pdf = '--pdf' in sys.argv
    quiet = '--quiet' in sys.argv

    tester = AdvancedBotProtectionTester(url, verbose=not quiet)

    try:
        report = tester.run_all_tests()
        tester.print_report(report)

        if export_json_flag:
            filename = tester.export_json(report)
            print(f"📄 JSON-rapport exporterad: {filename}")

        if export_pdf:
            try:
                from pdf_report_generator import generate_pdf_report

                # Konvertera report till dict för PDF-generatorn
                report_dict = asdict(report)

                pdf_path = generate_pdf_report(report_dict)
                print(f"📄 PDF-rapport genererad: {pdf_path}")

            except ImportError as e:
                print(f"\n⚠️  Kunde inte importera pdf_report_generator: {e}")
                print("   Kontrollera att pdf_report_generator.py finns i samma mapp")

    except KeyboardInterrupt:
        print("\n\n⚠️ Test avbrutet av användaren")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Fel vid testning: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()