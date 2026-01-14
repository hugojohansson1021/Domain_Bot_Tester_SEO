#!/usr/bin/env python3
"""
Security Bot Protection Tester
Testar bot-skydd och säkerhet - Rate limiting, WAF, Fingerprinting, etc.
"""

import requests
import time
import json
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
class SecurityReport:
    """Komplett rapport över säkerhet och bot-skydd"""
    target_url: str
    timestamp: str
    total_score: int
    rating: str
    tests_passed: int
    tests_failed: int
    protection_layers: List[str]
    vulnerabilities: List[str]
    recommendations: List[str]
    test_results: List[Dict]

class SecurityBotTester:
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
            'malicious': [
                'sqlmap/1.0',
                'nikto/2.1.6',
                'masscan/1.0',
                'nmap scripting engine',
                'dirbuster'
            ]
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

    def print_header(self):
        """Skriver ut header"""
        print("\n" + "="*70)
        print("🛡️  SECURITY BOT PROTECTION TESTER v1.0")
        print("="*70)
        print(f"Target: {self.target_url}")
        print(f"Tid: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Testar: Rate Limiting, WAF, Fingerprinting, API-skydd")
        print(f"Antal tester: 7")
        print("="*70 + "\n")

    def test_basic_connectivity(self) -> TestResult:
        """Test 0: Grundläggande connectivity"""
        self._log("Test 0: Basic Connectivity...", "🔌")

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
            return TestResult(
                test_name="Basic Connectivity",
                passed=False,
                details=f"❌ Timeout ({self.timeout}s) - Server svarar inte",
                severity="CRITICAL"
            )
        except requests.exceptions.ConnectionError as e:
            return TestResult(
                test_name="Basic Connectivity",
                passed=False,
                details=f"❌ Connection error: {str(e)[:50]}",
                severity="CRITICAL"
            )
        except Exception as e:
            return TestResult(
                test_name="Basic Connectivity",
                passed=False,
                details=f"❌ Fel: {str(e)[:50]}",
                severity="CRITICAL"
            )

    def test_aggressive_rate_limiting(self) -> TestResult:
        """Test 1: Aggressiv Rate Limiting"""
        self._log("Test 1: Aggressive Rate Limiting...", "📊")

        session = requests.Session()
        requests_sent = 0
        max_requests = 50

        try:
            for i in range(max_requests):
                try:
                    response = session.get(
                        self.target_url,
                        timeout=self.timeout,
                        verify=False,
                        headers={'User-Agent': self.user_agents['legitimate'][0]}
                    )
                    requests_sent += 1

                    # Kolla efter olika typer av blockering
                    if response.status_code in [429, 403, 503]:
                        self.protection_layers.add("Rate Limiting")

                        # Identifiera typ av rate limiting
                        if 'cloudflare' in response.text.lower():
                            protection_type = "Cloudflare Rate Limiting"
                        elif 'nginx' in response.headers.get('Server', '').lower():
                            protection_type = "Nginx Rate Limiting"
                        else:
                            protection_type = "Generic Rate Limiting"

                        return TestResult(
                            test_name="Aggressive Rate Limiting",
                            passed=True,
                            details=f"✅ Rate limiting aktivt efter {requests_sent} requests (HTTP {response.status_code})",
                            response_code=response.status_code,
                            protection_type=protection_type,
                            severity="LOW"
                        )

                    time.sleep(0.05)  # Mycket kort delay

                except requests.exceptions.Timeout:
                    continue
                except Exception:
                    continue

            self.vulnerabilities.append("Ingen rate limiting detekterad")
            return TestResult(
                test_name="Aggressive Rate Limiting",
                passed=False,
                details=f"❌ Ingen rate limiting efter {requests_sent} requests",
                response_code=200,
                severity="HIGH"
            )

        except Exception as e:
            return TestResult(
                test_name="Aggressive Rate Limiting",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)[:100]}",
                severity="MEDIUM"
            )

    def test_comprehensive_user_agent_filtering(self) -> TestResult:
        """Test 2: Omfattande User-Agent filtrering"""
        self._log("Test 2: User-Agent Filtering...", "🤖")

        blocked_count = 0
        total_tested = 0

        try:
            # Testa suspekta agents
            for agent in self.user_agents['suspicious']:
                total_tested += 1
                try:
                    response = requests.get(
                        self.target_url,
                        headers={"User-Agent": agent},
                        timeout=self.timeout,
                        verify=False
                    )

                    if response.status_code in [403, 406, 429]:
                        blocked_count += 1
                except:
                    continue

                time.sleep(0.5)

            # Testa malicious agents
            for agent in self.user_agents['malicious']:
                total_tested += 1
                try:
                    response = requests.get(
                        self.target_url,
                        headers={"User-Agent": agent},
                        timeout=self.timeout,
                        verify=False
                    )

                    if response.status_code in [403, 406, 429]:
                        blocked_count += 1
                except:
                    continue

                time.sleep(0.5)

            if blocked_count > 0:
                self.protection_layers.add("User-Agent Filtering")
                return TestResult(
                    test_name="User-Agent Filtering",
                    passed=True,
                    details=f"✅ Blockerar {blocked_count}/{total_tested} suspekta/malicious user agents",
                    severity="LOW"
                )
            else:
                self.vulnerabilities.append("Accepterar suspekta och malicious user agents")
                return TestResult(
                    test_name="User-Agent Filtering",
                    passed=False,
                    details=f"❌ Accepterar alla suspekta user agents ({total_tested} testade)",
                    severity="HIGH"
                )

        except Exception as e:
            return TestResult(
                test_name="User-Agent Filtering",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)[:100]}",
                severity="LOW"
            )

    def test_behavioral_analysis(self) -> TestResult:
        """Test 3: Beteendeanalys (Header fingerprinting)"""
        self._log("Test 3: Behavioral Analysis...", "🔍")

        try:
            # Test 1: Minimala headers (bot-like)
            minimal_headers = {
                "User-Agent": "Mozilla/5.0"
            }

            # Test 2: Kompletta browser headers (human-like)
            full_headers = {
                "User-Agent": self.user_agents['legitimate'][0],
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "Accept-Language": "sv-SE,sv;q=0.9,en-US;q=0.8,en;q=0.7",
                "Accept-Encoding": "gzip, deflate, br",
                "DNT": "1",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Cache-Control": "max-age=0"
            }

            minimal_response = requests.get(
                self.target_url,
                headers=minimal_headers,
                timeout=self.timeout,
                verify=False
            )

            time.sleep(1)

            full_response = requests.get(
                self.target_url,
                headers=full_headers,
                timeout=self.timeout,
                verify=False
            )

            # Analysera skillnader
            if minimal_response.status_code != full_response.status_code:
                self.protection_layers.add("Behavioral Analysis")
                return TestResult(
                    test_name="Behavioral Analysis",
                    passed=True,
                    details=f"✅ Servern analyserar request headers (minimala: {minimal_response.status_code}, full: {full_response.status_code})",
                    severity="LOW"
                )

            # Kolla response content skillnader
            if len(minimal_response.content) != len(full_response.content):
                diff_percent = abs(len(minimal_response.content) - len(full_response.content)) / max(len(full_response.content), 1) * 100
                if diff_percent > 5:
                    self.protection_layers.add("Content Fingerprinting")
                    return TestResult(
                        test_name="Behavioral Analysis",
                        passed=True,
                        details=f"✅ Servern varierar content baserat på headers ({diff_percent:.1f}% skillnad)",
                        severity="LOW"
                    )

            self.vulnerabilities.append("Ingen beteendeanalys detekterad")
            return TestResult(
                test_name="Behavioral Analysis",
                passed=False,
                details="❌ Servern analyserar inte request beteende",
                severity="MEDIUM"
            )

        except Exception as e:
            return TestResult(
                test_name="Behavioral Analysis",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)[:100]}",
                severity="LOW"
            )

    def test_waf_and_challenge_detection(self) -> TestResult:
        """Test 4: WAF & Challenge Detection"""
        self._log("Test 4: WAF & Challenge Detection...", "⚡")

        try:
            response = requests.get(
                self.target_url,
                timeout=self.timeout,
                verify=False,
                headers={'User-Agent': self.user_agents['legitimate'][0]}
            )

            content = response.text.lower()
            headers = {k.lower(): v.lower() for k, v in response.headers.items()}

            # Detektera olika WAF/CDN providers
            waf_indicators = {
                'Cloudflare': ['cloudflare', 'cf-ray', '__cfduid', 'checking your browser'],
                'Akamai': ['akamai', 'akamaighost'],
                'Imperva': ['imperva', 'incapsula', 'visid_incap'],
                'AWS WAF': ['x-amzn-requestid', 'x-amz-cf'],
                'Sucuri': ['sucuri', 'x-sucuri'],
                'Wordfence': ['wordfence'],
                'ModSecurity': ['mod_security', 'modsecurity'],
                'BIG-IP ASM': ['bigipserver', 'f5'],
                'Barracuda': ['barracuda', 'barra_counter_session']
            }

            detected_wafs = []

            for waf_name, indicators in waf_indicators.items():
                for indicator in indicators:
                    if indicator in content or indicator in str(headers):
                        detected_wafs.append(waf_name)
                        self.protection_layers.add(f"WAF: {waf_name}")
                        break

            # Kolla efter challenges
            challenge_indicators = [
                'just a moment',
                'checking your browser',
                'ddos protection',
                'captcha',
                'recaptcha',
                'hcaptcha',
                'please wait',
                'verifying you are human'
            ]

            has_challenge = any(ind in content for ind in challenge_indicators)

            if detected_wafs or has_challenge:
                details = []
                if detected_wafs:
                    details.append(f"WAF: {', '.join(detected_wafs)}")
                if has_challenge:
                    details.append("JavaScript Challenge aktiv")
                    self.protection_layers.add("JavaScript Challenge")

                return TestResult(
                    test_name="WAF & Challenge Detection",
                    passed=True,
                    details=f"✅ {' | '.join(details)}",
                    protection_type=detected_wafs[0] if detected_wafs else "Generic",
                    severity="LOW"
                )
            else:
                self.vulnerabilities.append("Ingen WAF eller challenge detekterad")
                return TestResult(
                    test_name="WAF & Challenge Detection",
                    passed=False,
                    details="❌ Ingen WAF eller JS challenge detekterad",
                    severity="HIGH"
                )

        except Exception as e:
            return TestResult(
                test_name="WAF & Challenge Detection",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)[:100]}",
                severity="MEDIUM"
            )

    def test_advanced_fingerprinting(self) -> TestResult:
        """Test 5: Avancerad Fingerprinting (Proxy, Tor, Headers)"""
        self._log("Test 5: Advanced Fingerprinting...", "🔬")

        try:
            # Test med olika header kombinationer
            test_scenarios = [
                {
                    'name': 'Proxy Headers',
                    'headers': {
                        'User-Agent': self.user_agents['legitimate'][0],
                        'X-Forwarded-For': '192.168.1.1',
                        'X-Real-IP': '192.168.1.1',
                        'Via': '1.1 proxy.example.com'
                    }
                },
                {
                    'name': 'Tor Exit Node',
                    'headers': {
                        'User-Agent': self.user_agents['legitimate'][0],
                        'X-Forwarded-For': '185.220.101.1'  # Known Tor exit
                    }
                },
                {
                    'name': 'Missing Accept Headers',
                    'headers': {
                        'User-Agent': self.user_agents['legitimate'][0]
                        # Saknar Accept, Accept-Language etc
                    }
                },
                {
                    'name': 'Suspicious Referer',
                    'headers': {
                        'User-Agent': self.user_agents['legitimate'][0],
                        'Referer': 'https://evil-site.com/attack'
                    }
                }
            ]

            blocked_scenarios = []

            for scenario in test_scenarios:
                try:
                    response = requests.get(
                        self.target_url,
                        headers=scenario['headers'],
                        timeout=self.timeout,
                        verify=False
                    )

                    if response.status_code in [403, 406, 503]:
                        blocked_scenarios.append(scenario['name'])

                except:
                    continue

                time.sleep(0.5)

            if blocked_scenarios:
                self.protection_layers.add("Advanced Fingerprinting")
                return TestResult(
                    test_name="Advanced Fingerprinting",
                    passed=True,
                    details=f"✅ Blockerar: {', '.join(blocked_scenarios)}",
                    severity="LOW"
                )
            else:
                self.vulnerabilities.append("Ingen avancerad fingerprinting - accepterar proxy/Tor headers")
                return TestResult(
                    test_name="Advanced Fingerprinting",
                    passed=False,
                    details="❌ Accepterar proxy/anonymiserings-headers",
                    severity="MEDIUM"
                )

        except Exception as e:
            return TestResult(
                test_name="Advanced Fingerprinting",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)[:100]}",
                severity="LOW"
            )

    def test_api_endpoint_protection(self) -> TestResult:
        """Test 6: API Endpoint Protection"""
        self._log("Test 6: API Endpoint Protection...", "🔧")

        try:
            parsed = urlparse(self.target_url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"

            # Vanliga API endpoints att testa
            api_paths = [
                '/api/',
                '/api/v1/',
                '/api/v2/',
                '/wp-json/',
                '/rest/',
                '/.env',
                '/.git/config',
                '/admin/',
                '/administrator/',
                '/api/users',
                '/api/config',
                '/graphql',
                '/debug',
                '/phpinfo.php',
                '/server-status'
            ]

            protected_endpoints = 0
            accessible_endpoints = []
            sensitive_exposed = []

            for path in api_paths:
                try:
                    url = base_url + path
                    response = requests.get(
                        url,
                        timeout=self.timeout,
                        verify=False,
                        headers={'User-Agent': self.user_agents['suspicious'][0]}
                    )

                    if response.status_code in [401, 403, 404]:
                        protected_endpoints += 1
                    elif response.status_code == 200:
                        accessible_endpoints.append(path)
                        # Markera extra känsliga
                        if path in ['/.env', '/.git/config', '/debug', '/phpinfo.php', '/server-status']:
                            sensitive_exposed.append(path)

                except:
                    protected_endpoints += 1  # Timeout/error = skyddad

                time.sleep(0.3)

            if sensitive_exposed:
                self.vulnerabilities.append(f"KRITISKT: Känsliga filer exponerade: {', '.join(sensitive_exposed)}")
                return TestResult(
                    test_name="API Endpoint Protection",
                    passed=False,
                    details=f"❌ KRITISKT: Känsliga endpoints exponerade: {', '.join(sensitive_exposed)}",
                    severity="CRITICAL"
                )
            elif len(accessible_endpoints) == 0:
                self.protection_layers.add("API Protection")
                return TestResult(
                    test_name="API Endpoint Protection",
                    passed=True,
                    details=f"✅ Alla testade endpoints är skyddade ({protected_endpoints}/{len(api_paths)})",
                    severity="LOW"
                )
            else:
                self.vulnerabilities.append(f"Öppna API endpoints: {', '.join(accessible_endpoints)}")
                return TestResult(
                    test_name="API Endpoint Protection",
                    passed=False,
                    details=f"⚠️ {len(accessible_endpoints)} öppna endpoints: {', '.join(accessible_endpoints[:3])}",
                    severity="MEDIUM"
                )

        except Exception as e:
            return TestResult(
                test_name="API Endpoint Protection",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)[:100]}",
                severity="LOW"
            )

    def calculate_security_score(self) -> Tuple[int, str]:
        """Beräknar säkerhetspoäng med viktning"""
        weights = {
            'CRITICAL': 0,
            'HIGH': 15,
            'MEDIUM': 20,
            'LOW': 25,
            'INFO': 0
        }

        max_score = 0
        actual_score = 0

        for result in self.results:
            weight = weights.get(result.severity, 15)
            max_score += weight
            if result.passed:
                actual_score += weight

        if max_score == 0:
            return 0, "🔴 INGEN DATA"

        score = int((actual_score / max_score) * 100)

        if score >= 85:
            rating = "🟢 STARKT SÄKERHETSSKYDD"
        elif score >= 65:
            rating = "🟡 MEDEL SÄKERHETSSKYDD"
        elif score >= 40:
            rating = "🟠 SVAGT SÄKERHETSSKYDD"
        else:
            rating = "🔴 MYCKET SVAGT SÄKERHETSSKYDD"

        return score, rating

    def generate_recommendations(self) -> List[str]:
        """Genererar rekommendationer baserat på resultat"""
        recommendations = []

        recommendations.append("🛡️ SÄKERHETSREKOMMENDATIONER:")
        recommendations.append("")

        if "Rate Limiting" not in self.protection_layers:
            recommendations.append("  🔴 KRITISKT: Implementera rate limiting")
            recommendations.append("     → Cloudflare (gratis): Rate Limiting Rules")
            recommendations.append("     → Nginx: limit_req_zone och limit_req")
            recommendations.append("     → Apache: mod_ratelimit eller mod_evasive")
            recommendations.append("")

        if "User-Agent Filtering" not in self.protection_layers:
            recommendations.append("  🔴 Filtrera suspekta user agents")
            recommendations.append("     → Blockera: python-requests, curl, wget, scrapy")
            recommendations.append("     → Blockera: sqlmap, nikto, nmap, dirbuster")
            recommendations.append("")

        if not any("WAF" in layer for layer in self.protection_layers):
            recommendations.append("  🟠 Överväg ett WAF (Web Application Firewall)")
            recommendations.append("     → Cloudflare WAF (gratis grundplan)")
            recommendations.append("     → AWS WAF")
            recommendations.append("     → ModSecurity (open source)")
            recommendations.append("")

        if "JavaScript Challenge" not in self.protection_layers:
            recommendations.append("  🟡 Aktivera JavaScript challenges")
            recommendations.append("     → Cloudflare: Under Attack Mode eller Bot Fight Mode")
            recommendations.append("     → Stoppar enkla script-baserade attacker")
            recommendations.append("")

        if "Advanced Fingerprinting" not in self.protection_layers:
            recommendations.append("  🟡 Implementera header fingerprinting")
            recommendations.append("     → Blockera requests med proxy headers (X-Forwarded-For)")
            recommendations.append("     → Kräv standard browser headers")
            recommendations.append("")

        if "API Protection" not in self.protection_layers:
            recommendations.append("  🟠 Skydda API endpoints")
            recommendations.append("     → Kräv autentisering för /api/ endpoints")
            recommendations.append("     → Blockera åtkomst till /.env, /.git, /debug")
            recommendations.append("     → Returnera 404 istället för 403 (information disclosure)")
            recommendations.append("")

        # Lägg till specifika sårbarheter
        for vuln in self.vulnerabilities:
            if "KRITISKT" in vuln:
                recommendations.append(f"  🚨 {vuln}")
                recommendations.append("")

        if not self.vulnerabilities:
            recommendations = ["✅ Utmärkt säkerhet! Fortsätt övervaka och uppdatera regelbundet."]

        return recommendations

    def run_all_tests(self) -> SecurityReport:
        """Kör alla tester och genererar rapport"""
        self.print_header()

        # Test 0: Connectivity (måste fungera för övriga tester)
        connectivity = self.test_basic_connectivity()
        self.results.append(connectivity)

        if not connectivity.passed:
            self._log("\n❌ Kunde inte nå servern. Avbryter tester.\n", "")
            return self.generate_report()

        time.sleep(1)

        # Kör alla säkerhetstester
        test_methods = [
            self.test_aggressive_rate_limiting,
            self.test_comprehensive_user_agent_filtering,
            self.test_behavioral_analysis,
            self.test_waf_and_challenge_detection,
            self.test_advanced_fingerprinting,
            self.test_api_endpoint_protection
        ]

        for test_method in test_methods:
            try:
                result = test_method()
                self.results.append(result)
                time.sleep(1)  # Delay mellan tester
            except Exception as e:
                self._log(f"  ⚠️ Test misslyckades: {str(e)[:50]}", "")

        return self.generate_report()

    def generate_report(self) -> SecurityReport:
        """Genererar slutlig rapport"""
        score, rating = self.calculate_security_score()
        recommendations = self.generate_recommendations()

        passed = sum(1 for r in self.results if r.passed)
        failed = len(self.results) - passed

        report = SecurityReport(
            target_url=self.target_url,
            timestamp=datetime.now().isoformat(),
            total_score=score,
            rating=rating,
            tests_passed=passed,
            tests_failed=failed,
            protection_layers=list(self.protection_layers),
            vulnerabilities=self.vulnerabilities,
            recommendations=recommendations,
            test_results=[asdict(r) for r in self.results]
        )

        return report

    def print_report(self, report: SecurityReport):
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
        print(f"🎯 SÄKERHETSPOÄNG: {report.total_score}/100")
        print(f"📊 BEDÖMNING: {report.rating}")
        print(f"✅ Godkända tester: {report.tests_passed}")
        print(f"❌ Misslyckade tester: {report.tests_failed}")
        print("="*70 + "\n")

        if report.protection_layers:
            print("🛡️  DETEKTERADE SKYDDSLAGER:")
            for layer in report.protection_layers:
                print(f"   • {layer}")
            print()

        if report.vulnerabilities:
            print("⚠️  IDENTIFIERADE SÄKERHETSSÅRBARHETER:")
            for vuln in report.vulnerabilities:
                print(f"   • {vuln}")
            print()

        print("💡 REKOMMENDATIONER:")
        for rec in report.recommendations:
            print(f"   {rec}")

        print("\n" + "="*70 + "\n")

    def export_json(self, report: SecurityReport, filename: str = None):
        """Exporterar rapport till JSON"""
        if filename is None:
            domain = urlparse(self.target_url).netloc.replace('.', '_')
            filename = f"security_report_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(asdict(report), f, indent=2, ensure_ascii=False)

        return filename

def main():
    if len(sys.argv) < 2:
        print("Usage: python security_bot_tester.py <URL> [--json] [--quiet]")
        print("\nExempel:")
        print("  python security_bot_tester.py https://example.com")
        print("  python security_bot_tester.py example.com --json")
        print("  python security_bot_tester.py example.com --quiet")
        print("\nTestar:")
        print("  • Rate Limiting")
        print("  • User-Agent Filtering")
        print("  • Behavioral Analysis")
        print("  • WAF & Challenge Detection")
        print("  • Advanced Fingerprinting")
        print("  • API Endpoint Protection")
        sys.exit(1)

    url = sys.argv[1]
    export_json = '--json' in sys.argv
    quiet = '--quiet' in sys.argv

    tester = SecurityBotTester(url, verbose=not quiet)

    try:
        report = tester.run_all_tests()
        tester.print_report(report)

        if export_json:
            filename = tester.export_json(report)
            print(f"📄 Rapport exporterad till: {filename}")

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
