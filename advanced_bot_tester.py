#!/usr/bin/env python3
"""
Advanced Bot Protection Tester
Testar bot-skydd med mer sofistikerade metoder och bättre felhantering
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
                'Mozilla/5.0 (compatible; DotBot/1.2; +https://opensiteexplorer.org/dotbot)'
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
        print("🛡️  BOT PROTECTION & SEO CRAWLABILITY TESTER v4.0")
        print("="*70)
        print(f"Target: {self.target_url}")
        print(f"Tid: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Testar: Säkerhet + SEO + Server Bot-behandling + AI Botar")
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
    
    def test_aggressive_rate_limiting(self) -> TestResult:
        """Test 1: Aggressiv Rate Limiting"""
        self._log("Test 1: Aggressive Rate Limiting...", "📊")
        
        session = requests.Session()
        blocked = False
        requests_sent = 0
        max_requests = 50
        block_threshold = None
        
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
                        blocked = True
                        block_threshold = requests_sent
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
                    self._log("  Request timeout (möjligt rate limiting)", "⏱️")
                    continue
                except Exception as e:
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
        blocked_agents = []
        
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
                        blocked_agents.append(agent)
                except:
                    continue
                
                time.sleep(0.5)
            
            # Testa legitimt vs. suspekt
            legit_response = None
            try:
                legit_response = requests.get(
                    self.target_url,
                    headers={"User-Agent": self.user_agents['legitimate'][0]},
                    timeout=self.timeout,
                    verify=False
                )
            except:
                pass
            
            if blocked_count > 0:
                self.protection_layers.add("User-Agent Filtering")
                return TestResult(
                    test_name="User-Agent Filtering",
                    passed=True,
                    details=f"✅ Blockerar {blocked_count}/{total_tested} suspekta user agents",
                    severity="LOW"
                )
            else:
                self.vulnerabilities.append("Accepterar suspekta user agents")
                return TestResult(
                    test_name="User-Agent Filtering",
                    passed=False,
                    details=f"❌ Accepterar alla suspekta user agents ({total_tested} testade)",
                    severity="MEDIUM"
                )
                
        except Exception as e:
            return TestResult(
                test_name="User-Agent Filtering",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)[:100]}",
                severity="LOW"
            )
    
    def test_behavioral_analysis(self) -> TestResult:
        """Test 3: Beteendeanalys (Header fingerprinting & TLS)"""
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
                self.protection_layers.add("Content Fingerprinting")
                return TestResult(
                    test_name="Behavioral Analysis",
                    passed=True,
                    details=f"✅ Servern varierar content baserat på headers",
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
        """Test 5: Avancerad Fingerprinting (TLS, Headers, Timing)"""
        self._log("Test 5: Advanced Fingerprinting...", "🔬")
        
        try:
            # Test med olika header kombinationer
            test_scenarios = [
                {
                    'name': 'Proxy Headers',
                    'headers': {
                        'X-Forwarded-For': '192.168.1.1',
                        'X-Real-IP': '192.168.1.1',
                        'Via': '1.1 proxy.example.com'
                    }
                },
                {
                    'name': 'Tor Exit Node',
                    'headers': {
                        'X-Forwarded-For': '185.220.101.1'  # Known Tor exit
                    }
                },
                {
                    'name': 'Missing Accept Headers',
                    'headers': {
                        'User-Agent': self.user_agents['legitimate'][0]
                        # Saknar Accept, Accept-Language etc
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
                self.vulnerabilities.append("Ingen avancerad fingerprinting")
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
                '/wp-json/',
                '/rest/',
                '/.env',
                '/admin/',
                '/api/users',
                '/graphql'
            ]
            
            protected_endpoints = 0
            accessible_endpoints = []
            
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
                        
                except:
                    protected_endpoints += 1  # Timeout/error = skyddad
                
                time.sleep(0.3)
            
            if len(accessible_endpoints) == 0:
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

    def test_seo_bot_accessibility(self) -> TestResult:
        """Test 7: SEO Bot Accessibility - Kritiskt för SEO"""
        self._log("Test 7: SEO Bot Accessibility...", "🔍")

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

                    bot_name = bot_ua.split('/')[0].split('(compatible; ')[-1] if '(compatible;' in bot_ua else bot_ua.split('/')[0]

                    if response.status_code == 200:
                        accessible_bots.append(bot_name)
                    elif response.status_code in [403, 406, 503]:
                        blocked_bots.append(bot_name)
                        self.seo_issues.append(f"Sökmotorbot blockerad: {bot_name}")

                except:
                    continue

                time.sleep(0.5)

            # Test SEO-verktygsbotar
            for bot_ua in self.user_agents['seo_bots'][:3]:  # Testa de 3 viktigaste
                try:
                    response = requests.get(
                        self.target_url,
                        headers={'User-Agent': bot_ua},
                        timeout=self.timeout,
                        verify=False
                    )

                    bot_name = bot_ua.split('/')[0].split('(compatible; ')[-1] if '(compatible;' in bot_ua else bot_ua.split('/')[0]

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
                    test_name="SEO Bot Accessibility",
                    passed=True,
                    details=f"✅ Alla SEO-botar ({len(accessible_bots)}) kan nå sidan - BRA för SEO",
                    severity="INFO"
                )
            elif len(blocked_bots) <= 2:
                return TestResult(
                    test_name="SEO Bot Accessibility",
                    passed=False,
                    details=f"⚠️ Vissa SEO-botar blockerade: {', '.join(blocked_bots)}",
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
        """Test 8: Robots.txt Analysis"""
        self._log("Test 8: Robots.txt Analysis...", "🤖")

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
        """Test 9: Sitemap.xml Accessibility"""
        self._log("Test 9: Sitemap Accessibility...", "🗺️")

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
        """Test 10: Cloaking Detection - Bot vs User Content"""
        self._log("Test 10: Cloaking Detection...", "👁️")

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
        """Test 11: AI Bot Accessibility - GPTBot, Claude, etc."""
        self._log("Test 11: AI Bot Accessibility...", "🤖")

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
        """Test 12: Response Time Comparison - Bot vs User"""
        self._log("Test 12: Response Time Comparison (Bot Throttling)...", "⏱️")

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
        """Test 13: Googlebot Stress Test - Rate limiting för SEO-botar"""
        self._log("Test 13: Googlebot Stress Test (Rate Limiting)...", "🚨")

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
        """Test 14: SEO Bot Differential Treatment - Jämför bot vs user behandling"""
        self._log("Test 14: Bot Differential Treatment...", "⚖️")

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
        """Test 15: Progressive Blocking Detection - Blir botten gradvis blockerad"""
        self._log("Test 15: Progressive Blocking Detection...", "📉")

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

    def test_server_performance(self) -> TestResult:
        """Test 16: Server Performance Analysis - TTFB & Response Times"""
        self._log("Test 16: Server Performance Analysis...", "⚡")

        try:
            response_times = []
            ttfb_times = []

            # Gör 5 requests för att få genomsnittlig performance
            for i in range(5):
                try:
                    start = time.time()
                    response = requests.get(
                        self.target_url,
                        headers={'User-Agent': self.user_agents['legitimate'][0]},
                        timeout=self.timeout,
                        verify=False,
                        stream=True  # För att mäta TTFB
                    )

                    # Time To First Byte (TTFB)
                    ttfb = time.time() - start
                    ttfb_times.append(ttfb)

                    # Läs hela responsen
                    _ = response.content
                    total_time = time.time() - start
                    response_times.append(total_time)

                except Exception as e:
                    continue

                time.sleep(0.5)

            if not response_times:
                return TestResult(
                    test_name="Server Performance",
                    passed=False,
                    details="❌ Kunde inte mäta server performance",
                    severity="HIGH"
                )

            avg_ttfb = sum(ttfb_times) / len(ttfb_times)
            avg_response = sum(response_times) / len(response_times)
            max_response = max(response_times)
            min_response = min(response_times)

            # Spara server info
            self.server_info['avg_ttfb'] = avg_ttfb
            self.server_info['avg_response_time'] = avg_response
            self.server_info['response_time_variance'] = max_response - min_response

            # Bedöm performance
            issues = []

            # TTFB bedömning (Google rekommenderar <200ms, max 600ms)
            if avg_ttfb > 1.0:  # >1s
                issues.append(f"TTFB mycket långsam ({avg_ttfb:.2f}s)")
                self.server_performance_issues.append(f"TTFB {avg_ttfb:.2f}s - KRITISKT långsamt")
                severity = "CRITICAL"
            elif avg_ttfb > 0.6:  # >600ms
                issues.append(f"TTFB långsam ({avg_ttfb:.2f}s)")
                self.server_performance_issues.append(f"TTFB {avg_ttfb:.2f}s - Långsammare än Google's rekommendation")
                severity = "HIGH"
            elif avg_ttfb > 0.2:  # >200ms
                issues.append(f"TTFB acceptabel ({avg_ttfb:.2f}s)")
                severity = "MEDIUM"
            else:
                severity = "INFO"

            # Total response time bedömning
            if avg_response > 3.0:
                issues.append(f"Mycket långsam server ({avg_response:.2f}s)")
                self.server_performance_issues.append(f"Response time {avg_response:.2f}s - Mycket långsam")
                severity = "CRITICAL"
            elif avg_response > 2.0:
                issues.append(f"Långsam server ({avg_response:.2f}s)")
                severity = "HIGH"

            # Variabilitet
            variance = max_response - min_response
            if variance > 1.0:
                issues.append(f"Inkonsekvent performance (varierar {variance:.2f}s)")
                self.server_performance_issues.append("Server performance inkonsekvent")

            if not issues or severity == "INFO":
                return TestResult(
                    test_name="Server Performance",
                    passed=True,
                    details=f"✅ Bra server performance: TTFB {avg_ttfb:.2f}s, Avg {avg_response:.2f}s - BRA för SEO",
                    severity="INFO"
                )
            else:
                return TestResult(
                    test_name="Server Performance",
                    passed=False,
                    details=f"⚠️ Performance-problem: {'; '.join(issues)} - Påverkar SEO negativt",
                    severity=severity
                )

        except Exception as e:
            return TestResult(
                test_name="Server Performance",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)[:100]}",
                severity="MEDIUM"
            )

    def test_server_load_handling(self) -> TestResult:
        """Test 17: Server Load Handling - Klarar servern belastning?"""
        self._log("Test 17: Server Load Handling...", "💪")

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

            # Skicka 10 samtidiga requests
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(make_request) for _ in range(10)]
                results = [f.result() for f in concurrent.futures.as_completed(futures)]

            successful = [r for r in results if r['success']]
            failed = [r for r in results if not r['success']]

            if not successful:
                self.server_performance_issues.append("Server klarar inte concurrent requests")
                return TestResult(
                    test_name="Server Load Handling",
                    passed=False,
                    details=f"❌ Server klarar inte belastning: 0/{len(results)} requests lyckades - KRITISKT för SEO",
                    severity="CRITICAL"
                )

            avg_concurrent_time = sum(r['time'] for r in successful) / len(successful)
            success_rate = len(successful) / len(results) * 100

            # Jämför med baseline (om den finns)
            baseline = self.server_info.get('avg_response_time', 0)
            if baseline > 0:
                slowdown = (avg_concurrent_time / baseline - 1) * 100
            else:
                slowdown = 0

            if success_rate < 70:
                self.server_performance_issues.append(f"Svag server - endast {success_rate:.0f}% requests lyckades under load")
                return TestResult(
                    test_name="Server Load Handling",
                    passed=False,
                    details=f"❌ Svag server: {success_rate:.0f}% success rate, {len(failed)} failures - Server klarar inte normal crawl-belastning",
                    severity="CRITICAL"
                )
            elif slowdown > 100:  # >100% långsammare under load
                self.server_performance_issues.append(f"Server presterar {slowdown:.0f}% sämre under belastning")
                return TestResult(
                    test_name="Server Load Handling",
                    passed=False,
                    details=f"⚠️ Server långsam under load: {slowdown:.0f}% långsammare ({avg_concurrent_time:.2f}s vs {baseline:.2f}s baseline)",
                    severity="HIGH"
                )
            elif slowdown > 50:
                return TestResult(
                    test_name="Server Load Handling",
                    passed=False,
                    details=f"ℹ️ Server något långsammare under load: {slowdown:.0f}% långsammare",
                    severity="MEDIUM"
                )
            else:
                return TestResult(
                    test_name="Server Load Handling",
                    passed=True,
                    details=f"✅ Server klarar belastning bra: {success_rate:.0f}% success rate, {avg_concurrent_time:.2f}s avg - Kan hantera Googlebot crawling",
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
        """Test 18: Server Technology Detection"""
        self._log("Test 18: Server Technology Detection...", "🔧")

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
        """Beräknar säkerhetspoäng med viktning"""
        weights = {
            'CRITICAL': 0,
            'HIGH': 10,
            'MEDIUM': 15,
            'LOW': 20,
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
            rating = "🟢 STARKT BOT-SKYDD"
        elif score >= 65:
            rating = "🟡 MEDEL BOT-SKYDD"
        elif score >= 40:
            rating = "🟠 SVAGT BOT-SKYDD"
        else:
            rating = "🔴 MYCKET SVAGT BOT-SKYDD"
        
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
            recommendations.append("     → Testa: https://www.cloudflare.com/learning/bots/what-is-a-bot/")
            recommendations.append("")

        # SÄKERHETSREKOMMENDATIONER
        recommendations.append("🛡️ SÄKERHETSREKOMMENDATIONER:")

        if "Rate Limiting" not in self.protection_layers:
            recommendations.append("  ⚠️ Implementera rate limiting (Cloudflare, Nginx limit_req, AWS WAF)")

        if "User-Agent Filtering" not in self.protection_layers:
            recommendations.append("  ⚠️ Filtrera suspekta user agents (scrapers, bots, automation tools)")

        if "WAF: Cloudflare" not in self.protection_layers and "WAF: Akamai" not in self.protection_layers:
            recommendations.append("  ⚠️ Överväg ett CDN/WAF (Cloudflare, Akamai, AWS WAF)")

        if "JavaScript Challenge" not in self.protection_layers:
            recommendations.append("  💡 Aktivera JavaScript challenges för bot-verifiering")

        if "Behavioral Analysis" not in self.protection_layers:
            recommendations.append("  💡 Implementera behavioral analysis (fingerprinting, timing analysis)")

        if "Advanced Fingerprinting" not in self.protection_layers:
            recommendations.append("  💡 Blockera proxy/VPN headers och anonymiseringstjänster")

        # Lägg till specifika sårbarheter
        for vuln in self.vulnerabilities:
            if "API endpoints" in vuln:
                recommendations.append(f"  🔴 {vuln}")

        # SEO-REKOMMENDATIONER
        if self.seo_issues:
            recommendations.append("")
            recommendations.append("🔍 SEO-REKOMMENDATIONER:")
            for issue in self.seo_issues:
                if "blockerad" in issue.lower():
                    recommendations.append(f"  🔴 {issue} - Justera WAF/bot-filter för att tillåta legitima SEO-botar")
                elif "sitemap" in issue.lower():
                    recommendations.append(f"  ⚠️ {issue} - Skapa sitemap.xml för bättre indexering")
                elif "cloaking" in issue.lower():
                    recommendations.append(f"  🔴 {issue} - Risk för Google-bestraffning!")
                else:
                    recommendations.append(f"  ⚠️ {issue}")
        else:
            recommendations.append("")
            recommendations.append("🔍 SEO-REKOMMENDATIONER:")
            recommendations.append("  ✅ Inga SEO-problem detekterade!")

        # SERVER PERFORMANCE-REKOMMENDATIONER
        if self.server_performance_issues:
            recommendations.append("")
            recommendations.append("⚡ SERVER PERFORMANCE-REKOMMENDATIONER:")
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
                    recommendations.append("     → Byt till snabbare webbhotell")
                    recommendations.append("     → Långsam server påverkar SEO rankings negativt")
                elif "klarar inte" in issue.lower():
                    recommendations.append(f"  🔴 {issue}")
                    recommendations.append("     → Server för svag - kan inte hantera Googlebot crawling")
                    recommendations.append("     → Uppgradera hosting-plan OMEDELBART")
                elif "inkonsekvent" in issue.lower():
                    recommendations.append(f"  ⚠️ {issue}")
                    recommendations.append("     → Instabil server kan skada user experience och SEO")
                elif "föråldrad" in issue.lower():
                    recommendations.append(f"  ⚠️ {issue}")
                    recommendations.append("     → Uppdatera server-programvara för säkerhet och performance")
                else:
                    recommendations.append(f"  ⚠️ {issue}")

        if not self.vulnerabilities and not self.seo_issues:
            recommendations = ["✅ Utmärkt säkerhet och SEO-vänlighet! Fortsätt övervaka och uppdatera regelbundet."]

        return recommendations
    
    def run_all_tests(self) -> BotProtectionReport:
        """Kör alla tester och genererar rapport"""
        self.print_header()
        
        # Test 0: Connectivity (måste fungera för övriga tester)
        connectivity = self.test_basic_connectivity()
        self.results.append(connectivity)
        
        if not connectivity.passed:
            self._log("\n❌ Kunde inte nå servern. Avbryter tester.\n", "")
            return self.generate_report()
        
        time.sleep(1)
        
        # Kör alla tester med delays
        test_methods = [
            self.test_aggressive_rate_limiting,
            self.test_comprehensive_user_agent_filtering,
            self.test_behavioral_analysis,
            self.test_waf_and_challenge_detection,
            self.test_advanced_fingerprinting,
            self.test_api_endpoint_protection,
            # SEO-tester
            self.test_seo_bot_accessibility,
            self.test_robots_txt,
            self.test_sitemap_accessibility,
            self.test_cloaking_detection,
            # AI Bot & Server Bot-skydd tester
            self.test_ai_bot_accessibility,
            self.test_response_time_comparison,
            self.test_googlebot_stress_test,
            self.test_bot_differential_treatment,
            self.test_progressive_blocking,
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
            test_results=[asdict(r) for r in self.results]
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
            filename = f"bot_protection_report_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(asdict(report), f, indent=2, ensure_ascii=False)
        
        return filename

def main():
    if len(sys.argv) < 2:
        print("Usage: python advanced_bot_tester.py <URL> [--json] [--quiet]")
        print("\nExempel:")
        print("  python advanced_bot_tester.py https://example.com")
        print("  python advanced_bot_tester.py example.com --json")
        print("  python advanced_bot_tester.py example.com --quiet")
        sys.exit(1)
    
    url = sys.argv[1]
    export_json = '--json' in sys.argv
    quiet = '--quiet' in sys.argv
    
    tester = AdvancedBotProtectionTester(url, verbose=not quiet)
    
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