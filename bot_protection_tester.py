#!/usr/bin/env python3
"""
Bot Protection Tester
Testar en servers bot-skydd genom att simulera olika attack-mönster
"""

import requests
import time
import json
from typing import Dict, List, Tuple
from dataclasses import dataclass
from datetime import datetime
import sys
from pathlib import Path

@dataclass
class TestResult:
    """Resultat från ett test"""
    test_name: str
    passed: bool
    details: str
    response_code: int = None
    response_time: float = None

@dataclass
class DomainAuditResult:
    """Resultat från audit av en domän"""
    domain: str
    score: int
    rating: str
    test_results: List[TestResult]
    failed_tests: List[str]
    timestamp: str

class BotProtectionTester:
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.results: List[TestResult] = []
        self.session = requests.Session()
        
    def print_header(self):
        """Skriver ut header"""
        print("\n" + "="*60)
        print("🛡️  BOT PROTECTION TESTER")
        print("="*60)
        print(f"Target: {self.target_url}")
        print(f"Tid: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60 + "\n")
    
    def test_rate_limiting(self) -> TestResult:
        """Test 1: Rate Limiting - Skickar många requests snabbt"""
        print("📊 Test 1: Rate Limiting...")
        
        blocked = False
        requests_sent = 0
        max_requests = 30
        
        try:
            for i in range(max_requests):
                response = self.session.get(self.target_url, timeout=5)
                requests_sent += 1
                
                # Kolla om vi blir blockade
                if response.status_code in [429, 403, 503]:
                    blocked = True
                    return TestResult(
                        test_name="Rate Limiting",
                        passed=True,
                        details=f"✅ Blockad efter {requests_sent} requests (HTTP {response.status_code})",
                        response_code=response.status_code
                    )
                
                time.sleep(0.1)  # Kort delay mellan requests
            
            return TestResult(
                test_name="Rate Limiting",
                passed=False,
                details=f"❌ Ingen rate limiting detekterad efter {requests_sent} requests",
                response_code=200
            )
            
        except Exception as e:
            return TestResult(
                test_name="Rate Limiting",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)}"
            )
    
    def test_user_agent_blocking(self) -> TestResult:
        """Test 2: User-Agent blocking - Testar suspekta user agents"""
        print("🤖 Test 2: User-Agent Blocking...")
        
        suspicious_agents = [
            "python-requests",
            "curl/7.68.0",
            "bot",
            "crawler",
            "scraper"
        ]
        
        blocked_count = 0
        
        try:
            for agent in suspicious_agents:
                response = requests.get(
                    self.target_url,
                    headers={"User-Agent": agent},
                    timeout=5
                )
                
                if response.status_code in [403, 406]:
                    blocked_count += 1
            
            if blocked_count > 0:
                return TestResult(
                    test_name="User-Agent Blocking",
                    passed=True,
                    details=f"✅ Blockerar {blocked_count}/{len(suspicious_agents)} suspekta user agents"
                )
            else:
                return TestResult(
                    test_name="User-Agent Blocking",
                    passed=False,
                    details=f"❌ Accepterar alla suspekta user agents"
                )
                
        except Exception as e:
            return TestResult(
                test_name="User-Agent Blocking",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)}"
            )
    
    def test_header_fingerprinting(self) -> TestResult:
        """Test 3: Header Fingerprinting - Kollar om servern analyserar headers"""
        print("🔍 Test 3: Header Fingerprinting...")
        
        try:
            # Request utan vanliga browser headers
            minimal_response = requests.get(
                self.target_url,
                headers={
                    "User-Agent": "Mozilla/5.0"
                },
                timeout=5
            )
            
            # Request med kompletta browser headers
            full_headers = {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none"
            }
            
            full_response = requests.get(
                self.target_url,
                headers=full_headers,
                timeout=5
            )
            
            # Om olika statuskoder, analyserar servern headers
            if minimal_response.status_code != full_response.status_code:
                return TestResult(
                    test_name="Header Fingerprinting",
                    passed=True,
                    details=f"✅ Servern analyserar request headers (olika svar: {minimal_response.status_code} vs {full_response.status_code})"
                )
            else:
                return TestResult(
                    test_name="Header Fingerprinting",
                    passed=False,
                    details="❌ Servern verkar inte analysera request headers"
                )
                
        except Exception as e:
            return TestResult(
                test_name="Header Fingerprinting",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)}"
            )
    
    def test_javascript_challenge(self) -> TestResult:
        """Test 4: JavaScript Challenge - Kollar efter Cloudflare/WAF challenges"""
        print("⚡ Test 4: JavaScript Challenge Detection...")
        
        try:
            response = requests.get(self.target_url, timeout=5)
            content = response.text.lower()
            
            # Kolla efter tecken på JS challenges
            challenge_indicators = [
                "cloudflare",
                "challenge",
                "just a moment",
                "checking your browser",
                "ddos protection",
                "ray id",
                "captcha"
            ]
            
            found_indicators = [ind for ind in challenge_indicators if ind in content]
            
            if found_indicators:
                return TestResult(
                    test_name="JavaScript Challenge",
                    passed=True,
                    details=f"✅ JS Challenge detekterad: {', '.join(found_indicators)}"
                )
            else:
                return TestResult(
                    test_name="JavaScript Challenge",
                    passed=False,
                    details="❌ Ingen JS Challenge detekterad"
                )
                
        except Exception as e:
            return TestResult(
                test_name="JavaScript Challenge",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)}"
            )
    
    def test_ip_reputation(self) -> TestResult:
        """Test 5: IP Reputation - Testar om IP blockeras"""
        print("🌐 Test 5: IP Reputation Check...")
        
        try:
            # Försök med olika headers som VPN/Proxy använder
            proxy_headers = {
                "X-Forwarded-For": "1.1.1.1",
                "X-Real-IP": "1.1.1.1",
                "Via": "1.1 proxy"
            }
            
            response = requests.get(
                self.target_url,
                headers=proxy_headers,
                timeout=5
            )
            
            if response.status_code in [403, 503]:
                return TestResult(
                    test_name="IP Reputation",
                    passed=True,
                    details=f"✅ Blockerar proxy/VPN headers (HTTP {response.status_code})"
                )
            else:
                return TestResult(
                    test_name="IP Reputation",
                    passed=False,
                    details="❌ Accepterar proxy/VPN headers"
                )
                
        except Exception as e:
            return TestResult(
                test_name="IP Reputation",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)}"
            )
    
    def test_automated_tools_detection(self) -> TestResult:
        """Test 6: Automated Tools Detection"""
        print("🔧 Test 6: Automated Tools Detection...")
        
        tool_signatures = [
            {"Referer": "https://example.com/admin"},
            {"X-Requested-With": "XMLHttpRequest"},
            {"Accept": "*/*"}
        ]
        
        blocked = 0
        
        try:
            for headers in tool_signatures:
                response = requests.get(
                    self.target_url,
                    headers=headers,
                    timeout=5
                )
                
                if response.status_code in [403, 406]:
                    blocked += 1
            
            if blocked > 0:
                return TestResult(
                    test_name="Automated Tools Detection",
                    passed=True,
                    details=f"✅ Blockerar {blocked}/{len(tool_signatures)} automatiserade verktyg"
                )
            else:
                return TestResult(
                    test_name="Automated Tools Detection",
                    passed=False,
                    details="❌ Blockerar inga automatiserade verktyg"
                )
                
        except Exception as e:
            return TestResult(
                test_name="Automated Tools Detection",
                passed=False,
                details=f"⚠️ Fel vid test: {str(e)}"
            )
    
    def calculate_security_score(self) -> Tuple[int, str]:
        """Beräknar säkerhetspoäng baserat på testen"""
        passed_tests = sum(1 for r in self.results if r.passed)
        total_tests = len(self.results)

        score = int((passed_tests / total_tests) * 100)

        if score >= 80:
            rating = "🟢 STARKT BOT-SKYDD"
        elif score >= 50:
            rating = "🟡 MEDEL BOT-SKYDD"
        else:
            rating = "🔴 SVAGT BOT-SKYDD"

        return score, rating

    def get_audit_result(self) -> DomainAuditResult:
        """Returnerar audit-resultat för domänen"""
        score, rating = self.calculate_security_score()
        failed_tests = [r.test_name for r in self.results if not r.passed]

        return DomainAuditResult(
            domain=self.target_url,
            score=score,
            rating=rating,
            test_results=self.results,
            failed_tests=failed_tests,
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )
    
    def run_all_tests(self):
        """Kör alla tester"""
        self.print_header()
        
        # Kör alla tester
        self.results.append(self.test_rate_limiting())
        time.sleep(1)
        
        self.results.append(self.test_user_agent_blocking())
        time.sleep(1)
        
        self.results.append(self.test_header_fingerprinting())
        time.sleep(1)
        
        self.results.append(self.test_javascript_challenge())
        time.sleep(1)
        
        self.results.append(self.test_ip_reputation())
        time.sleep(1)
        
        self.results.append(self.test_automated_tools_detection())
        
        # Visa resultat
        self.print_results()
    
    def print_results(self):
        """Skriver ut resultat"""
        print("\n" + "="*60)
        print("📋 RESULTAT")
        print("="*60 + "\n")
        
        for result in self.results:
            print(f"{result.test_name}:")
            print(f"  {result.details}\n")
        
        score, rating = self.calculate_security_score()
        
        print("="*60)
        print(f"🎯 SÄKERHETSPOÄNG: {score}/100")
        print(f"📊 BEDÖMNING: {rating}")
        print("="*60 + "\n")
        
        # Rekommendationer
        print("💡 REKOMMENDATIONER:")
        if score < 80:
            print("\n  Förslag för att förbättra bot-skyddet:")
            for result in self.results:
                if not result.passed:
                    if "Rate Limiting" in result.test_name:
                        print("  - Implementera rate limiting (t.ex. Cloudflare, Nginx)")
                    elif "User-Agent" in result.test_name:
                        print("  - Filtrera suspekta user agents")
                    elif "Header" in result.test_name:
                        print("  - Implementera header fingerprinting")
                    elif "JavaScript" in result.test_name:
                        print("  - Aktivera JavaScript challenges (Cloudflare)")
                    elif "IP Reputation" in result.test_name:
                        print("  - Använd IP reputation databaser")
                    elif "Automated" in result.test_name:
                        print("  - Blockera automatiserade verktyg")
        else:
            print("  ✅ Servern har starkt bot-skydd!")
        
        print("\n" + "="*60 + "\n")

def read_domains_from_file(file_path: str) -> List[str]:
    """Läser domäner från en textfil"""
    domains = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # Hoppa över tomma rader och kommentarer
                if line and not line.startswith('#'):
                    # Lägg till https:// om det saknas
                    if not line.startswith(('http://', 'https://')):
                        line = 'https://' + line
                    domains.append(line)
        return domains
    except FileNotFoundError:
        print(f"❌ Fel: Filen '{file_path}' hittades inte")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Fel vid läsning av fil: {str(e)}")
        sys.exit(1)

def run_batch_audit(domains: List[str]) -> List[DomainAuditResult]:
    """Kör audit på flera domäner"""
    results = []
    total = len(domains)

    print("\n" + "="*60)
    print(f"🔍 BATCH AUDIT - {total} domäner")
    print("="*60 + "\n")

    for i, domain in enumerate(domains, 1):
        print(f"\n[{i}/{total}] Testar {domain}...")
        print("-" * 60)

        try:
            tester = BotProtectionTester(domain)
            tester.run_all_tests()
            results.append(tester.get_audit_result())
        except KeyboardInterrupt:
            print("\n\n⚠️ Batch audit avbruten av användaren")
            break
        except Exception as e:
            print(f"❌ Fel vid testning av {domain}: {str(e)}")
            # Skapa ett felresultat
            error_result = DomainAuditResult(
                domain=domain,
                score=0,
                rating="⚠️ FEL VID TESTNING",
                test_results=[],
                failed_tests=["Alla tester (testning misslyckades)"],
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            )
            results.append(error_result)

        # Paus mellan domäner
        if i < total:
            time.sleep(2)

    return results

def print_batch_summary(results: List[DomainAuditResult]):
    """Skriver ut sammanfattning av batch audit"""
    print("\n" + "="*60)
    print("📊 SAMMANFATTNING - ALLA DOMÄNER")
    print("="*60 + "\n")

    # Översikt
    total_domains = len(results)
    strong_protection = sum(1 for r in results if r.score >= 80)
    medium_protection = sum(1 for r in results if 50 <= r.score < 80)
    weak_protection = sum(1 for r in results if r.score < 50)

    print(f"Totalt antal domäner: {total_domains}")
    print(f"🟢 Starkt skydd (≥80%): {strong_protection}")
    print(f"🟡 Medel skydd (50-79%): {medium_protection}")
    print(f"🔴 Svagt skydd (<50%): {weak_protection}")
    print("\n" + "="*60 + "\n")

    # Detaljerad lista
    print("📋 RESULTAT PER DOMÄN:\n")

    # Sortera efter poäng (lägst först för att visa problemdomäner först)
    sorted_results = sorted(results, key=lambda x: x.score)

    for result in sorted_results:
        print(f"Domän: {result.domain}")
        print(f"  Poäng: {result.score}/100")
        print(f"  Status: {result.rating}")

        if result.failed_tests:
            print(f"  ⚠️  Misslyckade tester: {', '.join(result.failed_tests)}")
        else:
            print(f"  ✅ Alla tester godkända!")

        print()

    print("="*60 + "\n")

    # Problemanalys
    if weak_protection > 0 or medium_protection > 0:
        print("🚨 PROBLEMDOMÄNER OCH REKOMMENDATIONER:\n")

        problem_domains = [r for r in sorted_results if r.score < 80]

        for result in problem_domains:
            print(f"❗ {result.domain} (Poäng: {result.score}/100)")

            if result.failed_tests:
                print("   Åtgärder som behövs:")
                for test in result.failed_tests:
                    if "Rate Limiting" in test:
                        print("   - Implementera rate limiting (t.ex. Cloudflare, Nginx)")
                    elif "User-Agent" in test:
                        print("   - Filtrera suspekta user agents")
                    elif "Header" in test:
                        print("   - Implementera header fingerprinting")
                    elif "JavaScript" in test:
                        print("   - Aktivera JavaScript challenges (Cloudflare)")
                    elif "IP Reputation" in test:
                        print("   - Använd IP reputation databaser")
                    elif "Automated" in test:
                        print("   - Blockera automatiserade verktyg")
            print()

        print("="*60 + "\n")
    else:
        print("🎉 Alla domäner har starkt bot-skydd!\n")
        print("="*60 + "\n")

    # Exportera till JSON
    try:
        output_file = f"audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        export_data = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'summary': {
                'total_domains': total_domains,
                'strong_protection': strong_protection,
                'medium_protection': medium_protection,
                'weak_protection': weak_protection
            },
            'results': [
                {
                    'domain': r.domain,
                    'score': r.score,
                    'rating': r.rating,
                    'failed_tests': r.failed_tests,
                    'timestamp': r.timestamp
                }
                for r in sorted_results
            ]
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)

        print(f"💾 Rapport sparad: {output_file}\n")
    except Exception as e:
        print(f"⚠️ Kunde inte spara rapport: {str(e)}\n")

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Testa en enskild URL:")
        print("    python bot_protection_tester.py <URL>")
        print("    Exempel: python bot_protection_tester.py https://example.com")
        print()
        print("  Testa flera domäner från fil:")
        print("    python bot_protection_tester.py --file <domains.txt>")
        print("    Exempel: python bot_protection_tester.py --file domains.txt")
        print()
        print("  Textfilen ska innehålla en domän per rad:")
        print("    example.com")
        print("    another-domain.com")
        print("    # Kommentarer börjar med #")
        sys.exit(1)

    # Kontrollera om det är batch mode
    if sys.argv[1] == '--file' or sys.argv[1] == '-f':
        if len(sys.argv) < 3:
            print("❌ Fel: Ange sökväg till fil med domäner")
            print("Exempel: python bot_protection_tester.py --file domains.txt")
            sys.exit(1)

        file_path = sys.argv[2]
        domains = read_domains_from_file(file_path)

        if not domains:
            print("❌ Fel: Inga domäner hittades i filen")
            sys.exit(1)

        print(f"📝 Läste {len(domains)} domäner från {file_path}")

        try:
            results = run_batch_audit(domains)
            print_batch_summary(results)
        except KeyboardInterrupt:
            print("\n\n⚠️ Batch audit avbruten av användaren")
            sys.exit(0)
        except Exception as e:
            print(f"\n❌ Fel vid batch audit: {str(e)}")
            sys.exit(1)
    else:
        # Single URL mode
        url = sys.argv[1]

        # Lägg till https:// om det saknas
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        tester = BotProtectionTester(url)

        try:
            tester.run_all_tests()
        except KeyboardInterrupt:
            print("\n\n⚠️ Test avbrutet av användaren")
            sys.exit(0)
        except Exception as e:
            print(f"\n❌ Fel vid testning: {str(e)}")
            sys.exit(1)

if __name__ == "__main__":
    main()