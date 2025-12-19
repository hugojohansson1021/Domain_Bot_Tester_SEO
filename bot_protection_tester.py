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

@dataclass
class TestResult:
    """Resultat från ett test"""
    test_name: str
    passed: bool
    details: str
    response_code: int = None
    response_time: float = None

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

def main():
    if len(sys.argv) < 2:
        print("Usage: python bot_protection_tester.py <URL>")
        print("Exempel: python bot_protection_tester.py https://example.com")
        sys.exit(1)
    
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