# 🛡️ Bot Protection & SEO Crawlability Tester v4.0

Ett professionellt Python-verktyg för att analysera **säkerhet** (bot-skydd), **SEO** (crawlbarhet), **server bot-behandling** och **AI bot-tillgång** på webbservrar. Verktyget är specialdesignat för att identifiera webbhotell-bot-skydd som skadar SEO genom att blockera eller throttla Googlebot.

## 📋 Vad är detta verktyg?

Bot Protection & SEO Crawlability Tester är ett trippelfokuserat analysverktyg som:

### 🛡️ Säkerhetsperspektiv
Testar hur väl servern är skyddad mot automatiserad trafik, skadliga botar och crawlers.

### 🔍 SEO-perspektiv
Säkerställer att legitima sökmotorbotar (Googlebot, Bingbot, Ahrefs, etc.) kan nå sidan för indexering och ranking.

### 🎯 Server Bot-behandling (NYT I v4.0!)
**Specialdesignat för SEO-byråer och webbhotell-kunder:**
- Detekterar om webbhotell blockerar eller throttlar Googlebot
- Jämför exakt hur servern behandlar botar vs användare
- Identifierar progressiv blockering (gradvis försämring)
- Mäter response time-skillnader (bot throttling)
- Perfekt för att diagnostisera SEO-problem orsak av aggressivt webbhotell-skydd

Verktyget genererar en detaljerad rapport med:

- **Säkerhetspoäng** (0-100) som visar övergripande skyddsnivå
- **Identifiering av skyddslager** (Cloudflare, Akamai, ModSecurity, etc.)
- **Sårbarhetsanalys** med konkreta rekommendationer
- **SEO-problem** som blockerade sökmotorbotar, saknad sitemap, cloaking
- **Detaljerade testresultat** för varje skyddsmekanisme

### Vad testas?

#### 🛡️ Säkerhetstester:
1. **Rate Limiting** - Kontrollerar om servern begränsar antalet requests per tidsenhet
2. **User-Agent Filtering** - Testar om suspekta user agents (python-requests, curl, scrapy) blockeras
3. **Behavioral Analysis** - Analyserar om servern detekterar bot-liknande beteenden via header fingerprinting
4. **WAF & Challenge Detection** - Identifierar Web Application Firewalls och JavaScript challenges
5. **Advanced Fingerprinting** - Testar TLS fingerprinting, proxy-detektion och anonymiseringsverktyg
6. **API Endpoint Protection** - Kontrollerar säkerheten på vanliga API-endpoints

#### 🔍 SEO/Crawlbarhet-tester:
7. **SEO Bot Accessibility** - Verifierar att Googlebot, Bingbot, Ahrefs, Semrush kan nå sidan
8. **Robots.txt Analysis** - Analyserar robots.txt för blockeringar av kritiska botar
9. **Sitemap Accessibility** - Kontrollerar om sitemap.xml finns och är tillgänglig
10. **Cloaking Detection** - Detekterar om botar ser annat innehåll än användare (Google penalty risk)

#### 🤖 AI Bot & Server Bot-behandling-tester:
11. **AI Bot Accessibility** - Testar GPTBot, Claude-Web, Google-Extended, CCBot och andra AI crawlers
12. **Response Time Comparison** - Jämför svarstider mellan botar och användare (detekterar bot throttling)
13. **Googlebot Stress Test** - Testar specifikt om Googlebot blir rate-limitad vid normalt crawl-tempo
14. **Bot Differential Treatment** - Jämför exakt hur servern behandlar Googlebot vs Bingbot vs användare
15. **Progressive Blocking Detection** - Detekterar om Googlebot gradvis blockeras eller throttlas över tid

## 🎯 Perfekt för SEO-byråer med webbhotell-problem

**Problem:** Kunden har bra content men rankings sjunker, eller Google crawlar inte sidan ordentligt.

**Lösning:** Verktyget identifierar om webbhotellets bot-skydd blockerar Googlebot!

### Vanliga scenario verktyget upptäcker:

1. **"Googlebot får 403 men user får 200"**
   → Webbhotell blockerar Googlebot specifikt

2. **"Googlebot blockerad efter 12 requests"**
   → För aggressiv rate limiting för SEO-botar

3. **"Googlebot 65% långsammare än användare"**
   → Server throttlar botar (dåligt för crawl budget)

4. **"Request 1-5 OK, 6-10 blockerade"**
   → Progressiv blockering av Googlebot

5. **"Sitemap.xml ej tillgänglig för Googlebot"**
   → Bot-filter blockerar även sitemap

Med verktygets rapport kan du:
- ✅ Visa webbhotellet exakt vad som är fel
- ✅ Få konkret data för support-ärenden
- ✅ Motivera byte av webbhotell med bevis
- ✅ Jämföra olika webbhotell innan migration

## 🚀 Snabbstart - Steg för steg

### Steg 1: Ladda ner projektet

```bash
# Klona eller ladda ner projektet till din dator
cd Desktop
# Om du har projektet som ZIP, packa upp det
# Om det är ett git-repo:
# git clone <repository-url>
cd Domain_Bot_Block_Tester
```

### Steg 2: Skapa virtuell miljö (venv)

```bash
# Skapa en ny virtuell miljö med Python 3
python3 -m venv venv
```

### Steg 3: Aktivera virtuell miljö

**På macOS/Linux:**
```bash
source venv/bin/activate
```

**På Windows:**
```bash
venv\Scripts\activate
```

Du vet att venv är aktiverad när du ser `(venv)` före din kommandoprompt.

### Steg 4: Installera beroenden

```bash
# Installera alla nödvändiga paket från requirements.txt
pip install -r requirements.txt
```

### Steg 5: Kör verktyget

**Grundläggande användning:**
```bash
# Kör advanced version (rekommenderas)
python advanced_bot_tester.py https://example.com

# URL utan https:// fungerar också (läggs till automatiskt)
python advanced_bot_tester.py example.com
```

**Med extra alternativ:**
```bash
# Exportera rapport till JSON
python advanced_bot_tester.py https://example.com --json

# Tyst läge (mindre output)
python advanced_bot_tester.py https://example.com --quiet

# Både JSON och tyst läge
python advanced_bot_tester.py https://example.com --json --quiet
```

**Enklare version:**
```bash
# Kör basic version (snabbare, enklare tester)
python bot_protection_tester.py https://example.com
```

### Steg 6: Avsluta

```bash
# När du är klar, deaktivera virtuell miljö
deactivate
```

## 📖 Komplett exempel

```bash
# 1. Navigera till projektet
cd /Users/hugo.johansson/Desktop/Domain_Bot_Block_Tester

# 2. Aktivera venv (om redan skapat)
source venv/bin/activate

# 3. Kör test mot en domän
python advanced_bot_tester.py https://cybersajt.se

# 4. Deaktivera venv när du är klar
deactivate
```

## 💼 Exempel: Diagnostisera SEO-kundens webbhotell

**Scenario:** Din kund på example-shop.se har bra content men rankings sjunker.

```bash
# Aktivera venv
source venv/bin/activate

# Kör full analys
python advanced_bot_tester.py https://example-shop.se --json

# Verktyget kör nu 16 tester och genererar rapport...
```

**Resultat kan visa:**
```
⚠️ IDENTIFIERADE SEO-PROBLEM:
   • Googlebot rate-limitad efter endast 14 requests
   • Googlebot får 52% långsammare svar (bot throttling)
   • Server behandlar Googlebot annorlunda (HTTP 403 vs 200)
   • Progressiv blockering: 5/5 OK först, 2/5 OK sedan

💡 REKOMMENDATIONER:
🔍 SEO-REKOMMENDATIONER:
  🔴 Googlebot rate-limitad efter endast 14 requests - Justera WAF/bot-filter
  🔴 Server behandlar Googlebot annorlunda (HTTP 403 vs 200) - KONTROLLERA WEBBHOTELL
  🔴 Progressiv blockering detekterad - Kan förhindra fullständig crawling
```

**Nu har du konkret bevis att visa webbhotellet!** 📊

## 📊 Output & Rapporter

Verktyget ger en detaljerad rapport med:

- ✅/❌ Status för varje test (både säkerhet och SEO)
- 📊 Säkerhetspoäng (0-100)
- 🎯 Övergripande bedömning (Svagt/Medel/Starkt bot-skydd)
- 🛡️ Detekterade säkerhetslager (WAF, CDN, etc.)
- ⚠️ Säkerhetssårbarheter
- 🔍 SEO-problem (blockerade botar, saknad sitemap, etc.)
- 💡 Rekommendationer för både säkerhet och SEO

### Exempel output:

```
======================================================================
🛡️  BOT PROTECTION & SEO CRAWLABILITY TESTER v4.0
======================================================================
Target: https://example.com
Tid: 2025-12-19 14:30:00
Testar: Säkerhet + SEO + Server Bot-behandling + AI Botar
======================================================================

🔌 Test 0: Basic Connectivity...
📊 Test 1: Aggressive Rate Limiting...
🤖 Test 2: User-Agent Filtering...
🔍 Test 3: Behavioral Analysis...
⚡ Test 4: WAF & Challenge Detection...
🔬 Test 5: Advanced Fingerprinting...
🔧 Test 6: API Endpoint Protection...
🔍 Test 7: SEO Bot Accessibility...
🤖 Test 8: Robots.txt Analysis...
🗺️ Test 9: Sitemap Accessibility...
👁️ Test 10: Cloaking Detection...
🤖 Test 11: AI Bot Accessibility...
⏱️ Test 12: Response Time Comparison (Bot Throttling)...
🚨 Test 13: Googlebot Stress Test (Rate Limiting)...
⚖️ Test 14: Bot Differential Treatment...
📉 Test 15: Progressive Blocking Detection...

============================================================
📋 RESULTAT
============================================================

Rate Limiting:
  ✅ Blockad efter 15 requests (HTTP 429)

User-Agent Blocking:
  ✅ Blockerar 3/5 suspekta user agents

Header Fingerprinting:
  ✅ Servern analyserar request headers (olika svar: 403 vs 200)

JavaScript Challenge:
  ✅ JS Challenge detekterad: cloudflare, challenge

IP Reputation:
  ✅ Blockerar proxy/VPN headers (HTTP 403)

Automated Tools Detection:
  ❌ Blockerar inga automatiserade verktyg

============================================================
🎯 SÄKERHETSPOÄNG: 83/100
📊 BEDÖMNING: 🟢 STARKT BOT-SKYDD
============================================================

💡 REKOMMENDATIONER:
  ✅ Servern har starkt bot-skydd!

============================================================
```

## Säkerhetspoäng

- **80-100**: 🟢 Starkt bot-skydd
- **50-79**: 🟡 Medel bot-skydd
- **0-49**: 🔴 Svagt bot-skydd

## 💼 Användningsområden

### 🛡️ Säkerhet:
- **Säkerhetsrevision**: Testa ditt eget bot-skydd
- **Konkurrentanalys**: Se hur konkurrenter skyddar sina sajter
- **Penetration testing**: Identifiera svagheter i bot-skydd
- **OSINT**: Analysera målsajters säkerhetsnivå

### 🔍 SEO & Digital Marketing:
- **SEO-audit**: Säkerställ att sökmotorbotar kan nå din sida
- **Teknisk SEO**: Verifiera robots.txt och sitemap.xml konfiguration
- **Competitor research**: Analysera konkurrenters crawlbarhet
- **Site migration**: Testa att nya säkerhetsinställningar inte blockerar SEO-botar
- **Agency services**: Erbjud crawlability-analys till kunder

### 🎯 Webbhotell & Server Bot-skydd (NYT I v4.0!):
- **Diagnostisera SEO-problem**: Identifiera om webbhotell blockerar Googlebot
- **Kund-rapporter**: Visa konkret bevis på server bot-diskriminering
- **Hosting-jämförelse**: Testa olika webbhotell innan migration
- **Support-ärenden**: Ge teknisk data till webbhotell support
- **Rate limiting-analys**: Visa om Googlebot får sämre behandling än användare
- **Perfekt för SEO-byråer**: Diagnostisera varför kunders rankings sjunker trots bra content

## VARNING ⚠️

Detta verktyg ska **endast användas på:**
- Din egen webbplats
- Webbplatser där du har tillstånd att testa
- I utbildningssyfte på testmiljöer

Obehörig testning kan vara olaglig enligt cybersäkerhetslagstiftning.

## 🔬 Tekniska detaljer

### 🛡️ Säkerhetstester:

**Test 1: Rate Limiting**
Skickar 50 requests snabbt med minimal delay (0.05s) för att detektera rate limiting. Letar efter HTTP 429, 403, eller 503 response codes.

**Test 2: User-Agent Filtering**
Testar suspekta user agents som:
- python-requests/2.31.0
- curl/7.68.0
- Wget, scrapy, Go-http-client

**Test 3: Behavioral Analysis**
Jämför response mellan minimala headers (bot-like) och kompletta browser headers (human-like) för att detektera fingerprinting.

**Test 4: WAF & Challenge Detection**
Identifierar Web Application Firewalls och JavaScript challenges från:
- Cloudflare, Akamai, Imperva
- AWS WAF, Sucuri, Wordfence
- ModSecurity, BIG-IP ASM, Barracuda

**Test 5: Advanced Fingerprinting**
Testar med:
- Proxy headers (X-Forwarded-For, X-Real-IP)
- Tor exit node signatures
- Missing browser headers

**Test 6: API Endpoint Protection**
Testar vanliga API endpoints:
- /api/, /api/v1/, /wp-json/
- /graphql, /.env, /admin/

### 🔍 SEO/Crawlbarhet-tester:

**Test 7: SEO Bot Accessibility**
Verifierar att legitima botar kan nå sidan:
- Sökmotorbotar: Googlebot, Bingbot, Yahoo Slurp
- SEO-verktyg: AhrefsBot, SemrushBot, MJ12bot
- Social: Facebook External Hit

**Test 8: Robots.txt Analysis**
- Kontrollerar om robots.txt finns
- Analyserar om kritiska botar (Googlebot, Bingbot) blockeras
- Verifierar sitemap-referens i robots.txt

**Test 9: Sitemap Accessibility**
Testar vanliga sitemap-platser:
- /sitemap.xml
- /sitemap_index.xml
- /sitemap-index.xml

**Test 10: Cloaking Detection**
Jämför content mellan vanlig användare och Googlebot:
- >10% skillnad = möjlig cloaking (Google penalty risk)
- 5-10% = liten skillnad
- <5% = ingen cloaking detekterad

### 🤖 AI Bot & Server Bot-behandling-tester:

**Test 11: AI Bot Accessibility**
Testar om AI-botar kan nå sidan:
- GPTBot (OpenAI), ChatGPT-User
- Claude-Web (Anthropic)
- Google-Extended (Google AI training)
- CCBot (Common Crawl)
- PerplexityBot, Bytespider, etc.

**Test 12: Response Time Comparison** ⭐ KRITISKT FÖR SEO
Jämför svarstider över 3 requests:
- Användare vs Googlebot
- Detekterar bot throttling (>50% långsammare = KRITISKT)
- Viktigt för crawl budget och ranking

**Test 13: Googlebot Stress Test** ⭐ KRITISKT FÖR SEO
Skickar 25 requests som Googlebot:
- Detekterar rate limiting specifikt för Googlebot
- <15 requests = KRITISKT (för aggressivt)
- 15-20 requests = Varning
- >20 requests = OK

**Test 14: Bot Differential Treatment** ⭐ KRITISKT FÖR SEO
Jämför exakt samma sida med:
- Vanlig användare (Chrome)
- Googlebot
- Bingbot
Analyserar: HTTP status code, content length, response time
Detekterar om servern diskriminerar SEO-botar

**Test 15: Progressive Blocking Detection** ⭐ KRITISKT FÖR SEO
Skickar 10 requests som Googlebot över tid:
- Detekterar om responses försämras (progressiv blockering)
- Detekterar soft throttling (svarstider ökar)
- Identifierar instabil bot-hantering

## 🔗 Integration & Användning

Detta verktyg kan integreras i olika tjänster:

### För säkerhetsanalys:
- Automatiserad säkerhetsanalys av målsajter
- Competitive intelligence rapporter
- Security audit-tjänster

### För SEO & Digital Marketing:
- Teknisk SEO-audit som del av SEO-tjänster
- Crawlability-rapporter för kunder
- Pre-launch säkerhetstester för nya sajter
- Periodisk övervakning av bot-access

## ❓ FAQ - För SEO-byråer

### Q: Min kunds rankings sjunker, hur använder jag verktyget?
**A:** Kör: `python advanced_bot_tester.py https://kundens-sajt.se --json`

Titta särskilt på:
- Test 13 (Googlebot Stress Test) - Blockeras Googlebot?
- Test 14 (Bot Differential Treatment) - Får Googlebot 403 men user 200?
- Test 12 (Response Time) - Är Googlebot >50% långsammare?

### Q: Vad är "normal" rate limiting för Googlebot?
**A:** Googlebot bör klara minst 20-30 requests på kort tid. Om blockerad efter <15 requests är det för aggressivt och skadar SEO.

### Q: Vad betyder "bot throttling"?
**A:** Servern svarar långsammare för botar än användare. >20% långsammare kan påverka crawl budget. >50% är KRITISKT.

### Q: Hur visar jag bevis för webbhotellet?
**A:** Kör med `--json` flaggan för att få strukturerad rapport. Visa dem:
- HTTP status codes (user vs bot)
- Response times (user vs bot)
- Rate limiting thresholds

### Q: Kan verktyget fixa problemen?
**A:** Nej, verktyget diagnostiserar bara. Lösningar:
1. Kontakta webbhotell och be dem justera bot-filter
2. Whitelist Googlebot IP-ranges
3. Byt till SEO-vänligt webbhotell
4. Använd Cloudflare med rätt inställningar

### Q: Hur ofta ska jag köra testerna?
**A:**
- Efter webbhotell-migration: Direkt
- Vid SEO-problem: Omedelbart
- Regelbunden kontroll: 1 gång/månad
- Efter hosting-uppdateringar: Inom 24h

### Q: Blockerar verktyget min sajt när det testar?
**A:** Verktyget är "snällt" och väntar mellan requests. Det simulerar normalt bot-beteende. Används för att hitta PROBLEM, inte skapa dem.

## Licens

Detta verktyg är skapat för säkerhetstestning, SEO-analys och utbildning. Använd ansvarsfullt.

## Författare

Hugo - Cybersajt.se

---

**Version 4.0** - Nu med server bot-behandling tester specifikt för SEO-byråer! 🚀