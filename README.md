# SEO Crawlability Tester v5.0

Ett professionellt verktyg för att testa hur sökmotorer, SEO-verktyg och AI-botar kan crawla din webbplats. Identifierar server-problem, bot-blockeringar och SEO-tekniska issues med detaljerade PDF-rapporter.

## Installation

```bash
# Skapa virtuell miljö
python3 -m venv venv
source venv/bin/activate  # macOS/Linux
# venv\Scripts\activate   # Windows

# Installera beroenden
pip install -r requirements.txt

# För PDF-generering (valfritt)
pip install weasyprint
```

## Användning

```bash
# Grundläggande test
python advanced_bot_tester.py https://example.com

# Med PDF-rapport
python advanced_bot_tester.py https://example.com --pdf

# Tyst läge + JSON
python advanced_bot_tester.py https://example.com --quiet --json
```

PDF-rapporten sparas automatiskt i `reports/`-mappen.

---

## Vad verktyget testar

### 1. Server Diagnostik (Fas för Fas)

Mäter exakt var eventuella prestandaproblem finns genom att bryta ner anslutningen i 5 faser:

| Fas | Vad den mäter | Bra tid | Varning | Kritiskt |
|-----|---------------|---------|---------|----------|
| **DNS Lookup** | Domän → IP-adress | <100ms | >500ms | >1s |
| **TCP Connect** | Anslutning till server | <200ms | >500ms | >1s |
| **SSL Handshake** | HTTPS-förhandling | <300ms | >1s | >2s |
| **TTFB** | Time To First Byte | <200ms | >600ms | >2s |
| **Content Download** | Ladda ner HTML | <1s | >3s | >5s |

**Automatisk flaskhals-identifiering:** Om en fas är långsam visas orsak och lösningsförslag.

```
┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐
│   ✓    │ │   ✓    │ │   ✓    │ │   ⚠    │ │   ✓    │
│  8ms   │ │  15ms  │ │  45ms  │ │ 2.5s   │ │  120ms │
│  DNS   │ │  TCP   │ │  SSL   │ │  TTFB  │ │Download│
└────────┘ └────────┘ └────────┘ └────────┘ └────────┘

⚠ Problem: TTFB är 2.5s - Serverns backend/databas är långsam.
```

---

### 2. Server Prestanda

| Metric | Beskrivning | SEO-påverkan |
|--------|-------------|--------------|
| **TTFB** | Time To First Byte | Core Web Vitals, Google mäter detta |
| **SSL-certifikat** | Giltighet + dagar kvar | HTTPS är en rankingfaktor |
| **Komprimering** | gzip eller brotli | Snabbare LCP |
| **Cache-headers** | Cache-Control | Crawl budget |
| **HTTP-version** | HTTP/1.1 eller HTTP/2 | Snabbare laddning |
| **Server** | nginx, Apache, Cloudflare | Info |

---

### 3. Bot-åtkomst

Testar 26 olika botar genom att simulera deras User-Agent:

#### Sökmotorbotar (3 st)
- Googlebot
- Bingbot
- Yahoo Slurp

#### SEO-verktyg (12 st)
- Ahrefs
- Semrush
- Majestic (MJ12bot)
- Moz/DotBot
- Screaming Frog
- Semrush Site Audit
- Mojeek
- LinkedIn
- Twitter/X
- Facebook
- Pinterest
- Slack

#### AI-botar (11 st)
- GPTBot (OpenAI)
- ChatGPT
- Claude (Anthropic)
- Google AI (Google-Extended)
- Perplexity AI
- Common Crawl (CCBot)
- ByteDance/TikTok (Bytespider)
- Apple AI (Applebot-Extended)
- Meta AI (FacebookBot)
- Anthropic
- Omgili

Varje bot testas individuellt och visas med checkmark/kryss i rapporten.

---

### 4. Testresultat per Kategori

Testerna är grupperade i 4 kategorier:

#### Server & Prestanda (4 tester)
| Test | Beskrivning |
|------|-------------|
| Basic Connectivity | Testar om servern svarar på HTTP-förfrågningar |
| Server Performance | Mäter TTFB, SSL, komprimering, cache-headers |
| Server Load Handling | Simulerar 10 samtidiga requests |
| Server Technology | Identifierar server, CDN, säkerhetslösningar |

#### Bot-åtkomst (4 tester)
| Test | Beskrivning |
|------|-------------|
| SEO Bot Accessibility | Testar Googlebot, Bingbot, Ahrefs, Semrush m.fl. |
| AI Bot Accessibility | Testar GPTBot, Claude, Perplexity m.fl. |
| Bot Differential Treatment | Jämför bot vs användare (cloaking-check) |
| Progressive Blocking | Testar rate limiting efter upprepade requests |

#### Crawlbarhet (4 tester)
| Test | Beskrivning |
|------|-------------|
| Robots.txt Analysis | Analyserar blockerade resurser |
| Sitemap Accessibility | Kontrollerar sitemap.xml |
| Blocked Resources | Testar CSS/JS/bilder för Googlebot |
| Protocol & WWW Consistency | HTTP/HTTPS och www redirects |

#### Googlebot & Mobile-First (4 tester)
| Test | Beskrivning |
|------|-------------|
| Cloaking Detection | Jämför innehåll bot vs användare |
| Mobile vs Desktop Googlebot | Mobile-First Indexing check |
| Googlebot Stress Test | Simulerar intensiv crawling |
| Response Time Comparison | Jämför svarstider bot vs användare |

---

## PDF-rapportens struktur

```
┌─────────────────────────────────────────────────────────────┐
│  SEO CRAWLBARHET RAPPORT                                    │
│  Poäng: 85/100 - Utmärkt                                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  SERVER PRESTANDA                                           │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐    │
│  │  140ms │ │  86d   │ │ Brotli │ │ Aktivt │ │ HTTP/2 │    │
│  │  TTFB  │ │  SSL   │ │ Kompr. │ │ Cache  │ │Protocol│    │
│  └────────┘ └────────┘ └────────┘ └────────┘ └────────┘    │
│                                                             │
│  SERVER DIAGNOSTIK - FAS FÖR FAS                            │
│  DNS → TCP → SSL → TTFB → Download                          │
│  8ms   15ms  45ms  140ms   50ms   = 258ms total             │
│                                                             │
│  TESTRESULTAT PER KATEGORI                                  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ ⚡ Server & Prestanda                           4/4   │  │
│  │ ✓ Basic Connectivity                                 │  │
│  │   Testar om servern svarar på HTTP-förfrågningar     │  │
│  │   Resultat: Server OK (200)                          │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  BOT ACCESSIBILITY - DETALJERAD STATUS                      │
│  Sökmotorbotar: ✓ Googlebot ✓ Bingbot ✓ Yahoo              │
│  SEO-verktyg:   ✓ Ahrefs ✓ Semrush ✗ Majestic              │
│  AI-botar:      ✗ GPTBot ✗ Claude ✓ Perplexity             │
│                                                             │
│  IDENTIFIERADE SEO-PROBLEM                                  │
│  • Sitemap saknas                                           │
│  • Majestic-bot blockerad                                   │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

## Vanliga problem som identifieras

| Problem | Trolig orsak | Lösning |
|---------|--------------|---------|
| Långsam TTFB (>2s) | Långsam backend/databas | Optimera databas, använd caching |
| SSL snart utgånget | Certifikat behöver förnyas | Förnya SSL-certifikatet |
| Ingen komprimering | Server-konfiguration | Aktivera gzip/brotli |
| Botar blockerade | WAF/Firewall | Vitlista sökmotorbotar |
| Sitemap saknas | Inte skapad | Skapa och submita sitemap.xml |
| Cloaking detekterad | Olika innehåll för botar | Visa samma innehåll för alla |
| Långsam DNS | Dålig DNS-provider | Byt till Cloudflare DNS (1.1.1.1) |
| Långsam TCP | Server långt bort | Använd CDN |
| Progressiv blockering | Aggressiv rate limiting | Justera WAF-inställningar |

---

## Filer

```
Domain_Bot_Block_Tester/
├── advanced_bot_tester.py    # Huvudverktyg (SEO-fokus)
├── security_bot_tester.py    # Säkerhetstester (separat)
├── pdf_report_generator.py   # PDF/HTML-rapportgenerator
├── reports/                  # Genererade rapporter
├── requirements.txt          # Python-beroenden
└── README.md                 # Denna fil
```

---

## Exempel på terminal-output

```
======================================================================
  SEO CRAWLABILITY TESTER v1.0
======================================================================
Target: https://example.com
Tid: 2025-01-14 12:00:00
======================================================================

🔬 Kör detaljerad server-diagnostik...
   ✅ DNS Lookup: 8ms
   ✅ TCP Connect: 15ms
   ✅ SSL Handshake: 45ms
   ✅ Time to First Byte: 140ms
   ✅ Content Download: 50ms

🔍 Test 1: SEO Bot Accessibility...
   ✅ Alla 26 botar kan nå sidan

🤖 Test 2: Robots.txt Analysis...
   ✅ robots.txt finns och är korrekt konfigurerad

⚡ Test 13: Server Performance Analysis...
   ✅ TTFB 140ms, Komprimering: brotli, SSL OK (86d kvar)

======================================================================
  SEO CRAWLBARHET POÄNG: 85/100
  BEDÖMNING: Utmärkt
  ✅ Godkända tester: 14
  ❌ Misslyckade tester: 2
======================================================================

📄 PDF-rapport genererad: reports/seo_report_example_com_20250114.pdf
```

---

## FAQ

### Q: Hur tolkar jag TTFB?
**A:** TTFB (Time To First Byte) är tiden det tar för servern att börja svara. Google rekommenderar <200ms. Över 2 sekunder är kritiskt.

### Q: Varför är AI-botar blockerade?
**A:** Många sajter blockerar AI-botar för att skydda sitt innehåll från AI-träning. Detta påverkar INTE SEO. Det är ett affärsbeslut.

### Q: Vad är "cloaking"?
**A:** Cloaking är när servern visar olika innehåll för botar vs användare. Detta är mot Googles riktlinjer och kan leda till penalty.

### Q: Hur ofta ska jag köra testet?
**A:**
- Efter hosting-migration: Direkt
- Vid SEO-problem: Omedelbart
- Regelbunden kontroll: 1 gång/månad

### Q: Blockerar verktyget min sajt?
**A:** Nej, verktyget är "snällt" med delays mellan requests. Det simulerar normalt bot-beteende.

---

## Säkerhetstester (separat fil)

För säkerhetstester (WAF-detektion, rate limiting, fingerprinting), använd:

```bash
python security_bot_tester.py https://example.com
```

---

## Licens

MIT License

## Författare

Hugo - Cybersajt.se

---

**Version 5.0** - Med detaljerad server-diagnostik, PDF-rapporter och 26 bot-tester!
