#!/usr/bin/env python3
"""
PDF Report Generator for SEO Crawlability Tester
Generates professional PDF reports from test results
"""

import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
from urllib.parse import urlparse

# HTML Template för rapporten
def generate_html_report(report_data: Dict[str, Any]) -> str:
    """Genererar HTML-rapport från testresultat"""

    # Extrahera data
    target_url = report_data.get('target_url', 'Unknown')
    timestamp = report_data.get('timestamp', datetime.now().isoformat())
    total_score = report_data.get('total_score', 0)
    rating = report_data.get('rating', 'Unknown')
    tests_passed = report_data.get('tests_passed', 0)
    tests_failed = report_data.get('tests_failed', 0)
    test_results = report_data.get('test_results', [])
    seo_issues = report_data.get('seo_issues', [])
    recommendations = report_data.get('recommendations', [])
    bot_accessibility_details = report_data.get('bot_accessibility_details', [])
    server_performance_details = report_data.get('server_performance_details', {})
    server_diagnostics = report_data.get('server_diagnostics', {})

    # Beräkna färg för score
    if total_score >= 85:
        score_color = '#22c55e'  # Grön
        score_bg = '#dcfce7'
        score_text = 'Utmärkt'
    elif total_score >= 65:
        score_color = '#eab308'  # Gul
        score_bg = '#fef9c3'
        score_text = 'Bra'
    elif total_score >= 40:
        score_color = '#f97316'  # Orange
        score_bg = '#ffedd5'
        score_text = 'Medel'
    else:
        score_color = '#ef4444'  # Röd
        score_bg = '#fee2e2'
        score_text = 'Behöver förbättras'

    # Generera test-resultat HTML
    test_results_html = ""
    for result in test_results:
        test_name = result.get('test_name', 'Unknown')
        passed = result.get('passed', False)
        details = result.get('details', '')
        severity = result.get('severity', 'INFO')

        # Ta bort emojis från details för PDF
        details_clean = details.replace('✅', '').replace('❌', '').replace('⚠️', '').replace('ℹ️', '').strip()

        if passed:
            status_class = 'passed'
            status_icon = '&#10004;'  # Checkmark
            status_text = 'OK'
        else:
            if severity == 'CRITICAL':
                status_class = 'critical'
            elif severity == 'HIGH':
                status_class = 'failed'
            else:
                status_class = 'warning'
            status_icon = '&#10006;' if severity in ['CRITICAL', 'HIGH'] else '&#9888;'
            status_text = 'Problem' if severity in ['CRITICAL', 'HIGH'] else 'Varning'

        test_results_html += f'''
        <tr class="{status_class}">
            <td class="status-cell"><span class="status-icon">{status_icon}</span> {status_text}</td>
            <td class="test-name">{test_name}</td>
            <td class="test-details">{details_clean}</td>
        </tr>
        '''

    # Generera issues HTML
    issues_html = ""
    if seo_issues:
        for issue in seo_issues:
            issues_html += f'<li>{issue}</li>\n'
    else:
        issues_html = '<li class="no-issues">Inga SEO-problem identifierade</li>'

    # Generera recommendations HTML
    recommendations_html = ""
    for rec in recommendations:
        # Skippa tomma rader och rubriker
        rec_clean = rec.strip()
        if not rec_clean or rec_clean.startswith('🔍') or rec_clean.startswith('⚡') or rec_clean.startswith('🚨'):
            continue
        # Ta bort emojis
        rec_clean = rec_clean.replace('🔴', '•').replace('⚠️', '•').replace('✅', '•').replace('→', '-')
        if rec_clean.startswith('  '):
            recommendations_html += f'<li>{rec_clean.strip()}</li>\n'

    if not recommendations_html:
        recommendations_html = '<li class="no-issues">Inga specifika rekommendationer - bra jobbat!</li>'

    # Generera bot accessibility HTML (individuella checkmarks)
    bot_accessibility_html = ""
    if bot_accessibility_details:
        # Gruppera efter kategori
        search_engines = [b for b in bot_accessibility_details if b.get('category') == 'Sökmotor']
        seo_tools = [b for b in bot_accessibility_details if b.get('category') == 'SEO-verktyg']
        ai_bots = [b for b in bot_accessibility_details if b.get('category') == 'AI-bot']

        bot_accessibility_html = '''
        <div class="bot-accessibility-section">
            <h3 class="bot-category-title">Sökmotorbotar</h3>
            <div class="bot-grid">
        '''
        for bot in search_engines:
            passed = bot.get('passed', False)
            name = bot.get('name', 'Unknown')
            status_code = bot.get('status_code', '-')
            icon = '&#10004;' if passed else '&#10006;'
            status_class = 'bot-passed' if passed else 'bot-blocked'
            bot_accessibility_html += f'''
                <div class="bot-item {status_class}">
                    <span class="bot-icon">{icon}</span>
                    <span class="bot-name">{name}</span>
                    <span class="bot-status">{status_code}</span>
                </div>
            '''

        bot_accessibility_html += '''
            </div>
            <h3 class="bot-category-title">SEO-verktyg</h3>
            <div class="bot-grid">
        '''
        for bot in seo_tools:
            passed = bot.get('passed', False)
            name = bot.get('name', 'Unknown')
            status_code = bot.get('status_code', '-')
            icon = '&#10004;' if passed else '&#10006;'
            status_class = 'bot-passed' if passed else 'bot-blocked'
            bot_accessibility_html += f'''
                <div class="bot-item {status_class}">
                    <span class="bot-icon">{icon}</span>
                    <span class="bot-name">{name}</span>
                    <span class="bot-status">{status_code}</span>
                </div>
            '''

        bot_accessibility_html += '''
            </div>
            <h3 class="bot-category-title">AI-botar (GPT, Claude, Perplexity m.fl.)</h3>
            <div class="bot-grid">
        '''
        for bot in ai_bots:
            passed = bot.get('passed', False)
            name = bot.get('name', 'Unknown')
            status_code = bot.get('status_code', '-')
            icon = '&#10004;' if passed else '&#10006;'
            status_class = 'bot-passed' if passed else 'bot-blocked'
            bot_accessibility_html += f'''
                <div class="bot-item {status_class}">
                    <span class="bot-icon">{icon}</span>
                    <span class="bot-name">{name}</span>
                    <span class="bot-status">{status_code}</span>
                </div>
            '''

        bot_accessibility_html += '''
            </div>
        </div>
        '''

    # Generera server performance boxes HTML
    server_perf_html = ""
    if server_performance_details:
        status_colors = {
            'good': ('#22c55e', '#f0fdf4'),      # Grön
            'ok': ('#eab308', '#fef9c3'),         # Gul
            'warning': ('#f97316', '#ffedd5'),    # Orange
            'critical': ('#ef4444', '#fee2e2'),   # Röd
            'info': ('#3b82f6', '#eff6ff'),       # Blå
            'unknown': ('#94a3b8', '#f8fafc')     # Grå
        }

        server_perf_html = '<div class="perf-grid">'

        # Ordning: TTFB, SSL, Komprimering, Cache, Protokoll
        metric_order = ['ttfb', 'ssl', 'compression', 'cache', 'http_version']

        for key in metric_order:
            if key in server_performance_details:
                metric = server_performance_details[key]
                value = metric.get('value', '-')
                status = metric.get('status', 'unknown')
                label = metric.get('label', key)

                color, bg = status_colors.get(status, status_colors['unknown'])
                icon = '&#10004;' if status in ['good', 'ok'] else ('&#10006;' if status == 'critical' else '&#9888;')

                server_perf_html += f'''
                <div class="perf-box" style="border-color: {color}; background: {bg};">
                    <div class="perf-icon" style="color: {color};">{icon}</div>
                    <div class="perf-value" style="color: {color};">{value}</div>
                    <div class="perf-label">{label}</div>
                </div>
                '''

        # Lägg till server-info om det finns
        if 'server' in server_performance_details:
            server = server_performance_details['server']
            server_perf_html += f'''
                <div class="perf-box perf-box-wide" style="border-color: #3b82f6; background: #eff6ff;">
                    <div class="perf-label">Server</div>
                    <div class="perf-value" style="color: #3b82f6;">{server.get('value', 'Okänd')}</div>
                </div>
            '''

        server_perf_html += '</div>'

    # Generera server diagnostics HTML (fas-för-fas)
    server_diag_html = ""
    if server_diagnostics:
        status_colors = {
            'good': ('#22c55e', '#f0fdf4', '&#10004;'),      # Grön
            'ok': ('#eab308', '#fef9c3', '&#10004;'),         # Gul
            'warning': ('#f97316', '#ffedd5', '&#9888;'),     # Orange
            'critical': ('#ef4444', '#fee2e2', '&#10006;'),   # Röd
            'skip': ('#94a3b8', '#f8fafc', '&#8211;'),        # Grå (skip)
            'unknown': ('#94a3b8', '#f8fafc', '?')            # Grå
        }

        phase_labels = {
            'dns': ('DNS Lookup', 'Domän → IP-adress'),
            'tcp': ('TCP Connect', 'Anslutning till server'),
            'ssl': ('SSL Handshake', 'HTTPS-förhandling'),
            'ttfb': ('Time to First Byte', 'Servern processar request'),
            'download': ('Content Download', 'Ladda ner HTML')
        }

        server_diag_html = '<div class="diagnostics-section">'
        server_diag_html += '<div class="diag-phases">'

        phases = ['dns', 'tcp', 'ssl', 'ttfb', 'download']
        for phase in phases:
            if phase in server_diagnostics:
                phase_data = server_diagnostics[phase]
                time_val = phase_data.get('time')
                status = phase_data.get('status', 'unknown')
                label, desc = phase_labels.get(phase, (phase, ''))

                if time_val is not None:
                    color, bg, icon = status_colors.get(status, status_colors['unknown'])

                    # Formatera tid
                    if time_val < 1:
                        time_str = f"{time_val*1000:.0f}ms"
                    else:
                        time_str = f"{time_val:.2f}s"

                    server_diag_html += f'''
                    <div class="diag-phase" style="border-color: {color}; background: {bg};">
                        <div class="diag-phase-header">
                            <span class="diag-icon" style="color: {color};">{icon}</span>
                            <span class="diag-time" style="color: {color};">{time_str}</span>
                        </div>
                        <div class="diag-label">{label}</div>
                        <div class="diag-desc">{desc}</div>
                    </div>
                    '''

        server_diag_html += '</div>'

        # Visa total tid
        total_data = server_diagnostics.get('total', {})
        total_time = total_data.get('time')
        if total_time is not None:
            total_status = total_data.get('status', 'unknown')
            color, bg, _ = status_colors.get(total_status, status_colors['unknown'])
            if total_time < 1:
                total_str = f"{total_time*1000:.0f}ms"
            else:
                total_str = f"{total_time:.2f}s"

            server_diag_html += f'''
            <div class="diag-total" style="border-color: {color};">
                <span class="diag-total-label">Total laddningstid:</span>
                <span class="diag-total-value" style="color: {color};">{total_str}</span>
            </div>
            '''

        # Visa flaskhals/problem om det finns
        bottleneck = server_diagnostics.get('bottleneck')
        bottleneck_cause = server_diagnostics.get('bottleneck_cause')
        if bottleneck and bottleneck_cause:
            server_diag_html += f'''
            <div class="diag-bottleneck">
                <div class="bottleneck-icon">&#9888;</div>
                <div class="bottleneck-text">
                    <strong>Problem identifierat:</strong> {bottleneck_cause}
                </div>
            </div>
            '''

        server_diag_html += '</div>'

    # Test-förklaringar - vad varje test faktiskt gör
    test_descriptions = {
        # Server & Prestanda
        'Basic Connectivity': 'Testar om servern svarar på HTTP-förfrågningar och returnerar korrekt statuskod.',
        'Server Performance': 'Mäter TTFB (Time To First Byte), SSL-certifikat, komprimering (gzip/brotli) och cache-headers.',
        'Server Load Handling': 'Simulerar 10 samtidiga requests för att testa hur servern hanterar belastning från crawlers.',
        'Server Technology': 'Identifierar server-mjukvara, CDN och säkerhetslösningar via HTTP-headers.',

        # Bot-åtkomst
        'SEO Bot Accessibility': 'Testar om sökmotorbotar (Googlebot, Bingbot) och SEO-verktyg (Ahrefs, Semrush) kan nå sidan.',
        'AI Bot Accessibility': 'Testar om AI-botar (GPTBot, Claude, Perplexity) är tillåtna eller blockerade.',
        'Bot Differential Treatment': 'Jämför om botar får samma innehåll som vanliga användare (cloaking-check).',
        'Progressive Blocking': 'Testar om servern börjar blockera efter upprepade requests (rate limiting).',

        # Crawlbarhet
        'Robots.txt Analysis': 'Analyserar robots.txt för att se vilka sidor/resurser som är blockerade för crawlers.',
        'Sitemap Accessibility': 'Kontrollerar om sitemap.xml finns och är tillgänglig för sökmotorer.',
        'Blocked Resources': 'Testar om viktiga resurser (CSS, JS, bilder) är blockerade för Googlebot.',
        'Protocol & WWW Consistency': 'Kontrollerar redirects mellan HTTP/HTTPS och www/icke-www versioner.',

        # Googlebot & Mobile-First
        'Cloaking Detection': 'Jämför innehåll som visas för Googlebot vs vanliga användare för att upptäcka cloaking.',
        'Mobile vs Desktop Googlebot': 'Testar om Mobile Googlebot och Desktop Googlebot får samma innehåll (Mobile-First Indexing).',
        'Googlebot Stress Test': 'Simulerar intensiv crawling för att testa serverns responstid under Googlebot-belastning.',
        'Response Time Comparison': 'Jämför svarstider mellan bot-requests och vanliga användarrequests.',
    }

    # Kategorisera tester
    test_categories = {
        'server': {
            'title': 'Server & Prestanda',
            'icon': '&#9889;',
            'tests': ['Basic Connectivity', 'Server Performance', 'Server Load Handling', 'Server Technology']
        },
        'bots': {
            'title': 'Bot-åtkomst',
            'icon': '&#129302;',
            'tests': ['SEO Bot Accessibility', 'AI Bot Accessibility', 'Bot Differential Treatment', 'Progressive Blocking']
        },
        'crawl': {
            'title': 'Crawlbarhet',
            'icon': '&#128269;',
            'tests': ['Robots.txt Analysis', 'Sitemap Accessibility', 'Blocked Resources', 'Protocol & WWW Consistency']
        },
        'googlebot': {
            'title': 'Googlebot & Mobile-First',
            'icon': '&#128241;',
            'tests': ['Cloaking Detection', 'Mobile vs Desktop Googlebot', 'Googlebot Stress Test', 'Response Time Comparison']
        }
    }

    # Gruppera tester efter kategori
    categorized_tests = {cat: [] for cat in test_categories}
    uncategorized = []

    for result in test_results:
        test_name = result.get('test_name', 'Unknown')
        found = False
        for cat_key, cat_info in test_categories.items():
            if test_name in cat_info['tests']:
                categorized_tests[cat_key].append(result)
                found = True
                break
        if not found:
            uncategorized.append(result)

    # Generera kategoriserad test HTML
    categorized_html = ""
    for cat_key, cat_info in test_categories.items():
        tests = categorized_tests[cat_key]
        if not tests:
            continue

        passed_count = sum(1 for t in tests if t.get('passed', False))
        total_count = len(tests)

        categorized_html += f'''
        <div class="category-section">
            <div class="category-header">
                <span class="category-icon">{cat_info['icon']}</span>
                <span class="category-title">{cat_info['title']}</span>
                <span class="category-score">{passed_count}/{total_count}</span>
            </div>
            <div class="category-tests">
        '''

        for result in tests:
            test_name = result.get('test_name', 'Unknown')
            passed = result.get('passed', False)
            details = result.get('details', '')
            severity = result.get('severity', 'INFO')

            # Hämta förklaring för testet
            description = test_descriptions.get(test_name, '')

            # Ta bort emojis från resultat
            details_clean = details.replace('✅', '').replace('❌', '').replace('⚠️', '').replace('ℹ️', '').strip()

            if passed:
                status_icon = '&#10004;'
                status_class = 'test-passed'
                result_label = 'OK'
            else:
                status_icon = '&#10006;' if severity in ['CRITICAL', 'HIGH'] else '&#9888;'
                status_class = 'test-failed' if severity in ['CRITICAL', 'HIGH'] else 'test-warning'
                result_label = 'Problem' if severity in ['CRITICAL', 'HIGH'] else 'Varning'

            categorized_html += f'''
                <div class="category-test-item {status_class}">
                    <div class="test-header">
                        <span class="test-status-icon">{status_icon}</span>
                        <span class="test-name">{test_name}</span>
                        <span class="test-result-label">{result_label}</span>
                    </div>
                    <div class="test-description">{description}</div>
                    <div class="test-result">{details_clean}</div>
                </div>
            '''

        categorized_html += '''
            </div>
        </div>
        '''

    # Formatera datum
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        formatted_date = dt.strftime('%Y-%m-%d %H:%M')
    except:
        formatted_date = timestamp[:16] if len(timestamp) > 16 else timestamp

    # Domännamn
    domain = urlparse(target_url).netloc

    html = f'''<!DOCTYPE html>
<html lang="sv">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SEO Crawlbarhet Rapport - {domain}</title>
    <style>
        @page {{
            size: A4;
            margin: 2cm 1.5cm;
            @top-center {{
                content: "SEO Crawlbarhet Rapport";
                font-size: 10px;
                color: #666;
            }}
            @bottom-center {{
                content: "Sida " counter(page) " av " counter(pages);
                font-size: 10px;
                color: #666;
            }}
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            font-size: 11px;
            line-height: 1.5;
            color: #333;
            background: #fff;
        }}

        .header {{
            background: #0C281D;
            color: #F5F2D4;
            padding: 30px;
            margin: -2cm -1.5cm 20px -1.5cm;
            text-align: center;
        }}

        .header h1 {{
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 5px;
        }}

        .header .subtitle {{
            font-size: 14px;
            opacity: 0.9;
        }}

        .meta-info {{
            display: flex;
            justify-content: space-between;
            background: #0C281D;
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            border: 1px solid #e2e8f0;
        }}

        .meta-item {{
            text-align: center;
        }}

        .meta-label {{
            font-size: 10px;
            color: #F5F2D4;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .meta-value {{
            font-size: 13px;
            font-weight: 600;
            color: #F5F2D4;
            margin-top: 2px;
        }}

        .score-section {{
            text-align: center;
            padding: 25px;
            margin-bottom: 25px;
            background: {score_bg};
            border-radius: 12px;
            border: 2px solid {score_color};
        }}

        .score-value {{
            font-size: 48px;
            font-weight: 700;
            color: {score_color};
        }}

        .score-label {{
            font-size: 14px;
            color: #64748b;
            margin-top: 5px;
        }}

        .score-rating {{
            font-size: 18px;
            font-weight: 600;
            color: {score_color};
            margin-top: 10px;
        }}

        .summary-boxes {{
            display: flex;
            gap: 15px;
            margin-bottom: 25px;
        }}

        .summary-box {{
            flex: 1;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }}

        .summary-box.passed {{
            background: #dcfce7;
            border: 1px solid #22c55e;
        }}

        .summary-box.failed {{
            background: #fee2e2;
            border: 1px solid #ef4444;
        }}

        .summary-box .number {{
            font-size: 28px;
            font-weight: 700;
        }}

        .summary-box.passed .number {{
            color: #22c55e;
        }}

        .summary-box.failed .number {{
            color: #ef4444;
        }}

        .summary-box .label {{
            font-size: 11px;
            color: #64748b;
        }}

        .section {{
            margin-bottom: 25px;
        }}

        .section-title {{
            font-size: 16px;
            font-weight: 600;
            color: #0C281D;
            padding-bottom: 8px;
            border-bottom: 2px solid #0C281D;
            margin-bottom: 15px;
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 10px;
        }}

        th {{
            background: #0C281D;
            color: white;
            padding: 10px 8px;
            text-align: left;
            font-weight: 600;
        }}

        td {{
            padding: 8px;
            border-bottom: 1px solid #e2e8f0;
            vertical-align: top;
        }}

        tr:nth-child(even) {{
            background: #f8fafc;
        }}

        tr.passed td {{
            background: #f0fdf4;
        }}

        tr.failed td {{
            background: #fef2f2;
        }}

        tr.critical td {{
            background: #fef2f2;
            border-left: 3px solid #ef4444;
        }}

        tr.warning td {{
            background: #fffbeb;
            border-left: 3px solid #f59e0b;
        }}

        .status-cell {{
            width: 80px;
            font-weight: 600;
            white-space: nowrap;
        }}

        .status-icon {{
            font-size: 12px;
        }}

        tr.passed .status-cell {{
            color: #22c55e;
        }}

        tr.failed .status-cell, tr.critical .status-cell {{
            color: #ef4444;
        }}

        tr.warning .status-cell {{
            color: #f59e0b;
        }}

        .test-name {{
            width: 180px;
            font-weight: 500;
        }}

        .test-details {{
            color: #64748b;
        }}

        .issues-list, .recommendations-list {{
            list-style: none;
            padding: 0;
        }}

        .issues-list li, .recommendations-list li {{
            padding: 10px 15px;
            margin-bottom: 8px;
            background: #fff7ed;
            border-left: 3px solid #f97316;
            border-radius: 0 6px 6px 0;
            font-size: 11px;
        }}

        .issues-list li.no-issues, .recommendations-list li.no-issues {{
            background: #f0fdf4;
            border-left-color: #22c55e;
            color: #166534;
        }}

        .recommendations-list li {{
            background: #eff6ff;
            border-left-color: #3b82f6;
        }}

        .footer {{
            margin-top: 30px;
            padding-top: 15px;
            border-top: 1px solid #e2e8f0;
            text-align: center;
            font-size: 10px;
            color: #94a3b8;
        }}

        .page-break {{
            page-break-before: always;
        }}

        /* Bot Accessibility Grid */
        .bot-accessibility-section {{
            margin-top: 15px;
            padding: 15px;
            background: #f8fafc;
            border-radius: 8px;
            border: 1px solid #e2e8f0;
        }}

        .bot-category-title {{
            font-size: 12px;
            font-weight: 600;
            color: #475569;
            margin: 10px 0 8px 0;
            padding-bottom: 5px;
            border-bottom: 1px solid #e2e8f0;
        }}

        .bot-category-title:first-child {{
            margin-top: 0;
        }}

        .bot-grid {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }}

        .bot-item {{
            display: flex;
            align-items: center;
            padding: 6px 12px;
            border-radius: 6px;
            font-size: 10px;
            min-width: 120px;
        }}

        .bot-item.bot-passed {{
            background: #f0fdf4;
            border: 1px solid #22c55e;
        }}

        .bot-item.bot-blocked {{
            background: #fef2f2;
            border: 1px solid #ef4444;
        }}

        .bot-icon {{
            font-size: 12px;
            margin-right: 6px;
            font-weight: bold;
        }}

        .bot-passed .bot-icon {{
            color: #22c55e;
        }}

        .bot-blocked .bot-icon {{
            color: #ef4444;
        }}

        .bot-name {{
            flex: 1;
            font-weight: 500;
            color: #334155;
        }}

        .bot-status {{
            font-size: 9px;
            color: #64748b;
            margin-left: 8px;
        }}

        /* Performance Boxes */
        .perf-grid {{
            display: flex;
            flex-wrap: wrap;
            gap: 12px;
            margin-bottom: 20px;
        }}

        .perf-box {{
            flex: 1;
            min-width: 100px;
            max-width: 140px;
            padding: 12px;
            border-radius: 8px;
            border: 2px solid;
            text-align: center;
        }}

        .perf-box-wide {{
            min-width: 200px;
            max-width: 300px;
        }}

        .perf-icon {{
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 4px;
        }}

        .perf-value {{
            font-size: 16px;
            font-weight: 700;
            margin-bottom: 2px;
        }}

        .perf-label {{
            font-size: 9px;
            color: #64748b;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        /* Category Sections */
        .category-section {{
            margin-bottom: 20px;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            overflow: hidden;
        }}

        .category-header {{
            background: #0C281D;
            color: #F5F2D4;
            padding: 10px 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .category-icon {{
            font-size: 16px;
        }}

        .category-title {{
            flex: 1;
            font-size: 13px;
            font-weight: 600;
        }}

        .category-score {{
            font-size: 12px;
            background: rgba(255,255,255,0.2);
            padding: 3px 10px;
            border-radius: 12px;
        }}

        .category-tests {{
            padding: 10px;
        }}

        .category-test-item {{
            padding: 12px;
            margin-bottom: 8px;
            border-radius: 6px;
            font-size: 10px;
        }}

        .category-test-item.test-passed {{
            background: #f0fdf4;
            border-left: 4px solid #22c55e;
        }}

        .category-test-item.test-failed {{
            background: #fef2f2;
            border-left: 4px solid #ef4444;
        }}

        .category-test-item.test-warning {{
            background: #fffbeb;
            border-left: 4px solid #f59e0b;
        }}

        .test-header {{
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 6px;
        }}

        .test-status-icon {{
            font-size: 14px;
            font-weight: bold;
        }}

        .test-passed .test-status-icon {{
            color: #22c55e;
        }}

        .test-failed .test-status-icon {{
            color: #ef4444;
        }}

        .test-warning .test-status-icon {{
            color: #f59e0b;
        }}

        .category-test-item .test-name {{
            font-weight: 700;
            color: #1e293b;
            font-size: 11px;
            flex: 1;
        }}

        .test-result-label {{
            font-size: 9px;
            font-weight: 600;
            padding: 2px 8px;
            border-radius: 10px;
        }}

        .test-passed .test-result-label {{
            background: #dcfce7;
            color: #166534;
        }}

        .test-failed .test-result-label {{
            background: #fee2e2;
            color: #991b1b;
        }}

        .test-warning .test-result-label {{
            background: #fef3c7;
            color: #92400e;
        }}

        .test-description {{
            color: #64748b;
            font-size: 9px;
            margin-bottom: 6px;
            font-style: italic;
        }}

        .test-result {{
            color: #334155;
            font-size: 10px;
            background: rgba(255,255,255,0.5);
            padding: 6px 8px;
            border-radius: 4px;
        }}

        /* Server Diagnostics */
        .diagnostics-section {{
            background: #f8fafc;
            border-radius: 8px;
            padding: 15px;
            border: 1px solid #e2e8f0;
        }}

        .diag-phases {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-bottom: 15px;
        }}

        .diag-phase {{
            flex: 1;
            min-width: 100px;
            max-width: 130px;
            padding: 10px;
            border-radius: 8px;
            border: 2px solid;
            text-align: center;
        }}

        .diag-phase-header {{
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 6px;
            margin-bottom: 6px;
        }}

        .diag-icon {{
            font-size: 14px;
            font-weight: bold;
        }}

        .diag-time {{
            font-size: 14px;
            font-weight: 700;
        }}

        .diag-label {{
            font-size: 9px;
            font-weight: 600;
            color: #334155;
            margin-bottom: 2px;
        }}

        .diag-desc {{
            font-size: 8px;
            color: #64748b;
        }}

        .diag-total {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 10px 15px;
            background: white;
            border-radius: 6px;
            border: 2px solid;
            margin-bottom: 10px;
        }}

        .diag-total-label {{
            font-size: 11px;
            font-weight: 600;
            color: #334155;
        }}

        .diag-total-value {{
            font-size: 16px;
            font-weight: 700;
        }}

        .diag-bottleneck {{
            display: flex;
            align-items: flex-start;
            gap: 10px;
            padding: 12px;
            background: #fef2f2;
            border-radius: 6px;
            border-left: 4px solid #ef4444;
        }}

        .bottleneck-icon {{
            font-size: 18px;
            color: #ef4444;
        }}

        .bottleneck-text {{
            font-size: 10px;
            color: #991b1b;
            line-height: 1.4;
        }}

        .bottleneck-text strong {{
            display: block;
            margin-bottom: 2px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>SEO Crawlbarhet Rapport</h1>
        <div class="subtitle">Analys av sökmotoroptimering och crawlbarhet</div>
    </div>

    <div class="meta-info">
        <div class="meta-item">
            <div class="meta-label">Webbplats</div>
            <div class="meta-value">{domain}</div>
        </div>
        <div class="meta-item">
            <div class="meta-label">Analyserad URL</div>
            <div class="meta-value">{target_url}</div>
        </div>
        <div class="meta-item">
            <div class="meta-label">Datum</div>
            <div class="meta-value">{formatted_date}</div>
        </div>
    </div>

    <div class="score-section">
        <div class="score-value">{total_score}/100</div>
        <div class="score-label">SEO Crawlbarhet Poäng</div>
        <div class="score-rating">{score_text}</div>
    </div>

    <div class="summary-boxes">
        <div class="summary-box passed">
            <div class="number">{tests_passed}</div>
            <div class="label">Godkända tester</div>
        </div>
        <div class="summary-box failed">
            <div class="number">{tests_failed}</div>
            <div class="label">Problem identifierade</div>
        </div>
    </div>

    <div class="section">
        <h2 class="section-title">Server Prestanda</h2>
        {server_perf_html}
    </div>

    <div class="section">
        <h2 class="section-title">Server Diagnostik - Fas för Fas</h2>
        {server_diag_html}
    </div>

    <div class="section">
        <h2 class="section-title">Testresultat per Kategori</h2>
        {categorized_html}
    </div>

    <div class="section">
        <h2 class="section-title">Bot Accessibility - Detaljerad Status</h2>
        {bot_accessibility_html}
    </div>

    <div class="section">
        <h2 class="section-title">Identifierade SEO-Problem</h2>
        <ul class="issues-list">
            {issues_html}
        </ul>
    </div>

    <div class="footer">
        <p>Genererad med SEO Crawlability Tester | {formatted_date}</p>
        <p>Denna rapport är automatgenererad baserat på tekniska tester av webbplatsens crawlbarhet.</p>
    </div>
</body>
</html>'''

    return html


def save_html_report(report_data: Dict[str, Any], output_path: str = None) -> str:
    """Sparar HTML-rapport till fil"""
    html = generate_html_report(report_data)

    if output_path is None:
        domain = urlparse(report_data.get('target_url', 'unknown')).netloc.replace('.', '_')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = f"reports/seo_report_{domain}_{timestamp}.html"

    # Skapa reports-mappen om den inte finns
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)

    return output_path


def generate_pdf_report(report_data: Dict[str, Any], output_path: str = None) -> str:
    """Genererar PDF-rapport från testresultat"""

    # Försök använda WeasyPrint
    try:
        from weasyprint import HTML, CSS

        html = generate_html_report(report_data)

        if output_path is None:
            domain = urlparse(report_data.get('target_url', 'unknown')).netloc.replace('.', '_')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_path = f"reports/seo_report_{domain}_{timestamp}.pdf"

        # Skapa reports-mappen om den inte finns
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        # Generera PDF
        HTML(string=html).write_pdf(output_path)

        return output_path

    except ImportError:
        print("⚠️  WeasyPrint är inte installerat. Installera med:")
        print("    pip install weasyprint")
        print("")
        print("📄 Genererar HTML-rapport istället...")

        # Fallback till HTML
        html_path = save_html_report(report_data, output_path.replace('.pdf', '.html') if output_path else None)
        print(f"✅ HTML-rapport sparad: {html_path}")
        print("   Öppna i webbläsare och använd 'Skriv ut' → 'Spara som PDF'")

        return html_path


def install_instructions():
    """Visar installationsinstruktioner för WeasyPrint"""
    print("""
╔══════════════════════════════════════════════════════════════╗
║  PDF-generering kräver WeasyPrint                            ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  Installation:                                               ║
║                                                              ║
║  macOS:                                                      ║
║    brew install pango libffi                                 ║
║    pip install weasyprint                                    ║
║                                                              ║
║  Windows:                                                    ║
║    pip install weasyprint                                    ║
║    (GTK+ runtime krävs - se weasyprint.org)                  ║
║                                                              ║
║  Linux (Ubuntu/Debian):                                      ║
║    sudo apt install libpango-1.0-0 libpangocairo-1.0-0       ║
║    pip install weasyprint                                    ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    # Test med dummy-data
    test_data = {
        'target_url': 'https://example.com',
        'timestamp': datetime.now().isoformat(),
        'total_score': 85,
        'rating': '🟢 UTMÄRKT SEO CRAWLBARHET',
        'tests_passed': 14,
        'tests_failed': 2,
        'test_results': [
            {'test_name': 'SEO Bot Accessibility', 'passed': True, 'details': 'Alla SEO-botar kan nå sidan', 'severity': 'INFO'},
            {'test_name': 'Robots.txt', 'passed': True, 'details': 'Korrekt konfigurerad', 'severity': 'INFO'},
            {'test_name': 'Protocol Consistency', 'passed': False, 'details': 'Problem med WWW redirect', 'severity': 'HIGH'},
        ],
        'seo_issues': ['WWW/non-WWW pekar på olika destinations'],
        'recommendations': ['  🔴 Fixa redirect-problemet', '  ⚠️ Lägg till sitemap']
    }

    print("Genererar test-rapport...")
    path = generate_pdf_report(test_data)
    print(f"Rapport sparad: {path}")
