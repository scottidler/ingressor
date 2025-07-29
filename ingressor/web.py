"""Web dashboard HTML generation for ingressor."""

from typing import List
from datetime import datetime

from .models import DomainInfo, ServiceSummary


def generate_dashboard_html(domains: List[DomainInfo], summary: ServiceSummary) -> str:
    """Generate HTML dashboard showing discovered domains."""
    
    # Group domains by environment
    by_env = {}
    for domain in domains:
        env = domain.environment
        if env not in by_env:
            by_env[env] = []
        by_env[env].append(domain)
    
    # Sort domains within each environment
    for env in by_env:
        by_env[env].sort(key=lambda x: x.domain)
    
    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ingressor - Service Discovery Dashboard</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        
        .header {{
            text-align: center;
            color: white;
            margin-bottom: 30px;
        }}
        
        .header h1 {{
            font-size: 2.5rem;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        
        .header p {{
            font-size: 1.1rem;
            opacity: 0.9;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: white;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }}
        
        .stat-card:hover {{
            transform: translateY(-2px);
        }}
        
        .stat-number {{
            font-size: 2rem;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 5px;
        }}
        
        .stat-label {{
            color: #666;
            font-size: 0.9rem;
        }}
        
        .controls {{
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .filter-buttons {{
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-bottom: 15px;
        }}
        
        .filter-btn {{
            padding: 8px 16px;
            border: 2px solid #667eea;
            background: white;
            color: #667eea;
            border-radius: 20px;
            cursor: pointer;
            transition: all 0.2s;
            font-size: 0.9rem;
        }}
        
        .filter-btn:hover, .filter-btn.active {{
            background: #667eea;
            color: white;
        }}
        
        .search-box {{
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 1rem;
            transition: border-color 0.2s;
        }}
        
        .search-box:focus {{
            outline: none;
            border-color: #667eea;
        }}
        
        .env-section {{
            background: white;
            border-radius: 10px;
            margin-bottom: 20px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .env-header {{
            background: #667eea;
            color: white;
            padding: 15px 20px;
            font-size: 1.2rem;
            font-weight: bold;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .env-count {{
            background: rgba(255,255,255,0.2);
            padding: 4px 12px;
            border-radius: 15px;
            font-size: 0.9rem;
        }}
        
        .domains-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 15px;
            padding: 20px;
        }}
        
        .domain-card {{
            border: 1px solid #e1e5e9;
            border-radius: 8px;
            padding: 15px;
            transition: all 0.2s;
            position: relative;
        }}
        
        .domain-card:hover {{
            border-color: #667eea;
            box-shadow: 0 2px 8px rgba(102, 126, 234, 0.15);
        }}
        
        .domain-link {{
            color: #667eea;
            text-decoration: none;
            font-weight: 600;
            font-size: 1rem;
            display: block;
            margin-bottom: 8px;
        }}
        
        .domain-link:hover {{
            text-decoration: underline;
        }}
        
        .domain-meta {{
            font-size: 0.85rem;
            color: #666;
            line-height: 1.4;
        }}
        
        .domain-meta div {{
            margin-bottom: 3px;
        }}
        
        .tls-badge {{
            position: absolute;
            top: 10px;
            right: 10px;
            background: #10b981;
            color: white;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.7rem;
            font-weight: bold;
        }}
        
        .no-results {{
            text-align: center;
            padding: 40px;
            color: #666;
            font-size: 1.1rem;
        }}
        
        .last-scan {{
            text-align: center;
            color: white;
            opacity: 0.8;
            margin-top: 20px;
            font-size: 0.9rem;
        }}
        
        .hidden {{
            display: none !important;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Ingressor</h1>
            <p>Multi-cluster Kubernetes Service Discovery</p>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{summary.total_domains}</div>
                <div class="stat-label">Total Domains</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(summary.by_environment)}</div>
                <div class="stat-label">Environments</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(summary.by_cluster)}</div>
                <div class="stat-label">Clusters</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(summary.by_namespace)}</div>
                <div class="stat-label">Namespaces</div>
            </div>
        </div>
        
        <div class="controls">
            <div class="filter-buttons">
                <button class="filter-btn active" onclick="filterEnvironment('all')">All Environments</button>
                {generate_env_filter_buttons(summary.by_environment.keys())}
            </div>
            <input type="text" class="search-box" placeholder="Search domains..." 
                   oninput="filterDomains(this.value)">
        </div>
        
        <div id="domains-container">
            {generate_environment_sections(by_env)}
        </div>
        
        <div class="no-results hidden" id="no-results">
            <p>No domains found matching your criteria.</p>
        </div>
        
        <div class="last-scan">
            Last scan: {summary.last_scan.strftime('%Y-%m-%d %H:%M:%S UTC') if summary.last_scan else 'Never'}
        </div>
    </div>
    
    <script>
        let currentFilter = 'all';
        let currentSearch = '';
        
        function filterEnvironment(env) {{
            currentFilter = env;
            
            // Update button states
            document.querySelectorAll('.filter-btn').forEach(btn => {{
                btn.classList.remove('active');
            }});
            event.target.classList.add('active');
            
            applyFilters();
        }}
        
        function filterDomains(searchTerm) {{
            currentSearch = searchTerm.toLowerCase();
            applyFilters();
        }}
        
        function applyFilters() {{
            const sections = document.querySelectorAll('.env-section');
            let visibleCount = 0;
            
            sections.forEach(section => {{
                const envName = section.dataset.env;
                const shouldShowEnv = currentFilter === 'all' || currentFilter === envName;
                
                if (!shouldShowEnv) {{
                    section.classList.add('hidden');
                    return;
                }}
                
                const domainCards = section.querySelectorAll('.domain-card');
                let visibleInSection = 0;
                
                domainCards.forEach(card => {{
                    const domainText = card.textContent.toLowerCase();
                    const shouldShow = domainText.includes(currentSearch);
                    
                    if (shouldShow) {{
                        card.classList.remove('hidden');
                        visibleInSection++;
                        visibleCount++;
                    }} else {{
                        card.classList.add('hidden');
                    }}
                }});
                
                if (visibleInSection > 0) {{
                    section.classList.remove('hidden');
                }} else {{
                    section.classList.add('hidden');
                }}
            }});
            
            // Show/hide no results message
            const noResults = document.getElementById('no-results');
            if (visibleCount === 0) {{
                noResults.classList.remove('hidden');
            }} else {{
                noResults.classList.add('hidden');
            }}
        }}
        
        // Auto-refresh every 5 minutes
        setTimeout(() => {{
            location.reload();
        }}, 300000);
    </script>
</body>
</html>
"""
    
    return html


def generate_env_filter_buttons(environments: List[str]) -> str:
    """Generate filter buttons for each environment."""
    buttons = []
    for env in sorted(environments):
        buttons.append(f'<button class="filter-btn" onclick="filterEnvironment(\'{env}\')">{env.title()}</button>')
    return '\n                '.join(buttons)


def generate_environment_sections(by_env: dict) -> str:
    """Generate HTML sections for each environment."""
    sections = []
    
    for env in sorted(by_env.keys()):
        domains = by_env[env]
        domain_cards = []
        
        for domain in domains:
            tls_badge = '<div class="tls-badge">TLS</div>' if domain.tls_enabled else ''
            
            card = f"""
                <div class="domain-card">
                    {tls_badge}
                    <a href="https://{domain.domain}" target="_blank" class="domain-link">
                        {domain.domain}
                    </a>
                    <div class="domain-meta">
                        <div><strong>Cluster:</strong> {domain.cluster}</div>
                        <div><strong>Namespace:</strong> {domain.namespace}</div>
                        <div><strong>Type:</strong> {domain.resource_type}</div>
                        {f'<div><strong>Service:</strong> {domain.service_name}</div>' if domain.service_name else ''}
                        {f'<div><strong>Ingress:</strong> {domain.ingress_name}</div>' if domain.ingress_name else ''}
                    </div>
                </div>
            """
            domain_cards.append(card)
        
        section = f"""
            <div class="env-section" data-env="{env}">
                <div class="env-header">
                    <span>{env.title()} Environment</span>
                    <span class="env-count">{len(domains)}</span>
                </div>
                <div class="domains-grid">
                    {''.join(domain_cards)}
                </div>
            </div>
        """
        sections.append(section)
    
    return '\n        '.join(sections) 