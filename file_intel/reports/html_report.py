"""
FILE-INTEL: HTML Report Generator
Generate professional HTML reports with vintage styling
"""

import logging
from pathlib import Path
from typing import List, Optional
from datetime import datetime


class HTMLReporter:
    """Generate styled HTML reports from scan results"""
    
    def __init__(self, config=None):
        self.logger = logging.getLogger(__name__)
        self.config = config
    
    def generate(
        self,
        results: List,
        output_path: Optional[str] = None,
        title: str = "FILE-INTEL Analysis Report"
    ) -> str:
        """
        Generate HTML report from scan results
        
        Args:
            results: List of ScanResult objects
            output_path: Optional path to save report
            title: Report title
        
        Returns:
            HTML string
        """
        # Calculate statistics
        stats = self._calculate_stats(results)
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Courier New', Courier, monospace;
            background: linear-gradient(135deg, #1e1a17 0%, #252220 100%);
            color: #c0b0a0;
            min-height: 100vh;
            padding: 40px;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        header {{
            text-align: center;
            padding: 40px;
            background: #252220;
            border: 2px solid #3a3530;
            border-radius: 10px;
            margin-bottom: 30px;
        }}
        h1 {{
            color: #d0c0b0;
            font-size: 2.5em;
            letter-spacing: 5px;
            margin-bottom: 10px;
        }}
        .subtitle {{
            color: #706050;
            font-size: 0.9em;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: #252220;
            border: 2px solid #3a3530;
            border-radius: 8px;
            padding: 25px;
            text-align: center;
        }}
        .stat-value {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        .stat-label {{
            color: #706050;
            font-size: 0.9em;
        }}
        .critical {{ color: #cc3333; }}
        .high {{ color: #cc6633; }}
        .medium {{ color: #ccaa33; }}
        .low {{ color: #66aa66; }}
        .safe {{ color: #4a8a4a; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #252220;
            border-radius: 8px;
            overflow: hidden;
            margin-bottom: 30px;
        }}
        th {{
            background: #2a2520;
            color: #a09080;
            padding: 15px;
            text-align: left;
            border-bottom: 2px solid #3a3530;
        }}
        td {{
            padding: 12px 15px;
            border-bottom: 1px solid #3a3530;
        }}
        tr:hover {{
            background: #2d2925;
        }}
        .threat-badge {{
            padding: 5px 12px;
            border-radius: 15px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        .threat-critical {{ background: #cc3333; color: white; }}
        .threat-high {{ background: #cc6633; color: white; }}
        .threat-medium {{ background: #ccaa33; color: #333; }}
        .threat-low {{ background: #66aa66; color: white; }}
        .threat-safe {{ background: #4a8a4a; color: white; }}
        .details-section {{
            background: #252220;
            border: 2px solid #3a3530;
            border-radius: 8px;
            padding: 25px;
            margin-bottom: 20px;
        }}
        .details-section h3 {{
            color: #d0c0b0;
            margin-bottom: 15px;
            border-bottom: 1px solid #3a3530;
            padding-bottom: 10px;
        }}
        .indicator {{
            background: #2a2520;
            padding: 10px 15px;
            border-left: 4px solid #cc6633;
            margin: 10px 0;
        }}
        .hash-value {{
            font-family: monospace;
            background: #1e1a17;
            padding: 5px 10px;
            border-radius: 3px;
            word-break: break-all;
        }}
        footer {{
            text-align: center;
            padding: 30px;
            color: #504030;
            border-top: 1px solid #3a3530;
            margin-top: 40px;
        }}
        @media (max-width: 768px) {{
            body {{ padding: 20px; }}
            h1 {{ font-size: 1.8em; }}
            .stats-grid {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>FILE-INTEL</h1>
            <p class="subtitle">Military-Grade File Analysis Report</p>
            <p class="subtitle">Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{stats['total']}</div>
                <div class="stat-label">Total Files</div>
            </div>
            <div class="stat-card">
                <div class="stat-value critical">{stats['critical']}</div>
                <div class="stat-label">Critical Threats</div>
            </div>
            <div class="stat-card">
                <div class="stat-value high">{stats['high']}</div>
                <div class="stat-label">High Risk</div>
            </div>
            <div class="stat-card">
                <div class="stat-value medium">{stats['medium']}</div>
                <div class="stat-label">Medium Risk</div>
            </div>
            <div class="stat-card">
                <div class="stat-value safe">{stats['safe'] + stats['low']}</div>
                <div class="stat-label">Clean Files</div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>File</th>
                    <th>Type</th>
                    <th>Size</th>
                    <th>Threat</th>
                    <th>Score</th>
                </tr>
            </thead>
            <tbody>
"""
        
        # Add table rows
        for result in results:
            type_name = result.magic_result.detected_type if result.magic_result else 'Unknown'
            threat_class = f"threat-{result.threat_level.value.lower()}"
            size = self._format_size(result.file_size)
            
            html += f"""                <tr>
                    <td title="{result.file_path}">{result.file_name}</td>
                    <td>{type_name[:25]}</td>
                    <td>{size}</td>
                    <td><span class="threat-badge {threat_class}">{result.threat_level.value.upper()}</span></td>
                    <td>{result.threat_score:.0f}</td>
                </tr>
"""
        
        html += """            </tbody>
        </table>
"""
        
        # Add detailed sections for high-threat files
        high_threats = [r for r in results if r.threat_score >= 60]
        if high_threats:
            html += """        <h2 style="color: #cc6633; margin: 30px 0 20px 0;">⚠ High-Risk File Details</h2>
"""
            for result in high_threats[:10]:
                html += self._generate_detail_section(result)
        
        html += f"""
        <footer>
            <p>FILE-INTEL v1.0.0 • Military-Grade File Type Identifier</p>
            <p>Report generated with {len(results)} file(s) analyzed</p>
        </footer>
    </div>
</body>
</html>"""
        
        if output_path:
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(html)
                self.logger.info(f"HTML report saved to: {output_path}")
            except Exception as e:
                self.logger.error(f"Error saving HTML report: {e}")
        
        return html
    
    def _calculate_stats(self, results: List) -> dict:
        """Calculate summary statistics"""
        stats = {
            'total': len(results),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'safe': 0
        }
        
        for result in results:
            level = result.threat_level.value.lower()
            stats[level] = stats.get(level, 0) + 1
        
        return stats
    
    def _format_size(self, size: int) -> str:
        """Format file size for display"""
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        elif size < 1024 * 1024 * 1024:
            return f"{size / (1024 * 1024):.1f} MB"
        else:
            return f"{size / (1024 * 1024 * 1024):.2f} GB"
    
    def _generate_detail_section(self, result) -> str:
        """Generate detailed section for a single result"""
        html = f"""        <div class="details-section">
            <h3>{result.file_name}</h3>
            <p><strong>Path:</strong> {result.file_path}</p>
            <p><strong>Size:</strong> {self._format_size(result.file_size)}</p>
"""
        
        if result.magic_result:
            html += f"""            <p><strong>Detected Type:</strong> {result.magic_result.detected_type}</p>
            <p><strong>Category:</strong> {result.magic_result.category.value}</p>
"""
        
        if result.hash_result:
            html += f"""            <p><strong>SHA256:</strong> <span class="hash-value">{result.hash_result.sha256}</span></p>
"""
        
        if result.threat_indicators:
            html += """            <h4 style="margin-top: 15px; color: #cc6633;">Threat Indicators:</h4>
"""
            for indicator in result.threat_indicators[:5]:
                html += f"""            <div class="indicator">{indicator}</div>
"""
        
        html += """        </div>
"""
        return html
