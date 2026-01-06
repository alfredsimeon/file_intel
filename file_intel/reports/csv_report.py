"""
FILE-INTEL: CSV Report Generator
Export scan results to CSV format for spreadsheet analysis
"""

import csv
import logging
from pathlib import Path
from typing import List, Optional
from datetime import datetime
import io


class CSVReporter:
    """Generate CSV reports from scan results"""
    
    def __init__(self, config=None):
        self.logger = logging.getLogger(__name__)
        self.config = config
    
    def generate(
        self,
        results: List,
        output_path: Optional[str] = None,
        include_hashes: bool = True,
        include_indicators: bool = True
    ) -> str:
        """
        Generate CSV report from scan results
        
        Args:
            results: List of ScanResult objects
            output_path: Optional path to save report
            include_hashes: Include file hashes
            include_indicators: Include threat indicators
        
        Returns:
            CSV string
        """
        output = io.StringIO()
        
        # Define columns
        columns = [
            'File Name',
            'File Path',
            'File Size (bytes)',
            'Detected Type',
            'Category',
            'MIME Type',
            'Threat Level',
            'Threat Score',
            'Entropy',
            'Scan Duration (ms)'
        ]
        
        if include_hashes:
            columns.extend(['MD5', 'SHA1', 'SHA256'])
        
        if include_indicators:
            columns.extend(['Indicators', 'YARA Matches', 'Extension Mismatch'])
        
        columns.append('Scan Timestamp')
        
        writer = csv.writer(output)
        writer.writerow(columns)
        
        for result in results:
            row = [
                result.file_name,
                result.file_path,
                result.file_size,
                result.magic_result.detected_type if result.magic_result else 'Unknown',
                result.magic_result.category.value if result.magic_result else '',
                result.magic_result.mime_type if result.magic_result else '',
                result.threat_level.value,
                f"{result.threat_score:.1f}",
                f"{result.entropy_result.overall_entropy:.2f}" if result.entropy_result else '',
                f"{result.scan_duration_ms:.0f}"
            ]
            
            if include_hashes:
                if result.hash_result:
                    row.extend([
                        result.hash_result.md5,
                        result.hash_result.sha1,
                        result.hash_result.sha256
                    ])
                else:
                    row.extend(['', '', ''])
            
            if include_indicators:
                # Indicators (semicolon separated)
                indicators = '; '.join(result.threat_indicators[:5]) if result.threat_indicators else ''
                row.append(indicators)
                
                # YARA matches
                yara = '; '.join([m.get('rule', '') for m in result.yara_matches[:5]]) if result.yara_matches else ''
                row.append(yara)
                
                # Extension mismatch
                mismatch = result.extension_mismatch.get('message', '') if result.extension_mismatch else ''
                row.append(mismatch)
            
            row.append(result.scan_timestamp)
            
            writer.writerow(row)
        
        csv_str = output.getvalue()
        
        if output_path:
            try:
                with open(output_path, 'w', newline='', encoding='utf-8') as f:
                    f.write(csv_str)
                self.logger.info(f"CSV report saved to: {output_path}")
            except Exception as e:
                self.logger.error(f"Error saving CSV report: {e}")
        
        return csv_str
    
    def generate_summary_csv(self, results: List, output_path: Optional[str] = None) -> str:
        """Generate summary-only CSV"""
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Summary header
        writer.writerow(['FILE-INTEL Analysis Summary'])
        writer.writerow(['Generated', datetime.now().isoformat()])
        writer.writerow(['Total Files', len(results)])
        writer.writerow([])
        
        # Threat distribution
        writer.writerow(['Threat Distribution'])
        threat_counts = {}
        for result in results:
            level = result.threat_level.value
            threat_counts[level] = threat_counts.get(level, 0) + 1
        
        for level, count in sorted(threat_counts.items()):
            writer.writerow([level.upper(), count])
        
        writer.writerow([])
        
        # High-risk files
        high_risk = [r for r in results if r.threat_score >= 60]
        if high_risk:
            writer.writerow(['High-Risk Files'])
            writer.writerow(['File', 'Score', 'Type'])
            for r in high_risk:
                writer.writerow([
                    r.file_name,
                    f"{r.threat_score:.0f}",
                    r.magic_result.detected_type if r.magic_result else 'Unknown'
                ])
        
        csv_str = output.getvalue()
        
        if output_path:
            try:
                with open(output_path, 'w', newline='', encoding='utf-8') as f:
                    f.write(csv_str)
            except Exception as e:
                self.logger.error(f"Error saving summary CSV: {e}")
        
        return csv_str
