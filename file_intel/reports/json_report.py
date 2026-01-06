"""
FILE-INTEL: JSON Report Generator
Export scan results to JSON format
"""

import json
import logging
from pathlib import Path
from typing import List, Optional
from datetime import datetime


class JSONReporter:
    """Generate JSON reports from scan results"""
    
    def __init__(self, config=None):
        self.logger = logging.getLogger(__name__)
        self.config = config
    
    def generate(
        self,
        results: List,
        output_path: Optional[str] = None,
        indent: int = 2,
        include_all: bool = True
    ) -> str:
        """
        Generate JSON report from scan results
        
        Args:
            results: List of ScanResult objects
            output_path: Optional path to save report
            indent: JSON indentation level
            include_all: Include all details or summary only
        
        Returns:
            JSON string
        """
        report_data = {
            'report_info': {
                'generated_at': datetime.now().isoformat(),
                'tool': 'FILE-INTEL',
                'version': '1.0.0',
                'total_files': len(results)
            },
            'summary': self._generate_summary(results),
            'results': []
        }
        
        for result in results:
            if include_all:
                report_data['results'].append(result.to_dict())
            else:
                # Minimal summary
                report_data['results'].append({
                    'file_name': result.file_name,
                    'file_path': result.file_path,
                    'threat_score': result.threat_score,
                    'threat_level': result.threat_level.value,
                    'detected_type': result.magic_result.detected_type if result.magic_result else 'Unknown'
                })
        
        json_str = json.dumps(report_data, indent=indent, default=str)
        
        if output_path:
            try:
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(json_str)
                self.logger.info(f"JSON report saved to: {output_path}")
            except Exception as e:
                self.logger.error(f"Error saving JSON report: {e}")
        
        return json_str
    
    def _generate_summary(self, results: List) -> dict:
        """Generate summary statistics"""
        if not results:
            return {}
        
        threat_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'safe': 0
        }
        
        total_size = 0
        types_found = {}
        
        for result in results:
            level = result.threat_level.value.lower()
            threat_counts[level] = threat_counts.get(level, 0) + 1
            total_size += result.file_size
            
            if result.magic_result:
                cat = result.magic_result.category.value
                types_found[cat] = types_found.get(cat, 0) + 1
        
        return {
            'threat_distribution': threat_counts,
            'files_by_type': types_found,
            'total_size_bytes': total_size,
            'highest_threat_score': max(r.threat_score for r in results) if results else 0,
            'average_threat_score': sum(r.threat_score for r in results) / len(results) if results else 0
        }
