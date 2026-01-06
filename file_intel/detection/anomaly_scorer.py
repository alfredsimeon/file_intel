"""
FILE-INTEL: Anomaly Scoring Engine
Calculates comprehensive threat scores based on multiple indicators
"""

import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum


class ThreatCategory(Enum):
    """Categories of threats"""
    MALWARE = "malware"
    PACKED = "packed"
    OBFUSCATED = "obfuscated"
    DISGUISED = "disguised"
    EXPLOIT = "exploit"
    SUSPICIOUS = "suspicious"
    UNKNOWN = "unknown"


@dataclass
class AnomalyScore:
    """Comprehensive anomaly/threat score"""
    total_score: float  # 0-100
    threat_category: ThreatCategory
    confidence: float  # 0-1
    indicators: List[Dict[str, Any]]
    risk_summary: str
    detailed_breakdown: Dict[str, float]


class AnomalyScorer:
    """
    Calculates threat scores based on multiple analysis results
    """
    
    # Scoring weights for different indicators
    WEIGHTS = {
        'extension_mismatch': 30,
        'extension_mismatch_critical': 50,
        'high_entropy': 20,
        'very_high_entropy': 35,
        'executable_type': 15,
        'yara_match': 25,
        'yara_match_critical': 45,
        'virustotal_detection': 40,
        'polyglot': 25,
        'suspicious_strings': 15,
        'suspicious_imports': 20,
        'packer_detected': 20,
        'anomalous_structure': 15
    }
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def calculate_score(
        self,
        magic_result: Optional[Dict] = None,
        entropy_result: Optional[Dict] = None,
        extension_mismatch: Optional[Dict] = None,
        yara_matches: Optional[List] = None,
        virustotal_result: Optional[Dict] = None,
        polyglot_result: Optional[Dict] = None,
        additional_indicators: Optional[List[Dict]] = None
    ) -> AnomalyScore:
        """
        Calculate comprehensive anomaly score from all indicators
        
        Returns:
            AnomalyScore with detailed breakdown
        """
        score = 0.0
        indicators = []
        breakdown = {}
        
        # 1. Extension mismatch scoring
        if extension_mismatch and extension_mismatch.get('has_mismatch'):
            severity = extension_mismatch.get('severity', 'warning')
            if severity == 'critical':
                points = self.WEIGHTS['extension_mismatch_critical']
                indicators.append({
                    'type': 'extension_mismatch',
                    'severity': 'CRITICAL',
                    'points': points,
                    'description': extension_mismatch.get('message', 'Extension mismatch detected')
                })
            else:
                points = self.WEIGHTS['extension_mismatch']
                indicators.append({
                    'type': 'extension_mismatch',
                    'severity': 'WARNING',
                    'points': points,
                    'description': extension_mismatch.get('message', 'Extension mismatch')
                })
            score += points
            breakdown['extension_mismatch'] = points
        
        # 2. Entropy scoring
        if entropy_result:
            entropy_val = entropy_result.get('overall', 0)
            if entropy_val >= 7.8:
                points = self.WEIGHTS['very_high_entropy']
                indicators.append({
                    'type': 'entropy',
                    'severity': 'HIGH',
                    'points': points,
                    'description': f'Very high entropy ({entropy_val:.2f}) - likely encrypted/packed'
                })
                score += points
                breakdown['entropy'] = points
            elif entropy_val >= 7.0:
                points = self.WEIGHTS['high_entropy']
                indicators.append({
                    'type': 'entropy',
                    'severity': 'MEDIUM',
                    'points': points,
                    'description': f'High entropy ({entropy_val:.2f}) - possibly compressed/packed'
                })
                score += points
                breakdown['entropy'] = points
        
        # 3. File type scoring
        if magic_result:
            category = magic_result.get('category', '').lower()
            threat_level = magic_result.get('threat_level', 'safe').lower()
            
            if category == 'executable' or threat_level in ('high', 'critical'):
                points = self.WEIGHTS['executable_type']
                indicators.append({
                    'type': 'file_type',
                    'severity': 'INFO',
                    'points': points,
                    'description': f'Executable file type: {magic_result.get("detected_type", "unknown")}'
                })
                score += points
                breakdown['file_type'] = points
        
        # 4. YARA matches scoring
        if yara_matches:
            yara_points = 0
            for match in yara_matches:
                severity = match.get('severity', 'MEDIUM')
                rule = match.get('rule', 'unknown')
                
                if severity == 'CRITICAL':
                    match_points = self.WEIGHTS['yara_match_critical']
                else:
                    match_points = self.WEIGHTS['yara_match']
                
                yara_points += match_points
                indicators.append({
                    'type': 'yara_match',
                    'severity': severity,
                    'points': match_points,
                    'description': f'YARA rule match: {rule}'
                })
            
            score += min(yara_points, 80)  # Cap YARA contribution
            breakdown['yara_matches'] = min(yara_points, 80)
        
        # 5. VirusTotal scoring
        if virustotal_result:
            detections = virustotal_result.get('positives', 0)
            total = virustotal_result.get('total', 0)
            
            if detections > 0:
                # Scale based on detection ratio
                vt_points = min(50, detections * 2.5)
                indicators.append({
                    'type': 'virustotal',
                    'severity': 'CRITICAL' if detections > 10 else 'HIGH',
                    'points': vt_points,
                    'description': f'VirusTotal: {detections}/{total} engines detected threats'
                })
                score += vt_points
                breakdown['virustotal'] = vt_points
        
        # 6. Polyglot scoring
        if polyglot_result and polyglot_result.get('is_polyglot'):
            threat = polyglot_result.get('threat_level', 'MEDIUM')
            points = self.WEIGHTS['polyglot']
            indicators.append({
                'type': 'polyglot',
                'severity': threat,
                'points': points,
                'description': f'Polyglot file: {polyglot_result.get("description", "Multiple valid types")}'
            })
            score += points
            breakdown['polyglot'] = points
        
        # 7. Additional indicators
        if additional_indicators:
            for indicator in additional_indicators:
                ind_points = indicator.get('points', 10)
                score += ind_points
                indicators.append(indicator)
                breakdown[indicator.get('type', 'unknown')] = ind_points
        
        # Cap total score at 100
        total_score = min(100, score)
        
        # Determine threat category
        category = self._determine_category(indicators)
        
        # Calculate confidence
        confidence = self._calculate_confidence(indicators)
        
        # Generate risk summary
        summary = self._generate_summary(total_score, category, indicators)
        
        return AnomalyScore(
            total_score=total_score,
            threat_category=category,
            confidence=confidence,
            indicators=indicators,
            risk_summary=summary,
            detailed_breakdown=breakdown
        )
    
    def _determine_category(self, indicators: List[Dict]) -> ThreatCategory:
        """Determine primary threat category from indicators"""
        
        # Count indicator types
        type_counts = {}
        for ind in indicators:
            ind_type = ind.get('type', 'unknown')
            type_counts[ind_type] = type_counts.get(ind_type, 0) + 1
        
        # Check for specific categories
        has_yara = 'yara_match' in type_counts
        has_vt = 'virustotal' in type_counts
        has_mismatch = 'extension_mismatch' in type_counts
        has_entropy = 'entropy' in type_counts
        has_polyglot = 'polyglot' in type_counts
        
        if has_yara or has_vt:
            return ThreatCategory.MALWARE
        elif has_mismatch:
            return ThreatCategory.DISGUISED
        elif has_entropy:
            return ThreatCategory.PACKED
        elif has_polyglot:
            return ThreatCategory.SUSPICIOUS
        else:
            return ThreatCategory.UNKNOWN
    
    def _calculate_confidence(self, indicators: List[Dict]) -> float:
        """Calculate confidence in the assessment"""
        if not indicators:
            return 0.5
        
        # More indicators = higher confidence
        indicator_count = len(indicators)
        
        # High severity indicators boost confidence
        high_severity_count = sum(
            1 for ind in indicators 
            if ind.get('severity') in ('HIGH', 'CRITICAL')
        )
        
        base_confidence = min(0.5 + (indicator_count * 0.1), 0.8)
        severity_boost = min(high_severity_count * 0.1, 0.2)
        
        return min(base_confidence + severity_boost, 1.0)
    
    def _generate_summary(
        self, 
        score: float, 
        category: ThreatCategory, 
        indicators: List[Dict]
    ) -> str:
        """Generate human-readable risk summary"""
        
        if score >= 80:
            risk_level = "CRITICAL RISK"
        elif score >= 60:
            risk_level = "HIGH RISK"
        elif score >= 40:
            risk_level = "MEDIUM RISK"
        elif score >= 20:
            risk_level = "LOW RISK"
        else:
            risk_level = "MINIMAL RISK"
        
        summary_parts = [f"{risk_level} (Score: {score:.0f}/100)"]
        
        if category != ThreatCategory.UNKNOWN:
            summary_parts.append(f"Category: {category.value.upper()}")
        
        # Add top indicators
        top_indicators = sorted(indicators, key=lambda x: x.get('points', 0), reverse=True)[:3]
        if top_indicators:
            summary_parts.append("Key findings: " + "; ".join(
                ind.get('description', '')[:50] for ind in top_indicators
            ))
        
        return " | ".join(summary_parts)
    
    def get_risk_level(self, score: float) -> str:
        """Get risk level label from score"""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        elif score >= 20:
            return "LOW"
        else:
            return "SAFE"
    
    def get_recommendations(self, score: AnomalyScore) -> List[str]:
        """Generate recommendations based on anomaly score"""
        recommendations = []
        
        if score.total_score >= 80:
            recommendations.extend([
                "QUARANTINE this file immediately",
                "Do NOT execute or open under any circumstances",
                "Submit to sandbox for dynamic analysis",
                "Report to security operations center"
            ])
        elif score.total_score >= 60:
            recommendations.extend([
                "Treat this file with extreme caution",
                "Do not execute without thorough analysis",
                "Scan with multiple antivirus engines",
                "Consider submitting to VirusTotal for community analysis"
            ])
        elif score.total_score >= 40:
            recommendations.extend([
                "Verify the source of this file",
                "Scan with updated antivirus software",
                "Monitor system behavior if file is opened"
            ])
        elif score.total_score >= 20:
            recommendations.extend([
                "Some anomalies detected - verify file legitimacy",
                "Consider scanning with additional tools"
            ])
        else:
            recommendations.append("No significant threats detected")
        
        return recommendations
