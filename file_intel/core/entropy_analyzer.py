"""
FILE-INTEL: Entropy Analysis Engine
Detects packed, encrypted, and compressed content through entropy analysis
"""

import math
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class EntropyCategory(Enum):
    """Entropy classification categories"""
    LOW = "low"               # < 4.0 - Plain text, structured data
    MEDIUM = "medium"         # 4.0 - 6.0 - Mixed content, some compression
    HIGH = "high"             # 6.0 - 7.5 - Compressed data
    VERY_HIGH = "very_high"   # 7.5 - 8.0 - Encrypted/packed content
    MAXIMUM = "maximum"       # ~8.0 - Highly compressed or encrypted


@dataclass
class EntropyResult:
    """Result of entropy analysis"""
    overall_entropy: float
    category: EntropyCategory
    is_suspicious: bool
    suspicion_reason: str
    section_entropies: List[Dict]
    entropy_histogram: List[int]
    recommendations: List[str]


class EntropyAnalyzer:
    """
    Advanced entropy analysis for detecting packed/encrypted content
    Uses Shannon entropy calculation with section-by-section analysis
    """
    
    # Entropy thresholds
    THRESHOLD_LOW = 4.0
    THRESHOLD_MEDIUM = 6.0
    THRESHOLD_HIGH = 7.5
    THRESHOLD_VERY_HIGH = 7.9
    
    # Known packers/protectors entropy patterns
    KNOWN_PATTERNS = {
        'upx': (7.0, 7.8, "UPX Packed"),
        'themida': (7.5, 8.0, "Themida/WinLicense Protected"),
        'vmprotect': (7.6, 8.0, "VMProtect Protected"),
        'aspack': (7.2, 7.8, "ASPack Packed"),
        'pecompact': (7.3, 7.9, "PECompact Packed"),
        'nspack': (7.4, 7.9, "NSPack Packed"),
        'mpress': (7.2, 7.8, "MPRESS Packed"),
    }
    
    def __init__(self, chunk_size: int = 65536):
        self.logger = logging.getLogger(__name__)
        self.chunk_size = chunk_size
    
    def analyze(self, file_path: str, deep_scan: bool = True) -> Optional[EntropyResult]:
        """
        Perform comprehensive entropy analysis on a file
        
        Args:
            file_path: Path to file to analyze
            deep_scan: If True, analyze entire file in sections
        
        Returns:
            EntropyResult with analysis details
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            self.logger.error(f"File not found: {file_path}")
            return None
        
        try:
            file_size = file_path.stat().st_size
            
            if file_size == 0:
                return EntropyResult(
                    overall_entropy=0.0,
                    category=EntropyCategory.LOW,
                    is_suspicious=False,
                    suspicion_reason="",
                    section_entropies=[],
                    entropy_histogram=[0] * 256,
                    recommendations=[]
                )
            
            # Calculate overall entropy
            overall_entropy, histogram = self._calculate_file_entropy(file_path)
            
            # Calculate section entropies for deep scan
            section_entropies = []
            if deep_scan and file_size > self.chunk_size:
                section_entropies = self._analyze_sections(file_path, file_size)
            
            # Categorize entropy
            category = self._categorize_entropy(overall_entropy)
            
            # Check for suspicious patterns
            is_suspicious, suspicion_reason = self._check_suspicion(
                overall_entropy, section_entropies, file_size
            )
            
            # Generate recommendations
            recommendations = self._generate_recommendations(
                overall_entropy, category, is_suspicious, section_entropies
            )
            
            return EntropyResult(
                overall_entropy=overall_entropy,
                category=category,
                is_suspicious=is_suspicious,
                suspicion_reason=suspicion_reason,
                section_entropies=section_entropies,
                entropy_histogram=histogram,
                recommendations=recommendations
            )
            
        except PermissionError:
            self.logger.error(f"Permission denied: {file_path}")
            return None
        except Exception as e:
            self.logger.error(f"Error analyzing entropy: {e}")
            return None
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of byte data"""
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _calculate_file_entropy(self, file_path: Path) -> Tuple[float, List[int]]:
        """Calculate entropy of entire file"""
        byte_counts = [0] * 256
        total_bytes = 0
        
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break
                
                for byte in chunk:
                    byte_counts[byte] += 1
                total_bytes += len(chunk)
        
        if total_bytes == 0:
            return 0.0, [0] * 256
        
        entropy = 0.0
        for count in byte_counts:
            if count > 0:
                probability = count / total_bytes
                entropy -= probability * math.log2(probability)
        
        return entropy, byte_counts
    
    def _analyze_sections(self, file_path: Path, file_size: int) -> List[Dict]:
        """Analyze file in sections to find entropy anomalies"""
        sections = []
        num_sections = min(16, max(4, file_size // (self.chunk_size * 4)))
        section_size = file_size // num_sections
        
        with open(file_path, 'rb') as f:
            for i in range(num_sections):
                offset = i * section_size
                f.seek(offset)
                data = f.read(section_size)
                
                if data:
                    entropy = self._calculate_entropy(data)
                    sections.append({
                        'section_index': i,
                        'offset': offset,
                        'size': len(data),
                        'entropy': entropy,
                        'category': self._categorize_entropy(entropy).value
                    })
        
        return sections
    
    def _categorize_entropy(self, entropy: float) -> EntropyCategory:
        """Categorize entropy value"""
        if entropy < self.THRESHOLD_LOW:
            return EntropyCategory.LOW
        elif entropy < self.THRESHOLD_MEDIUM:
            return EntropyCategory.MEDIUM
        elif entropy < self.THRESHOLD_HIGH:
            return EntropyCategory.HIGH
        elif entropy < self.THRESHOLD_VERY_HIGH:
            return EntropyCategory.VERY_HIGH
        else:
            return EntropyCategory.MAXIMUM
    
    def _check_suspicion(
        self, 
        overall_entropy: float, 
        section_entropies: List[Dict],
        file_size: int
    ) -> Tuple[bool, str]:
        """Check for suspicious entropy patterns"""
        reasons = []
        
        # Check for very high overall entropy
        if overall_entropy >= self.THRESHOLD_HIGH:
            reasons.append(f"High overall entropy ({overall_entropy:.2f}) suggests packed/encrypted content")
        
        # Check for encrypted content (near maximum entropy)
        if overall_entropy >= 7.9:
            reasons.append("Near-maximum entropy indicates strong encryption or compression")
        
        # Check for section anomalies
        if section_entropies:
            high_entropy_sections = [s for s in section_entropies if s['entropy'] >= 7.5]
            low_entropy_sections = [s for s in section_entropies if s['entropy'] < 4.0]
            
            # Suspicious if most sections are high entropy
            if len(high_entropy_sections) > len(section_entropies) * 0.7:
                reasons.append(f"{len(high_entropy_sections)}/{len(section_entropies)} sections have high entropy")
            
            # Check for entropy variance (packed files often have uniform high entropy)
            entropies = [s['entropy'] for s in section_entropies]
            if entropies:
                entropy_variance = self._calculate_variance(entropies)
                
                # Very low variance with high entropy is suspicious
                if entropy_variance < 0.1 and overall_entropy > 7.0:
                    reasons.append("Uniform high entropy across sections (typical of packed/encrypted files)")
                
                # Sudden entropy spikes are suspicious
                for i in range(1, len(entropies)):
                    if entropies[i] - entropies[i-1] > 3.0:
                        reasons.append(f"Sudden entropy spike at section {i} (possible hidden payload)")
                        break
        
        is_suspicious = len(reasons) > 0
        suspicion_reason = "; ".join(reasons) if reasons else ""
        
        return is_suspicious, suspicion_reason
    
    def _calculate_variance(self, values: List[float]) -> float:
        """Calculate variance of a list of values"""
        if not values:
            return 0.0
        
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance
    
    def _generate_recommendations(
        self,
        overall_entropy: float,
        category: EntropyCategory,
        is_suspicious: bool,
        section_entropies: List[Dict]
    ) -> List[str]:
        """Generate analysis recommendations"""
        recommendations = []
        
        if category in (EntropyCategory.VERY_HIGH, EntropyCategory.MAXIMUM):
            recommendations.append("Submit to sandbox for dynamic analysis")
            recommendations.append("Check for known packer signatures")
            
            if overall_entropy > 7.8:
                recommendations.append("Consider memory forensics - file may be encrypted malware")
        
        if is_suspicious:
            recommendations.append("Perform YARA scan with packer/cryptor rules")
            recommendations.append("Examine file with hex editor for anomalies")
        
        if category == EntropyCategory.HIGH:
            recommendations.append("File may be compressed - attempt decompression")
        
        # Check section anomalies
        if section_entropies:
            low_sections = [s for s in section_entropies if s['entropy'] < 2.0]
            if low_sections:
                recommendations.append(
                    f"Section {low_sections[0]['section_index']} has very low entropy - may contain strings/resources"
                )
        
        return recommendations
    
    def get_entropy_description(self, entropy: float) -> str:
        """Get human-readable description of entropy value"""
        if entropy < 1.0:
            return "Extremely low - likely empty or repetitive data"
        elif entropy < 2.0:
            return "Very low - plain text or simple structure"
        elif entropy < 4.0:
            return "Low - structured data, source code, logs"
        elif entropy < 5.0:
            return "Medium-low - mixed content"
        elif entropy < 6.0:
            return "Medium - some compression or encoding"
        elif entropy < 7.0:
            return "Medium-high - compressed or encoded content"
        elif entropy < 7.5:
            return "High - heavily compressed content"
        elif entropy < 7.9:
            return "Very high - packed/encrypted content"
        else:
            return "Maximum - encrypted or random data"
    
    def is_likely_packed(self, entropy: float) -> bool:
        """Quick check if file is likely packed based on entropy"""
        return entropy >= 7.0
    
    def is_likely_encrypted(self, entropy: float) -> bool:
        """Quick check if file is likely encrypted based on entropy"""
        return entropy >= 7.8
