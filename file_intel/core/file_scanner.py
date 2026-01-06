"""
FILE-INTEL: Main File Scanner
Orchestrates all analysis modules for comprehensive file analysis
"""

import os
import logging
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import json

from .magic_detector import MagicDetector, FileTypeResult, ThreatLevel, FileCategory
from .entropy_analyzer import EntropyAnalyzer, EntropyResult
from .hash_generator import HashGenerator, HashResult


@dataclass
class ScanResult:
    """Comprehensive scan result for a file"""
    # Basic info
    file_path: str
    file_name: str
    file_size: int
    scan_timestamp: str
    scan_duration_ms: float
    
    # Type detection
    magic_result: Optional[FileTypeResult] = None
    extension_mismatch: Optional[Dict] = None
    
    # Entropy analysis
    entropy_result: Optional[EntropyResult] = None
    
    # Hash values
    hash_result: Optional[HashResult] = None
    
    # YARA matches
    yara_matches: List[Dict] = field(default_factory=list)
    
    # Threat intelligence
    virustotal_result: Optional[Dict] = None
    malwarebazaar_result: Optional[Dict] = None
    urlhaus_matches: List[str] = field(default_factory=list)
    
    # Overall assessment
    threat_score: float = 0.0
    threat_level: ThreatLevel = ThreatLevel.SAFE
    threat_indicators: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    # Errors
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for serialization"""
        result = {
            'file_path': self.file_path,
            'file_name': self.file_name,
            'file_size': self.file_size,
            'scan_timestamp': self.scan_timestamp,
            'scan_duration_ms': self.scan_duration_ms,
            'threat_score': self.threat_score,
            'threat_level': self.threat_level.value,
            'threat_indicators': self.threat_indicators,
            'recommendations': self.recommendations,
            'errors': self.errors
        }
        
        if self.magic_result:
            result['detected_type'] = {
                'type': self.magic_result.detected_type,
                'extension': self.magic_result.extension,
                'category': self.magic_result.category.value,
                'mime_type': self.magic_result.mime_type,
                'confidence': self.magic_result.confidence,
                'description': self.magic_result.description
            }
        
        if self.extension_mismatch:
            result['extension_mismatch'] = self.extension_mismatch
        
        if self.entropy_result:
            result['entropy'] = {
                'overall': self.entropy_result.overall_entropy,
                'category': self.entropy_result.category.value,
                'is_suspicious': self.entropy_result.is_suspicious,
                'suspicion_reason': self.entropy_result.suspicion_reason
            }
        
        if self.hash_result:
            result['hashes'] = {
                'md5': self.hash_result.md5,
                'sha1': self.hash_result.sha1,
                'sha256': self.hash_result.sha256,
                'sha512': self.hash_result.sha512
            }
            if self.hash_result.ssdeep:
                result['hashes']['ssdeep'] = self.hash_result.ssdeep
            if self.hash_result.imphash:
                result['hashes']['imphash'] = self.hash_result.imphash
        
        if self.yara_matches:
            result['yara_matches'] = self.yara_matches
        
        if self.virustotal_result:
            result['virustotal'] = self.virustotal_result
        
        if self.malwarebazaar_result:
            result['malwarebazaar'] = self.malwarebazaar_result
        
        if self.urlhaus_matches:
            result['urlhaus_matches'] = self.urlhaus_matches
        
        return result
    
    def to_json(self, indent: int = 2) -> str:
        """Convert result to JSON string"""
        return json.dumps(self.to_dict(), indent=indent)


class FileScanner:
    """
    Main file scanning engine that orchestrates all analysis modules
    """
    
    def __init__(self, config=None):
        self.logger = logging.getLogger(__name__)
        self.config = config
        
        # Initialize analysis modules
        self.magic_detector = MagicDetector()
        self.entropy_analyzer = EntropyAnalyzer()
        self.hash_generator = HashGenerator()
        
        # Optional modules (lazy loaded)
        self._yara_scanner = None
        self._virustotal_client = None
        self._malwarebazaar_client = None
        self._urlhaus_db = None
        
        # Callbacks for progress reporting
        self._progress_callback: Optional[Callable] = None
        self._cancel_flag = threading.Event()
        
        self.logger.info("FileScanner initialized")
    
    def set_progress_callback(self, callback: Callable[[str, float], None]) -> None:
        """Set callback for progress updates: callback(message, progress_percent)"""
        self._progress_callback = callback
    
    def cancel_scan(self) -> None:
        """Cancel ongoing scan"""
        self._cancel_flag.set()
    
    def reset_cancel(self) -> None:
        """Reset cancel flag for new scan"""
        self._cancel_flag.clear()
    
    @property
    def yara_scanner(self):
        """Lazy load YARA scanner"""
        if self._yara_scanner is None:
            try:
                from ..detection.yara_scanner import YaraScanner
                self._yara_scanner = YaraScanner(self.config)
            except Exception as e:
                self.logger.warning(f"Could not load YARA scanner: {e}")
        return self._yara_scanner
    
    @property
    def virustotal_client(self):
        """Lazy load VirusTotal client"""
        if self._virustotal_client is None:
            try:
                from ..intel.virustotal import VirusTotalClient
                self._virustotal_client = VirusTotalClient(self.config)
            except Exception as e:
                self.logger.warning(f"Could not load VirusTotal client: {e}")
        return self._virustotal_client
    
    @property
    def urlhaus_db(self):
        """Lazy load URLhaus database"""
        if self._urlhaus_db is None:
            try:
                from ..intel.urlhaus import URLhausDatabase
                self._urlhaus_db = URLhausDatabase(self.config)
            except Exception as e:
                self.logger.warning(f"Could not load URLhaus database: {e}")
        return self._urlhaus_db
    
    def scan_file(
        self,
        file_path: str,
        deep_scan: bool = True,
        enable_yara: bool = True,
        enable_threat_intel: bool = False,
        enable_online_lookup: bool = False
    ) -> ScanResult:
        """
        Perform comprehensive scan of a single file
        
        Args:
            file_path: Path to file to scan
            deep_scan: Enable thorough analysis
            enable_yara: Run YARA rules
            enable_threat_intel: Check threat intelligence databases
            enable_online_lookup: Query online APIs (VirusTotal, etc.)
        
        Returns:
            ScanResult with all analysis data
        """
        start_time = datetime.now()
        file_path = Path(file_path)
        
        # Initialize result
        result = ScanResult(
            file_path=str(file_path.absolute()),
            file_name=file_path.name,
            file_size=0,
            scan_timestamp=start_time.isoformat(),
            scan_duration_ms=0.0
        )
        
        # Check file exists
        if not file_path.exists():
            result.errors.append(f"File not found: {file_path}")
            return result
        
        try:
            result.file_size = file_path.stat().st_size
        except Exception as e:
            result.errors.append(f"Could not get file size: {e}")
        
        # Report progress
        self._report_progress(f"Analyzing {file_path.name}...", 0)
        
        # 1. Magic number detection
        self._report_progress("Detecting file type...", 10)
        try:
            result.magic_result = self.magic_detector.detect(str(file_path), deep_scan)
            
            # Check for extension mismatch
            if result.magic_result:
                result.extension_mismatch = self.magic_detector.get_extension_mismatch(
                    str(file_path), result.magic_result
                )
        except Exception as e:
            result.errors.append(f"Magic detection failed: {e}")
        
        # Check for cancellation
        if self._cancel_flag.is_set():
            result.errors.append("Scan cancelled")
            return self._finalize_result(result, start_time)
        
        # 2. Entropy analysis
        self._report_progress("Analyzing entropy...", 25)
        try:
            result.entropy_result = self.entropy_analyzer.analyze(str(file_path), deep_scan)
        except Exception as e:
            result.errors.append(f"Entropy analysis failed: {e}")
        
        # 3. Hash generation
        self._report_progress("Generating hashes...", 40)
        try:
            result.hash_result = self.hash_generator.generate_hashes(str(file_path))
        except Exception as e:
            result.errors.append(f"Hash generation failed: {e}")
        
        # Check for cancellation
        if self._cancel_flag.is_set():
            result.errors.append("Scan cancelled")
            return self._finalize_result(result, start_time)
        
        # 4. YARA scanning
        if enable_yara and self.yara_scanner:
            self._report_progress("Running YARA rules...", 55)
            try:
                yara_matches = self.yara_scanner.scan_file(str(file_path))
                result.yara_matches = yara_matches
            except Exception as e:
                result.errors.append(f"YARA scan failed: {e}")
        
        # 5. Threat intelligence lookup
        if enable_threat_intel and self.urlhaus_db:
            self._report_progress("Checking threat intelligence...", 70)
            try:
                # Check file for embedded URLs
                # This would scan document content for known malicious URLs
                pass
            except Exception as e:
                result.errors.append(f"Threat intel check failed: {e}")
        
        # 6. Online lookups (if enabled and hash available)
        if enable_online_lookup and result.hash_result:
            self._report_progress("Querying online databases...", 85)
            
            if self.virustotal_client:
                try:
                    vt_result = self.virustotal_client.lookup_hash(result.hash_result.sha256)
                    result.virustotal_result = vt_result
                except Exception as e:
                    result.errors.append(f"VirusTotal lookup failed: {e}")
        
        # 7. Calculate threat score
        self._report_progress("Calculating threat assessment...", 95)
        self._calculate_threat_score(result)
        
        # Finalize
        self._report_progress("Analysis complete", 100)
        return self._finalize_result(result, start_time)
    
    def scan_directory(
        self,
        directory_path: str,
        recursive: bool = True,
        max_files: Optional[int] = None,
        file_extensions: Optional[List[str]] = None,
        **scan_options
    ) -> List[ScanResult]:
        """
        Scan all files in a directory
        
        Args:
            directory_path: Path to directory
            recursive: Scan subdirectories
            max_files: Maximum number of files to scan
            file_extensions: Only scan files with these extensions (None = all)
            **scan_options: Options passed to scan_file
        
        Returns:
            List of ScanResult for each file
        """
        directory_path = Path(directory_path)
        results = []
        
        if not directory_path.exists():
            self.logger.error(f"Directory not found: {directory_path}")
            return results
        
        # Collect files to scan
        files_to_scan = []
        
        if recursive:
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    file_path = Path(root) / file
                    if file_extensions:
                        if file_path.suffix.lower().lstrip('.') in file_extensions:
                            files_to_scan.append(file_path)
                    else:
                        files_to_scan.append(file_path)
        else:
            for item in directory_path.iterdir():
                if item.is_file():
                    if file_extensions:
                        if item.suffix.lower().lstrip('.') in file_extensions:
                            files_to_scan.append(item)
                    else:
                        files_to_scan.append(item)
        
        # Limit files if specified
        if max_files:
            files_to_scan = files_to_scan[:max_files]
        
        total_files = len(files_to_scan)
        self.logger.info(f"Scanning {total_files} files in {directory_path}")
        
        # Scan files
        for i, file_path in enumerate(files_to_scan):
            if self._cancel_flag.is_set():
                self.logger.info("Directory scan cancelled")
                break
            
            progress = (i / total_files) * 100
            self._report_progress(f"Scanning {file_path.name} ({i+1}/{total_files})", progress)
            
            try:
                result = self.scan_file(str(file_path), **scan_options)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Error scanning {file_path}: {e}")
                results.append(ScanResult(
                    file_path=str(file_path),
                    file_name=file_path.name,
                    file_size=0,
                    scan_timestamp=datetime.now().isoformat(),
                    scan_duration_ms=0,
                    errors=[str(e)]
                ))
        
        self._report_progress("Directory scan complete", 100)
        return results
    
    def scan_directory_parallel(
        self,
        directory_path: str,
        max_workers: int = 4,
        **scan_options
    ) -> List[ScanResult]:
        """
        Scan directory using parallel processing for speed
        """
        directory_path = Path(directory_path)
        results = []
        
        if not directory_path.exists():
            return results
        
        # Collect all files
        files_to_scan = list(directory_path.rglob('*'))
        files_to_scan = [f for f in files_to_scan if f.is_file()]
        
        total_files = len(files_to_scan)
        completed = 0
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self.scan_file, str(f), **scan_options): f 
                for f in files_to_scan
            }
            
            for future in as_completed(futures):
                if self._cancel_flag.is_set():
                    break
                
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    file_path = futures[future]
                    self.logger.error(f"Error scanning {file_path}: {e}")
                
                completed += 1
                progress = (completed / total_files) * 100
                self._report_progress(f"Completed {completed}/{total_files}", progress)
        
        return results
    
    def _calculate_threat_score(self, result: ScanResult) -> None:
        """Calculate overall threat score based on all indicators"""
        score = 0.0
        indicators = []
        
        # Extension mismatch (major indicator)
        if result.extension_mismatch:
            if result.extension_mismatch.get('severity') == 'CRITICAL':
                score += 40
                indicators.append(f"CRITICAL: {result.extension_mismatch.get('message')}")
            else:
                score += 20
                indicators.append(f"WARNING: {result.extension_mismatch.get('message')}")
        
        # Magic result threat level
        if result.magic_result:
            threat_scores = {
                ThreatLevel.SAFE: 0,
                ThreatLevel.LOW: 5,
                ThreatLevel.MEDIUM: 15,
                ThreatLevel.HIGH: 30,
                ThreatLevel.CRITICAL: 50
            }
            threat_add = threat_scores.get(result.magic_result.threat_level, 0)
            if threat_add > 10:
                score += threat_add
                indicators.append(f"File type {result.magic_result.detected_type} has {result.magic_result.threat_level.value} threat level")
        
        # Entropy analysis
        if result.entropy_result:
            if result.entropy_result.is_suspicious:
                score += 25
                indicators.append(f"Suspicious entropy: {result.entropy_result.suspicion_reason}")
            elif result.entropy_result.overall_entropy >= 7.5:
                score += 15
                indicators.append(f"High entropy ({result.entropy_result.overall_entropy:.2f}) - possible packed/encrypted content")
        
        # YARA matches
        if result.yara_matches:
            for match in result.yara_matches:
                rule_name = match.get('rule', 'Unknown')
                
                # Higher score for APT/malware rules
                if 'APT' in rule_name.upper() or 'MALW' in rule_name.upper():
                    score += 40
                    indicators.append(f"YARA match: {rule_name} (high severity)")
                elif 'RANSOM' in rule_name.upper():
                    score += 50
                    indicators.append(f"YARA match: {rule_name} (ransomware indicator)")
                else:
                    score += 20
                    indicators.append(f"YARA match: {rule_name}")
        
        # VirusTotal results
        if result.virustotal_result:
            detections = result.virustotal_result.get('positives', 0)
            if detections > 0:
                score += min(50, detections * 3)
                indicators.append(f"VirusTotal: {detections} detections")
        
        # Cap score at 100
        result.threat_score = min(100, score)
        result.threat_indicators = indicators
        
        # Determine threat level
        if result.threat_score >= 80:
            result.threat_level = ThreatLevel.CRITICAL
        elif result.threat_score >= 60:
            result.threat_level = ThreatLevel.HIGH
        elif result.threat_score >= 40:
            result.threat_level = ThreatLevel.MEDIUM
        elif result.threat_score >= 20:
            result.threat_level = ThreatLevel.LOW
        else:
            result.threat_level = ThreatLevel.SAFE
        
        # Generate recommendations
        result.recommendations = self._generate_recommendations(result)
    
    def _generate_recommendations(self, result: ScanResult) -> List[str]:
        """Generate actionable recommendations based on scan results"""
        recommendations = []
        
        if result.threat_level in (ThreatLevel.CRITICAL, ThreatLevel.HIGH):
            recommendations.append("QUARANTINE: Isolate this file immediately")
            recommendations.append("Do not execute or open this file")
            recommendations.append("Submit to sandbox for dynamic analysis")
        
        if result.extension_mismatch:
            recommendations.append("Verify file source and intended purpose")
            recommendations.append(f"Rename file to correct extension (.{result.magic_result.extension})")
        
        if result.entropy_result and result.entropy_result.is_suspicious:
            recommendations.extend(result.entropy_result.recommendations)
        
        if result.yara_matches:
            recommendations.append("Run through additional malware analysis tools")
            recommendations.append("Check file hash against threat intelligence feeds")
        
        if not recommendations and result.threat_level == ThreatLevel.SAFE:
            recommendations.append("No immediate threats detected")
        
        return recommendations
    
    def _report_progress(self, message: str, progress: float) -> None:
        """Report progress to callback if set"""
        if self._progress_callback:
            try:
                self._progress_callback(message, progress)
            except Exception:
                pass
    
    def _finalize_result(self, result: ScanResult, start_time: datetime) -> ScanResult:
        """Finalize scan result with timing"""
        end_time = datetime.now()
        result.scan_duration_ms = (end_time - start_time).total_seconds() * 1000
        return result
