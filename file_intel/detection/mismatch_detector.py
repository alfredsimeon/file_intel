"""
FILE-INTEL: Extension Mismatch Detector
Detects files where extension doesn't match actual content type
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum


class MismatchSeverity(Enum):
    """Severity levels for extension mismatches"""
    INFO = "info"           # Different but related (jpg vs jpeg)
    WARNING = "warning"     # Different type but not executable
    HIGH = "high"           # Could be masquerading
    CRITICAL = "critical"   # Executable disguised as non-executable


@dataclass
class MismatchResult:
    """Result of mismatch detection"""
    has_mismatch: bool
    actual_extension: str
    expected_extension: str
    detected_type: str
    severity: MismatchSeverity
    message: str
    is_executable_disguise: bool
    recommendations: List[str]


class MismatchDetector:
    """
    Detects extension mismatches and potential file masquerading
    """
    
    # Extension equivalence groups (these are considered matches)
    EQUIVALENT_EXTENSIONS = {
        frozenset(['jpg', 'jpeg', 'jpe']): 'JPEG Image',
        frozenset(['tif', 'tiff']): 'TIFF Image',
        frozenset(['htm', 'html']): 'HTML Document',
        frozenset(['doc', 'dot']): 'Word Document',
        frozenset(['xls', 'xlt']): 'Excel Document',
        frozenset(['ppt', 'pps']): 'PowerPoint Document',
        frozenset(['docx', 'docm']): 'Word OOXML',
        frozenset(['xlsx', 'xlsm']): 'Excel OOXML',
        frozenset(['pptx', 'pptm']): 'PowerPoint OOXML',
        frozenset(['tar.gz', 'tgz']): 'Gzipped TAR',
        frozenset(['tar.bz2', 'tbz2', 'tbz']): 'Bzipped TAR',
        frozenset(['tar.xz', 'txz']): 'XZ TAR',
        frozenset(['mp3', 'mp3']): 'MP3 Audio',
        frozenset(['mp4', 'm4v', 'm4a']): 'MP4 Container',
        frozenset(['mpeg', 'mpg', 'mpe']): 'MPEG Video',
    }
    
    # Executable extensions that pose high risk
    EXECUTABLE_EXTENSIONS = {
        'exe', 'dll', 'scr', 'com', 'pif', 'bat', 'cmd', 'ps1',
        'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'msc', 'hta',
        'cpl', 'msi', 'msp', 'jar', 'py', 'pyw', 'sh', 'bash',
        'elf', 'bin', 'run', 'app', 'deb', 'rpm', 'apk'
    }
    
    # Non-executable extensions commonly used to disguise malware
    COMMON_DISGUISE_EXTENSIONS = {
        'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'ico',
        'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'txt', 'rtf', 'csv', 'log', 'xml', 'json',
        'mp3', 'mp4', 'avi', 'mkv', 'wav', 'flac',
        'zip', 'rar', '7z', 'tar', 'gz'
    }
    
    # Double extension tricks
    DOUBLE_EXTENSION_PATTERNS = [
        ('.pdf.exe', 'PDF disguised as executable'),
        ('.doc.exe', 'Word document disguised as executable'),
        ('.jpg.exe', 'Image disguised as executable'),
        ('.txt.exe', 'Text file disguised as executable'),
        ('.mp3.scr', 'Audio disguised as screensaver'),
        ('.pdf.scr', 'PDF disguised as screensaver'),
        ('.doc.scr', 'Document disguised as screensaver'),
    ]
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def detect(
        self, 
        file_path: str, 
        detected_type: str,
        detected_extension: str
    ) -> MismatchResult:
        """
        Check for extension mismatch
        
        Args:
            file_path: Path to file
            detected_type: Detected file type name
            detected_extension: Expected extension based on content
        
        Returns:
            MismatchResult with analysis
        """
        file_path = Path(file_path)
        actual_extension = file_path.suffix.lower().lstrip('.')
        expected_extension = detected_extension.lower()
        
        # Check for double extension tricks first
        double_ext_result = self._check_double_extension(file_path)
        if double_ext_result:
            return double_ext_result
        
        # Check if extensions are equivalent
        if self._are_equivalent(actual_extension, expected_extension):
            return MismatchResult(
                has_mismatch=False,
                actual_extension=actual_extension,
                expected_extension=expected_extension,
                detected_type=detected_type,
                severity=MismatchSeverity.INFO,
                message="Extension matches detected type",
                is_executable_disguise=False,
                recommendations=[]
            )
        
        # Calculate mismatch severity
        severity, is_disguise = self._calculate_severity(
            actual_extension, expected_extension, detected_type
        )
        
        # Generate message and recommendations
        message = self._generate_message(
            actual_extension, expected_extension, detected_type, severity
        )
        recommendations = self._generate_recommendations(
            actual_extension, expected_extension, detected_type, severity, is_disguise
        )
        
        return MismatchResult(
            has_mismatch=True,
            actual_extension=actual_extension,
            expected_extension=expected_extension,
            detected_type=detected_type,
            severity=severity,
            message=message,
            is_executable_disguise=is_disguise,
            recommendations=recommendations
        )
    
    def _are_equivalent(self, ext1: str, ext2: str) -> bool:
        """Check if two extensions are equivalent"""
        if ext1 == ext2:
            return True
        
        for equiv_set in self.EQUIVALENT_EXTENSIONS:
            if ext1 in equiv_set and ext2 in equiv_set:
                return True
        
        return False
    
    def _check_double_extension(self, file_path: Path) -> Optional[MismatchResult]:
        """Check for double extension tricks"""
        filename = file_path.name.lower()
        
        for pattern, description in self.DOUBLE_EXTENSION_PATTERNS:
            if filename.endswith(pattern):
                return MismatchResult(
                    has_mismatch=True,
                    actual_extension=file_path.suffix.lower().lstrip('.'),
                    expected_extension='',
                    detected_type='Double Extension Attack',
                    severity=MismatchSeverity.CRITICAL,
                    message=f"DOUBLE EXTENSION DETECTED: {description}",
                    is_executable_disguise=True,
                    recommendations=[
                        "CRITICAL: This file uses a double extension trick",
                        "The file appears to be one type but is actually executable",
                        "Do NOT open or execute this file",
                        "Quarantine immediately and report to security team"
                    ]
                )
        
        # Check for Unicode tricks (Right-to-Left Override)
        if '\u202e' in str(file_path.name) or '\u200e' in str(file_path.name):
            return MismatchResult(
                has_mismatch=True,
                actual_extension=file_path.suffix.lower().lstrip('.'),
                expected_extension='',
                detected_type='Unicode Filename Attack',
                severity=MismatchSeverity.CRITICAL,
                message="UNICODE BIDIRECTIONAL OVERRIDE DETECTED",
                is_executable_disguise=True,
                recommendations=[
                    "CRITICAL: Filename contains bidirectional text override characters",
                    "This is a known attack technique to disguise file extensions",
                    "Quarantine immediately"
                ]
            )
        
        return None
    
    def _calculate_severity(
        self, 
        actual_ext: str, 
        expected_ext: str,
        detected_type: str
    ) -> Tuple[MismatchSeverity, bool]:
        """Calculate mismatch severity and detect executable disguises"""
        
        # Most critical: Executable disguised with non-executable extension
        if expected_ext in self.EXECUTABLE_EXTENSIONS:
            if actual_ext in self.COMMON_DISGUISE_EXTENSIONS:
                return MismatchSeverity.CRITICAL, True
            elif actual_ext not in self.EXECUTABLE_EXTENSIONS:
                return MismatchSeverity.HIGH, True
        
        # High: Actual extension is executable but content is not (weird case)
        if actual_ext in self.EXECUTABLE_EXTENSIONS:
            if expected_ext not in self.EXECUTABLE_EXTENSIONS:
                return MismatchSeverity.HIGH, False
        
        # Medium: General type mismatch between different categories
        type_lower = detected_type.lower()
        if 'executable' in type_lower or 'script' in type_lower:
            return MismatchSeverity.HIGH, False
        
        # Default: Simple mismatch
        return MismatchSeverity.WARNING, False
    
    def _generate_message(
        self,
        actual_ext: str,
        expected_ext: str,
        detected_type: str,
        severity: MismatchSeverity
    ) -> str:
        """Generate human-readable mismatch message"""
        
        if severity == MismatchSeverity.CRITICAL:
            return (f"CRITICAL MISMATCH: File claims to be .{actual_ext} but is actually "
                   f"{detected_type} (.{expected_ext}) - POSSIBLE MALWARE DISGUISE")
        elif severity == MismatchSeverity.HIGH:
            return (f"HIGH RISK MISMATCH: File extension .{actual_ext} does not match "
                   f"detected type {detected_type} (.{expected_ext})")
        elif severity == MismatchSeverity.WARNING:
            return (f"Extension mismatch: .{actual_ext} file detected as {detected_type} "
                   f"(expected .{expected_ext})")
        else:
            return f"Minor mismatch between .{actual_ext} and {detected_type}"
    
    def _generate_recommendations(
        self,
        actual_ext: str,
        expected_ext: str,
        detected_type: str,
        severity: MismatchSeverity,
        is_disguise: bool
    ) -> List[str]:
        """Generate recommendations based on mismatch type"""
        recommendations = []
        
        if is_disguise:
            recommendations.extend([
                "Do NOT execute or open this file",
                "This appears to be a disguised executable",
                "Quarantine the file immediately",
                "Report to your security team",
                f"If you need to handle this file, rename to .{expected_ext} first"
            ])
        elif severity == MismatchSeverity.HIGH:
            recommendations.extend([
                "Exercise caution with this file",
                "Verify the source of this file",
                f"Consider renaming to correct extension (.{expected_ext})",
                "Scan with antivirus before opening"
            ])
        elif severity == MismatchSeverity.WARNING:
            recommendations.extend([
                "Verify this file was intentionally renamed",
                f"Original format appears to be {detected_type}"
            ])
        
        return recommendations
    
    def check_suspicious_name_patterns(self, file_path: str) -> List[Dict]:
        """Check for suspicious filename patterns"""
        file_path = Path(file_path)
        filename = file_path.name
        findings = []
        
        # Check for excessive spaces (hiding extension)
        if '   ' in filename:
            findings.append({
                'pattern': 'excessive_spaces',
                'severity': 'HIGH',
                'message': 'Filename contains excessive spaces (may hide true extension)'
            })
        
        # Check for many dots (confusing extension)
        if filename.count('.') > 2:
            findings.append({
                'pattern': 'multiple_dots',
                'severity': 'MEDIUM',
                'message': 'Filename contains multiple dots (may confuse extension)'
            })
        
        # Check for leading/trailing dots
        if filename.startswith('.') or filename.endswith('.'):
            findings.append({
                'pattern': 'unusual_dots',
                'severity': 'MEDIUM',
                'message': 'Filename has unusual dot placement'
            })
        
        # Check for null byte (old attack vector)
        if '\x00' in filename:
            findings.append({
                'pattern': 'null_byte',
                'severity': 'CRITICAL',
                'message': 'Filename contains null byte (classic path traversal attack)'
            })
        
        return findings
