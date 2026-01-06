"""
FILE-INTEL: Polyglot File Detector
Detects files that are valid as multiple file types (potential attack vectors)
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class PolyglotResult:
    """Result of polyglot detection"""
    is_polyglot: bool
    valid_types: List[str]
    primary_type: str
    threat_level: str
    description: str
    attack_potential: List[str]


class PolyglotDetector:
    """
    Detects polyglot files (files valid as multiple types)
    These are often used in sophisticated attacks
    """
    
    # Known polyglot combinations and their threat levels
    POLYGLOT_SIGNATURES = {
        # PDF/ZIP - Very common for malware
        ('pdf', 'zip'): {
            'threat': 'HIGH',
            'description': 'PDF/ZIP polyglot - can contain hidden archive within PDF',
            'attacks': ['Hidden payload extraction', 'ZIP bomb within PDF', 'Macro injection']
        },
        
        # JAR/ZIP - Java archives are ZIPs
        ('jar', 'zip'): {
            'threat': 'MEDIUM',
            'description': 'JAR files are ZIP archives - check for malicious classes',
            'attacks': ['Malicious Java code', 'Classpath hijacking']
        },
        
        # PE/ZIP - Self-extracting archives
        ('exe', 'zip'): {
            'threat': 'HIGH',
            'description': 'PE/ZIP polyglot - self-extracting archive or hidden payload',
            'attacks': ['Hidden malware in ZIP section', 'PE injection']
        },
        
        # GIF/JavaScript - Image with embedded JS
        ('gif', 'js'): {
            'threat': 'CRITICAL',
            'description': 'GIF with embedded JavaScript - XSS attack vector',
            'attacks': ['Cross-site scripting', 'GIFAR attack']
        },
        
        # JPEG/Archive - JFIF allows trailing data
        ('jpg', 'zip'): {
            'threat': 'HIGH',
            'description': 'JPEG with embedded archive - hidden data after image',
            'attacks': ['Data exfiltration', 'Steganography', 'Hidden payloads']
        },
        
        # PDF/JavaScript
        ('pdf', 'js'): {
            'threat': 'HIGH',
            'description': 'PDF with embedded JavaScript actions',
            'attacks': ['PDF exploit delivery', 'Malicious scripts']
        },
        
        # HTML/PE (rare but dangerous)
        ('html', 'exe'): {
            'threat': 'CRITICAL',
            'description': 'HTML/Executable polyglot',
            'attacks': ['Drive-by download', 'Browser exploit']
        },
    }
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def detect(self, file_path: str, header_data: bytes = None) -> PolyglotResult:
        """
        Detect if file is a polyglot
        
        Args:
            file_path: Path to file
            header_data: Optional pre-read header bytes
        
        Returns:
            PolyglotResult with detection details
        """
        file_path = Path(file_path)
        
        if header_data is None:
            try:
                with open(file_path, 'rb') as f:
                    header_data = f.read(65536)  # Read 64KB
            except Exception as e:
                self.logger.error(f"Error reading file: {e}")
                return PolyglotResult(
                    is_polyglot=False,
                    valid_types=[],
                    primary_type='Unknown',
                    threat_level='UNKNOWN',
                    description='Could not read file',
                    attack_potential=[]
                )
        
        # Detect all valid types for this file
        valid_types = self._detect_all_types(header_data)
        
        if len(valid_types) <= 1:
            primary = valid_types[0] if valid_types else 'Unknown'
            return PolyglotResult(
                is_polyglot=False,
                valid_types=valid_types,
                primary_type=primary,
                threat_level='SAFE',
                description='Single file type detected',
                attack_potential=[]
            )
        
        # Check known dangerous combinations
        threat_info = self._check_known_polyglots(valid_types)
        
        return PolyglotResult(
            is_polyglot=True,
            valid_types=valid_types,
            primary_type=valid_types[0],
            threat_level=threat_info['threat'],
            description=threat_info['description'],
            attack_potential=threat_info['attacks']
        )
    
    def _detect_all_types(self, data: bytes) -> List[str]:
        """Detect all file types this data could be"""
        types = []
        
        # Check various magic signatures
        checks = [
            (b'%PDF', 'pdf'),
            (b'PK\x03\x04', 'zip'),
            (b'PK\x05\x06', 'zip'),
            (b'MZ', 'exe'),
            (b'\x7fELF', 'elf'),
            (b'GIF87a', 'gif'),
            (b'GIF89a', 'gif'),
            (b'\xff\xd8\xff', 'jpg'),
            (b'\x89PNG', 'png'),
            (b'Rar!', 'rar'),
            (b'7z\xbc\xaf', '7z'),
            (b'<!DOCTYPE', 'html'),
            (b'<html', 'html'),
            (b'<script', 'js'),
            (b'{\\rtf', 'rtf'),
            (b'\xd0\xcf\x11\xe0', 'ole'),
        ]
        
        for magic, ftype in checks:
            if magic in data[:1024]:
                if ftype not in types:
                    types.append(ftype)
        
        # Check for JavaScript patterns anywhere in file
        js_patterns = [b'function(', b'var ', b'const ', b'<script', b'eval(']
        for pattern in js_patterns:
            if pattern in data:
                if 'js' not in types:
                    types.append('js')
                break
        
        # Check for trailing data after known formats
        types.extend(self._check_trailing_content(data))
        
        return types
    
    def _check_trailing_content(self, data: bytes) -> List[str]:
        """Check for hidden content after primary file data"""
        additional_types = []
        
        # Check for ZIP appended to file
        zip_sig_pos = data.find(b'PK\x03\x04', 100)  # Skip first 100 bytes
        if zip_sig_pos > 0:
            additional_types.append('hidden_zip')
        
        # Check for PE appended to file
        mz_pos = data.find(b'MZ', 100)
        if mz_pos > 0:
            additional_types.append('hidden_pe')
        
        return additional_types
    
    def _check_known_polyglots(self, types: List[str]) -> Dict:
        """Check for known dangerous polyglot combinations"""
        
        type_set = set(types)
        
        for (type1, type2), info in self.POLYGLOT_SIGNATURES.items():
            if type1 in type_set and type2 in type_set:
                return info
        
        # Check for hidden content
        if 'hidden_zip' in type_set or 'hidden_pe' in type_set:
            return {
                'threat': 'HIGH',
                'description': 'File contains hidden appended content',
                'attacks': ['Hidden payload', 'Data smuggling', 'Antivirus evasion']
            }
        
        # Generic polyglot
        return {
            'threat': 'MEDIUM',
            'description': f'File valid as multiple types: {", ".join(types)}',
            'attacks': ['Unknown attack potential', 'Parser confusion']
        }
    
    def check_appended_data(self, file_path: str) -> Optional[Dict]:
        """
        Check if file has significant appended data after expected content
        
        Returns details about appended data if found
        """
        file_path = Path(file_path)
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
        except Exception:
            return None
        
        # Check JPEG - should end with FFD9
        if data[:2] == b'\xff\xd8':
            end_marker = data.rfind(b'\xff\xd9')
            if end_marker > 0 and end_marker < len(data) - 10:
                appended = data[end_marker + 2:]
                return {
                    'format': 'JPEG',
                    'appended_bytes': len(appended),
                    'appended_preview': appended[:64].hex(),
                    'threat': 'Check for hidden data/malware after JPEG end marker'
                }
        
        # Check PNG - should end with IEND chunk
        if data[:8] == b'\x89PNG\r\n\x1a\n':
            iend = data.find(b'IEND')
            if iend > 0:
                # IEND is 4 bytes + 4 bytes CRC
                expected_end = iend + 12
                if expected_end < len(data) - 10:
                    appended = data[expected_end:]
                    return {
                        'format': 'PNG',
                        'appended_bytes': len(appended),
                        'appended_preview': appended[:64].hex(),
                        'threat': 'Data appended after PNG IEND chunk'
                    }
        
        return None
