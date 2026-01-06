"""
FILE-INTEL: YARA Scanner
Comprehensive YARA rule scanning with support for multiple rule sets
"""

import os
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import threading
import time


@dataclass
class YaraMatch:
    """YARA match result"""
    rule: str
    namespace: str
    tags: List[str]
    meta: Dict[str, Any]
    strings: List[Dict]
    severity: str


class YaraScanner:
    """
    Advanced YARA scanning engine
    Supports multiple rule directories and lazy loading
    """
    
    # Severity classification based on rule name patterns
    SEVERITY_PATTERNS = {
        'CRITICAL': ['APT', 'RANSOM', 'BACKDOOR', 'ROOTKIT', 'RAT_', 'TROJAN'],
        'HIGH': ['MALW', 'HACK', 'EXPLOIT', 'WORM', 'STEALER', 'KEYLOG'],
        'MEDIUM': ['SUSPICIOUS', 'PUA_', 'TOOL', 'SUSP_'],
        'LOW': ['GEN_', 'GENERIC', 'INFO']
    }
    
    def __init__(self, config=None):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.rules = None
        self.rules_loaded = False
        self._load_lock = threading.Lock()
        
        # Get rule directories from config
        self.rule_directories = []
        if config:
            self.rule_directories = config.get_yara_rule_paths()
        
        # Statistics
        self.rules_count = 0
        self.load_errors = []
    
    def _ensure_yara_available(self) -> bool:
        """Check if yara-python is available"""
        try:
            import yara
            return True
        except ImportError:
            self.logger.error("yara-python not installed. Run: pip install yara-python")
            return False
    
    def load_rules(self, force_reload: bool = False) -> bool:
        """
        Load all YARA rules from configured directories
        
        Args:
            force_reload: Force reload even if already loaded
        
        Returns:
            True if rules loaded successfully
        """
        with self._load_lock:
            if self.rules_loaded and not force_reload:
                return True
            
            if not self._ensure_yara_available():
                return False
            
            import yara
            
            self.rules = None
            self.load_errors = []
            rule_files = {}
            
            start_time = time.time()
            
            # Collect all .yar files from rule directories
            for rule_dir in self.rule_directories:
                if not rule_dir.exists():
                    self.logger.warning(f"Rule directory not found: {rule_dir}")
                    continue
                
                self.logger.info(f"Loading rules from: {rule_dir}")
                
                for yar_file in rule_dir.rglob('*.yar'):
                    try:
                        # Create a namespace based on file path
                        relative_path = yar_file.relative_to(rule_dir)
                        namespace = str(relative_path.with_suffix('')).replace(os.sep, '_')
                        
                        rule_files[namespace] = str(yar_file)
                        
                    except Exception as e:
                        self.load_errors.append(f"{yar_file}: {e}")
            
            if not rule_files:
                self.logger.warning("No YARA rule files found")
                return False
            
            # Compile rules
            try:
                self.logger.info(f"Compiling {len(rule_files)} rule files...")
                
                # Try to compile all at once for efficiency
                self.rules = yara.compile(filepaths=rule_files)
                self.rules_count = len(rule_files)
                self.rules_loaded = True
                
                elapsed = time.time() - start_time
                self.logger.info(f"Loaded {self.rules_count} rule files in {elapsed:.2f}s")
                
                if self.load_errors:
                    self.logger.warning(f"{len(self.load_errors)} rules had errors")
                
                return True
                
            except yara.SyntaxError as e:
                self.logger.error(f"YARA syntax error during compilation: {e}")
                self.load_errors.append(str(e))
                
                # Try loading rules individually to identify problematic ones
                return self._load_rules_individually(rule_files)
                
            except Exception as e:
                self.logger.error(f"Error compiling YARA rules: {e}")
                return False
    
    def _load_rules_individually(self, rule_files: Dict[str, str]) -> bool:
        """Load rules one by one, skipping problematic ones"""
        import yara
        
        valid_rules = {}
        
        for namespace, filepath in rule_files.items():
            try:
                # Test compile individually
                yara.compile(filepath=filepath)
                valid_rules[namespace] = filepath
            except Exception as e:
                self.load_errors.append(f"{filepath}: {e}")
                self.logger.debug(f"Skipping invalid rule: {filepath}")
        
        if valid_rules:
            try:
                self.rules = yara.compile(filepaths=valid_rules)
                self.rules_count = len(valid_rules)
                self.rules_loaded = True
                
                self.logger.info(f"Loaded {self.rules_count} valid rule files ({len(self.load_errors)} skipped)")
                return True
                
            except Exception as e:
                self.logger.error(f"Error compiling valid rules: {e}")
                return False
        
        return False
    
    def scan_file(self, file_path: str, timeout: int = 60) -> List[Dict]:
        """
        Scan a file with all loaded YARA rules
        
        Args:
            file_path: Path to file to scan
            timeout: Timeout in seconds
        
        Returns:
            List of match dictionaries
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            self.logger.error(f"File not found: {file_path}")
            return []
        
        # Ensure rules are loaded
        if not self.rules_loaded:
            if not self.load_rules():
                return []
        
        if not self.rules:
            return []
        
        import yara
        
        try:
            matches = self.rules.match(str(file_path), timeout=timeout)
            return self._format_matches(matches)
            
        except yara.TimeoutError:
            self.logger.warning(f"YARA scan timeout for {file_path}")
            return []
        except yara.Error as e:
            self.logger.error(f"YARA error scanning {file_path}: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Error scanning {file_path}: {e}")
            return []
    
    def scan_data(self, data: bytes, timeout: int = 60) -> List[Dict]:
        """
        Scan byte data with all loaded YARA rules
        
        Args:
            data: Bytes to scan
            timeout: Timeout in seconds
        
        Returns:
            List of match dictionaries
        """
        if not self.rules_loaded:
            if not self.load_rules():
                return []
        
        if not self.rules:
            return []
        
        import yara
        
        try:
            matches = self.rules.match(data=data, timeout=timeout)
            return self._format_matches(matches)
            
        except yara.TimeoutError:
            self.logger.warning("YARA scan timeout for data")
            return []
        except Exception as e:
            self.logger.error(f"Error scanning data: {e}")
            return []
    
    def _format_matches(self, matches) -> List[Dict]:
        """Format YARA matches into structured dictionaries"""
        results = []
        
        for match in matches:
            # Determine severity based on rule name
            severity = self._classify_severity(match.rule)
            
            # Extract string matches (limit to avoid huge output)
            string_matches = []
            for string_match in match.strings[:10]:  # Limit to 10 strings
                string_matches.append({
                    'identifier': string_match.identifier if hasattr(string_match, 'identifier') else str(string_match[1]),
                    'offset': string_match.instances[0].offset if hasattr(string_match, 'instances') and string_match.instances else string_match[0] if isinstance(string_match, tuple) else 0,
                    'data': self._safe_string_preview(string_match)
                })
            
            results.append({
                'rule': match.rule,
                'namespace': match.namespace,
                'tags': list(match.tags) if match.tags else [],
                'meta': dict(match.meta) if match.meta else {},
                'strings': string_matches,
                'severity': severity
            })
        
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        results.sort(key=lambda x: severity_order.get(x['severity'], 4))
        
        return results
    
    def _classify_severity(self, rule_name: str) -> str:
        """Classify rule severity based on name patterns"""
        rule_upper = rule_name.upper()
        
        for severity, patterns in self.SEVERITY_PATTERNS.items():
            for pattern in patterns:
                if pattern in rule_upper:
                    return severity
        
        return 'MEDIUM'  # Default
    
    def _safe_string_preview(self, string_match) -> str:
        """Get safe preview of matched string"""
        try:
            if hasattr(string_match, 'instances') and string_match.instances:
                data = string_match.instances[0].matched_data
            elif isinstance(string_match, tuple) and len(string_match) >= 3:
                data = string_match[2]
            else:
                return "[no data]"
            
            # Convert bytes to safe string preview
            if isinstance(data, bytes):
                # Show hex for binary data
                if any(b < 32 or b > 126 for b in data[:20]):
                    return data[:20].hex()
                else:
                    return data[:50].decode('utf-8', errors='replace')
            
            return str(data)[:50]
            
        except Exception:
            return "[error reading data]"
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scanner statistics"""
        return {
            'rules_loaded': self.rules_loaded,
            'rules_count': self.rules_count,
            'rule_directories': [str(d) for d in self.rule_directories],
            'load_errors_count': len(self.load_errors)
        }
    
    def get_load_errors(self) -> List[str]:
        """Get list of rule loading errors"""
        return self.load_errors.copy()
