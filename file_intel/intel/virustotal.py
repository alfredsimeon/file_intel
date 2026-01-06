"""
FILE-INTEL: VirusTotal Integration
Query VirusTotal API for file reputation
"""

import logging
import time
import json
from pathlib import Path
from typing import Dict, Optional, Any
from dataclasses import dataclass
import hashlib


@dataclass
class VTResult:
    """VirusTotal lookup result"""
    found: bool
    sha256: str
    positives: int
    total: int
    scan_date: str
    permalink: str
    scans: Dict[str, Dict]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'found': self.found,
            'sha256': self.sha256,
            'positives': self.positives,
            'total': self.total,
            'scan_date': self.scan_date,
            'permalink': self.permalink,
            'detection_ratio': f"{self.positives}/{self.total}" if self.total > 0 else "N/A"
        }


class VirusTotalClient:
    """
    VirusTotal API client for file reputation lookups
    """
    
    API_URL = "https://www.virustotal.com/vtapi/v2"
    
    def __init__(self, config=None):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.api_key = ""
        
        # Rate limiting (4 requests per minute for free API)
        self.rate_limit = 4
        self.rate_window = 60
        self.request_times = []
        
        # Cache
        self.cache = {}
        self.cache_enabled = True
        
        # Load API key from config
        if config:
            self.api_key = config.api_keys.virustotal
            self.cache_enabled = config.threat_intel.cache_enabled
        
        if not self.api_key:
            self.logger.warning("VirusTotal API key not configured")
    
    def _check_rate_limit(self) -> bool:
        """Check if we can make a request within rate limits"""
        now = time.time()
        
        # Remove old requests from tracking
        self.request_times = [t for t in self.request_times if now - t < self.rate_window]
        
        if len(self.request_times) >= self.rate_limit:
            wait_time = self.rate_window - (now - self.request_times[0])
            self.logger.warning(f"Rate limit reached, need to wait {wait_time:.1f}s")
            return False
        
        return True
    
    def _record_request(self) -> None:
        """Record a request for rate limiting"""
        self.request_times.append(time.time())
    
    def lookup_hash(self, file_hash: str) -> Optional[VTResult]:
        """
        Look up file hash in VirusTotal
        
        Args:
            file_hash: MD5, SHA1, or SHA256 hash
        
        Returns:
            VTResult or None if lookup failed
        """
        if not self.api_key:
            self.logger.error("VirusTotal API key not configured")
            return None
        
        # Check cache
        if self.cache_enabled and file_hash in self.cache:
            self.logger.debug(f"Cache hit for {file_hash}")
            return self.cache[file_hash]
        
        # Check rate limit
        if not self._check_rate_limit():
            self.logger.warning("Rate limit exceeded, skipping VT lookup")
            return None
        
        try:
            import requests
            
            url = f"{self.API_URL}/file/report"
            params = {
                'apikey': self.api_key,
                'resource': file_hash
            }
            
            self.logger.info(f"Querying VirusTotal for {file_hash[:16]}...")
            
            response = requests.get(url, params=params, timeout=30)
            self._record_request()
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('response_code') == 1:
                    # Found in VT
                    result = VTResult(
                        found=True,
                        sha256=data.get('sha256', file_hash),
                        positives=data.get('positives', 0),
                        total=data.get('total', 0),
                        scan_date=data.get('scan_date', ''),
                        permalink=data.get('permalink', ''),
                        scans=data.get('scans', {})
                    )
                else:
                    # Not found or never scanned
                    result = VTResult(
                        found=False,
                        sha256=file_hash,
                        positives=0,
                        total=0,
                        scan_date='',
                        permalink='',
                        scans={}
                    )
                
                # Cache result
                if self.cache_enabled:
                    self.cache[file_hash] = result
                
                return result
                
            elif response.status_code == 204:
                self.logger.warning("VirusTotal rate limit exceeded")
                return None
            else:
                self.logger.error(f"VirusTotal API error: {response.status_code}")
                return None
                
        except ImportError:
            self.logger.error("requests library not available")
            return None
        except Exception as e:
            self.logger.error(f"VirusTotal lookup error: {e}")
            return None
    
    def lookup_file(self, file_path: str) -> Optional[VTResult]:
        """
        Look up file by computing its SHA256 hash
        
        Args:
            file_path: Path to file
        
        Returns:
            VTResult or None
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            self.logger.error(f"File not found: {file_path}")
            return None
        
        try:
            sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    sha256.update(chunk)
            
            return self.lookup_hash(sha256.hexdigest())
            
        except Exception as e:
            self.logger.error(f"Error hashing file: {e}")
            return None
    
    def get_detections_summary(self, result: VTResult) -> Dict[str, Any]:
        """Get summary of AV detections"""
        if not result.found or result.positives == 0:
            return {'detected': False, 'detections': []}
        
        detections = []
        for engine, scan_result in result.scans.items():
            if scan_result.get('detected'):
                detections.append({
                    'engine': engine,
                    'result': scan_result.get('result', 'Malware'),
                    'version': scan_result.get('version', ''),
                    'update': scan_result.get('update', '')
                })
        
        # Sort by engine name
        detections.sort(key=lambda x: x['engine'])
        
        return {
            'detected': True,
            'ratio': f"{result.positives}/{result.total}",
            'detections': detections[:20]  # Limit to 20
        }
    
    def is_configured(self) -> bool:
        """Check if VT client is properly configured"""
        return bool(self.api_key)
    
    def clear_cache(self) -> None:
        """Clear the result cache"""
        self.cache.clear()
