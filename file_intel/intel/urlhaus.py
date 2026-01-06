"""
FILE-INTEL: URLhaus Database Integration
Check files for known malicious URLs
"""

import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
import time


@dataclass
class URLhausMatch:
    """Match result from URLhaus database"""
    url: str
    found_in_file: bool
    context: str  # Surrounding text


class URLhausDatabase:
    """
    URLhaus malicious URL database integration
    Loads and indexes the URLhaus plaintext URL list for fast lookups
    """
    
    def __init__(self, config=None):
        self.logger = logging.getLogger(__name__)
        self.config = config
        
        self.urls: Set[str] = set()
        self.domains: Set[str] = set()
        self.ips: Set[str] = set()
        self.loaded = False
        self.url_count = 0
        
        # URL patterns for extraction
        self.url_pattern = re.compile(
            r'https?://[^\s<>"\'}\]\\]+',
            re.IGNORECASE
        )
        self.ip_pattern = re.compile(
            r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        )
        self.domain_pattern = re.compile(
            r'https?://([^/:]+)',
            re.IGNORECASE
        )
        
        # Auto-load if config available
        if config:
            db_path = config.get_urlhaus_path()
            if db_path.exists():
                self.load_database(str(db_path))
    
    def load_database(self, file_path: str) -> bool:
        """
        Load URLhaus URL list from file
        
        Args:
            file_path: Path to URLhaus plaintext file
        
        Returns:
            True if loaded successfully
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            self.logger.error(f"URLhaus database not found: {file_path}")
            return False
        
        start_time = time.time()
        self.urls.clear()
        self.domains.clear()
        self.ips.clear()
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue
                    
                    # Add URL
                    self.urls.add(line.lower())
                    
                    # Extract and index domain
                    domain_match = self.domain_pattern.match(line)
                    if domain_match:
                        domain = domain_match.group(1).lower()
                        self.domains.add(domain)
                        
                        # Check if domain is actually an IP
                        if self.ip_pattern.match(domain):
                            self.ips.add(domain)
            
            self.url_count = len(self.urls)
            self.loaded = True
            
            elapsed = time.time() - start_time
            self.logger.info(
                f"Loaded {self.url_count:,} URLs, {len(self.domains):,} domains, "
                f"{len(self.ips):,} IPs in {elapsed:.2f}s"
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading URLhaus database: {e}")
            return False
    
    def check_url(self, url: str) -> bool:
        """Check if a URL is in the malicious database"""
        if not self.loaded:
            return False
        
        return url.lower() in self.urls
    
    def check_domain(self, domain: str) -> bool:
        """Check if a domain is known malicious"""
        if not self.loaded:
            return False
        
        return domain.lower() in self.domains
    
    def check_ip(self, ip: str) -> bool:
        """Check if an IP is known malicious"""
        if not self.loaded:
            return False
        
        return ip in self.ips
    
    def scan_file_content(self, file_path: str, max_size: int = 10485760) -> List[URLhausMatch]:
        """
        Scan file content for malicious URLs
        
        Args:
            file_path: Path to file
            max_size: Maximum file size to scan (default 10MB)
        
        Returns:
            List of URLhausMatch for found malicious URLs
        """
        if not self.loaded:
            self.logger.warning("URLhaus database not loaded")
            return []
        
        file_path = Path(file_path)
        
        if not file_path.exists():
            return []
        
        matches = []
        
        try:
            file_size = file_path.stat().st_size
            
            if file_size > max_size:
                self.logger.debug(f"File too large for URL scan: {file_size} bytes")
                return []
            
            # Try to read as text
            content = None
            for encoding in ['utf-8', 'latin-1', 'utf-16']:
                try:
                    with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
                        content = f.read()
                    break
                except Exception:
                    continue
            
            if not content:
                # Try binary mode and decode
                with open(file_path, 'rb') as f:
                    data = f.read()
                content = data.decode('utf-8', errors='ignore')
            
            # Extract all URLs from content
            found_urls = self.url_pattern.findall(content)
            
            for url in found_urls:
                url_lower = url.lower()
                
                # Check exact URL match
                if url_lower in self.urls:
                    # Get some context
                    idx = content.find(url)
                    start = max(0, idx - 50)
                    end = min(len(content), idx + len(url) + 50)
                    context = content[start:end].replace('\n', ' ').strip()
                    
                    matches.append(URLhausMatch(
                        url=url,
                        found_in_file=True,
                        context=context[:100]
                    ))
                else:
                    # Check domain match
                    domain_match = self.domain_pattern.match(url)
                    if domain_match:
                        domain = domain_match.group(1).lower()
                        if domain in self.domains:
                            idx = content.find(url)
                            start = max(0, idx - 50)
                            end = min(len(content), idx + len(url) + 50)
                            context = content[start:end].replace('\n', ' ').strip()
                            
                            matches.append(URLhausMatch(
                                url=url,
                                found_in_file=True,
                                context=f"[Domain match: {domain}] " + context[:80]
                            ))
            
            return matches
            
        except Exception as e:
            self.logger.error(f"Error scanning file for URLs: {e}")
            return []
    
    def scan_text(self, text: str) -> List[str]:
        """
        Scan text for malicious URLs
        
        Returns:
            List of malicious URLs found
        """
        if not self.loaded:
            return []
        
        malicious = []
        urls = self.url_pattern.findall(text)
        
        for url in urls:
            if url.lower() in self.urls:
                malicious.append(url)
        
        return malicious
    
    def get_stats(self) -> Dict:
        """Get database statistics"""
        return {
            'loaded': self.loaded,
            'url_count': self.url_count,
            'domain_count': len(self.domains),
            'ip_count': len(self.ips)
        }
    
    def is_loaded(self) -> bool:
        """Check if database is loaded"""
        return self.loaded
