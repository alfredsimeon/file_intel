"""
FILE-INTEL: Hash Generation Engine
Generates multiple hash types for threat intelligence correlation
"""

import hashlib
import logging
import os
from pathlib import Path
from typing import Dict, Optional
from dataclasses import dataclass


@dataclass
class HashResult:
    """Result of hash generation"""
    md5: str
    sha1: str
    sha256: str
    sha512: str
    ssdeep: Optional[str]
    tlsh: Optional[str]
    file_size: int
    imphash: Optional[str]  # PE import hash


class HashGenerator:
    """
    Multi-algorithm hash generator for file identification
    Supports cryptographic hashes and fuzzy hashes
    """
    
    def __init__(self, chunk_size: int = 65536):
        self.logger = logging.getLogger(__name__)
        self.chunk_size = chunk_size
        
        # Check for optional fuzzy hashing libraries
        self.ssdeep_available = self._check_ssdeep()
        self.tlsh_available = self._check_tlsh()
    
    def _check_ssdeep(self) -> bool:
        """Check if ssdeep is available"""
        try:
            import ssdeep
            return True
        except ImportError:
            self.logger.debug("ssdeep not available - fuzzy hashing disabled")
            return False
    
    def _check_tlsh(self) -> bool:
        """Check if tlsh is available"""
        try:
            import tlsh
            return True
        except ImportError:
            self.logger.debug("tlsh not available - locality-sensitive hashing disabled")
            return False
    
    def generate_hashes(self, file_path: str) -> Optional[HashResult]:
        """
        Generate all hash types for a file
        
        Args:
            file_path: Path to file to hash
        
        Returns:
            HashResult with all computed hashes
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            self.logger.error(f"File not found: {file_path}")
            return None
        
        try:
            # Initialize hashers
            md5_hasher = hashlib.md5()
            sha1_hasher = hashlib.sha1()
            sha256_hasher = hashlib.sha256()
            sha512_hasher = hashlib.sha512()
            
            file_size = file_path.stat().st_size
            file_data = b''  # For fuzzy hashing
            
            # Read file and compute hashes
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        break
                    
                    md5_hasher.update(chunk)
                    sha1_hasher.update(chunk)
                    sha256_hasher.update(chunk)
                    sha512_hasher.update(chunk)
                    
                    # Collect data for fuzzy hashing (limit to 100MB)
                    if len(file_data) < 100 * 1024 * 1024:
                        file_data += chunk
            
            # Compute fuzzy hashes
            ssdeep_hash = self._compute_ssdeep(file_data) if self.ssdeep_available else None
            tlsh_hash = self._compute_tlsh(file_data) if self.tlsh_available else None
            
            # Compute imphash for PE files
            imphash = self._compute_imphash(file_path)
            
            return HashResult(
                md5=md5_hasher.hexdigest(),
                sha1=sha1_hasher.hexdigest(),
                sha256=sha256_hasher.hexdigest(),
                sha512=sha512_hasher.hexdigest(),
                ssdeep=ssdeep_hash,
                tlsh=tlsh_hash,
                file_size=file_size,
                imphash=imphash
            )
            
        except PermissionError:
            self.logger.error(f"Permission denied: {file_path}")
            return None
        except Exception as e:
            self.logger.error(f"Error generating hashes: {e}")
            return None
    
    def _compute_ssdeep(self, data: bytes) -> Optional[str]:
        """Compute ssdeep fuzzy hash"""
        try:
            import ssdeep
            return ssdeep.hash(data)
        except Exception as e:
            self.logger.debug(f"ssdeep computation failed: {e}")
            return None
    
    def _compute_tlsh(self, data: bytes) -> Optional[str]:
        """Compute TLSH locality-sensitive hash"""
        try:
            import tlsh
            # TLSH requires minimum 50 bytes
            if len(data) < 50:
                return None
            return tlsh.hash(data)
        except Exception as e:
            self.logger.debug(f"tlsh computation failed: {e}")
            return None
    
    def _compute_imphash(self, file_path: Path) -> Optional[str]:
        """Compute PE import hash"""
        try:
            import pefile
            
            # Quick check for PE file
            with open(file_path, 'rb') as f:
                header = f.read(2)
                if header != b'MZ':
                    return None
            
            pe = pefile.PE(str(file_path), fast_load=True)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']
            ])
            
            imphash = pe.get_imphash()
            pe.close()
            
            return imphash
            
        except ImportError:
            self.logger.debug("pefile not available - imphash computation disabled")
            return None
        except Exception as e:
            self.logger.debug(f"imphash computation failed: {e}")
            return None
    
    def quick_hash(self, file_path: str, algorithm: str = 'sha256') -> Optional[str]:
        """
        Compute a single hash quickly
        
        Args:
            file_path: Path to file
            algorithm: Hash algorithm (md5, sha1, sha256, sha512)
        
        Returns:
            Hash string or None on error
        """
        file_path = Path(file_path)
        
        if not file_path.exists():
            return None
        
        try:
            hasher = hashlib.new(algorithm)
            
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        break
                    hasher.update(chunk)
            
            return hasher.hexdigest()
            
        except Exception as e:
            self.logger.error(f"Error computing hash: {e}")
            return None
    
    def hash_data(self, data: bytes, algorithm: str = 'sha256') -> str:
        """
        Compute hash of byte data
        
        Args:
            data: Bytes to hash
            algorithm: Hash algorithm
        
        Returns:
            Hash string
        """
        hasher = hashlib.new(algorithm)
        hasher.update(data)
        return hasher.hexdigest()
    
    def compare_fuzzy(self, hash1: str, hash2: str) -> Optional[int]:
        """
        Compare two ssdeep hashes
        
        Returns:
            Similarity score (0-100) or None if comparison failed
        """
        if not self.ssdeep_available:
            return None
        
        try:
            import ssdeep
            return ssdeep.compare(hash1, hash2)
        except Exception:
            return None
    
    def format_hashes(self, result: HashResult) -> Dict[str, str]:
        """Format hash result as dictionary"""
        hashes = {
            'MD5': result.md5,
            'SHA-1': result.sha1,
            'SHA-256': result.sha256,
            'SHA-512': result.sha512,
            'File Size': f"{result.file_size:,} bytes"
        }
        
        if result.ssdeep:
            hashes['ssdeep'] = result.ssdeep
        
        if result.tlsh:
            hashes['TLSH'] = result.tlsh
        
        if result.imphash:
            hashes['Import Hash'] = result.imphash
        
        return hashes
