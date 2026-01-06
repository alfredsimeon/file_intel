"""
FILE-INTEL: Configuration Management
Handles loading and managing application configuration
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Any, Dict, Optional
from dataclasses import dataclass, field


@dataclass
class APIKeys:
    """API key configuration"""
    virustotal: str = ""
    malwarebazaar: str = ""


@dataclass
class ScanningConfig:
    """Scanning configuration"""
    max_file_size: int = 10737418240  # 10GB
    deep_scan: bool = True
    scan_nested_archives: bool = True
    max_archive_depth: int = 5
    chunk_size: int = 65536
    thread_count: int = 4


@dataclass
class YaraConfig:
    """YARA configuration"""
    enabled: bool = True
    rule_directories: list = field(default_factory=lambda: ["rules-master", "signature-base-master/yara"])
    timeout: int = 60
    fast_mode: bool = False


@dataclass
class ThreatIntelConfig:
    """Threat intelligence configuration"""
    online_enabled: bool = True
    cache_enabled: bool = True
    cache_expiry_hours: int = 24
    urlhaus_path: str = "plain-text-url-list.txt"


@dataclass
class DetectionConfig:
    """Detection configuration"""
    entropy_threshold: float = 7.5
    min_confidence: float = 0.7
    polyglot_detection: bool = True
    stego_detection: bool = True


@dataclass
class GUIConfig:
    """GUI configuration"""
    theme: str = "vintage"
    default_width: int = 1280
    default_height: int = 800
    animations: bool = True


@dataclass
class ReportingConfig:
    """Reporting configuration"""
    output_directory: str = "reports"
    include_hex_dump: bool = True
    hex_dump_bytes: int = 256
    organization_name: str = "FILE-INTEL"
    report_title: str = "File Analysis Report"


@dataclass
class LoggingConfig:
    """Logging configuration"""
    level: str = "INFO"
    file_logging: bool = True
    log_file: str = "file_intel.log"
    max_log_size_mb: int = 50


class Config:
    """
    Main configuration manager for FILE-INTEL
    Loads configuration from YAML file and provides access to all settings
    """
    
    _instance: Optional['Config'] = None
    
    def __new__(cls, config_path: Optional[str] = None):
        """Singleton pattern to ensure single config instance"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self, config_path: Optional[str] = None):
        if self._initialized:
            return
            
        self._initialized = True
        self.project_root = Path(__file__).parent.parent
        
        # Default config path
        if config_path is None:
            config_path = self.project_root / "config.yaml"
        
        self.config_path = Path(config_path)
        self._raw_config: Dict[str, Any] = {}
        
        # Initialize configuration sections
        self.api_keys = APIKeys()
        self.scanning = ScanningConfig()
        self.yara = YaraConfig()
        self.threat_intel = ThreatIntelConfig()
        self.detection = DetectionConfig()
        self.gui = GUIConfig()
        self.reporting = ReportingConfig()
        self.logging_config = LoggingConfig()
        
        # Load configuration
        self._load_config()
        self._setup_logging()
    
    def _load_config(self) -> None:
        """Load configuration from YAML file"""
        if not self.config_path.exists():
            logging.warning(f"Config file not found: {self.config_path}. Using defaults.")
            return
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                self._raw_config = yaml.safe_load(f) or {}
        except Exception as e:
            logging.error(f"Error loading config: {e}. Using defaults.")
            return
        
        # Parse API Keys
        if 'api_keys' in self._raw_config:
            self.api_keys = APIKeys(**self._raw_config['api_keys'])
        
        # Parse Scanning Config
        if 'scanning' in self._raw_config:
            self.scanning = ScanningConfig(**self._raw_config['scanning'])
        
        # Parse YARA Config
        if 'yara' in self._raw_config:
            self.yara = YaraConfig(**self._raw_config['yara'])
        
        # Parse Threat Intel Config
        if 'threat_intel' in self._raw_config:
            self.threat_intel = ThreatIntelConfig(**self._raw_config['threat_intel'])
        
        # Parse Detection Config
        if 'detection' in self._raw_config:
            self.detection = DetectionConfig(**self._raw_config['detection'])
        
        # Parse GUI Config
        if 'gui' in self._raw_config:
            self.gui = GUIConfig(**self._raw_config['gui'])
        
        # Parse Reporting Config
        if 'reporting' in self._raw_config:
            self.reporting = ReportingConfig(**self._raw_config['reporting'])
        
        # Parse Logging Config
        if 'logging' in self._raw_config:
            self.logging_config = LoggingConfig(**self._raw_config['logging'])
    
    def _setup_logging(self) -> None:
        """Configure application logging"""
        log_level = getattr(logging, self.logging_config.level.upper(), logging.INFO)
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
        
        # File handler (if enabled)
        if self.logging_config.file_logging:
            log_path = self.project_root / self.logging_config.log_file
            file_handler = logging.handlers.RotatingFileHandler(
                log_path,
                maxBytes=self.logging_config.max_log_size_mb * 1024 * 1024,
                backupCount=5,
                encoding='utf-8'
            )
            file_handler.setLevel(log_level)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
    
    def get_yara_rule_paths(self) -> list:
        """Get absolute paths to YARA rule directories"""
        paths = []
        for rule_dir in self.yara.rule_directories:
            full_path = self.project_root / rule_dir
            if full_path.exists():
                paths.append(full_path)
        return paths
    
    def get_urlhaus_path(self) -> Path:
        """Get absolute path to URLhaus database"""
        return self.project_root / self.threat_intel.urlhaus_path
    
    def get_reports_path(self) -> Path:
        """Get absolute path to reports directory"""
        reports_dir = self.project_root / self.reporting.output_directory
        reports_dir.mkdir(exist_ok=True)
        return reports_dir
    
    @classmethod
    def reset(cls) -> None:
        """Reset singleton instance (for testing)"""
        cls._instance = None


# Import logging.handlers for RotatingFileHandler
import logging.handlers
