"""
FILE-INTEL: Main Application Entry Point
"""

import sys
import argparse
import logging
from pathlib import Path


def setup_logging(verbose: bool = False) -> None:
    """Setup basic logging for CLI mode"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s | %(levelname)-8s | %(message)s',
        datefmt='%H:%M:%S'
    )


def run_cli(args: argparse.Namespace) -> int:
    """Run command-line interface"""
    from .config import Config
    from .core.file_scanner import FileScanner
    
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    # Initialize configuration
    config = Config()
    
    # Initialize scanner
    scanner = FileScanner(config)
    
    # Process files
    if args.file:
        # Single file scan
        logger.info(f"Scanning: {args.file}")
        
        result = scanner.scan_file(
            args.file,
            deep_scan=not args.quick,
            enable_yara=not args.no_yara,
            enable_online_lookup=args.online
        )
        
        # Output results
        if args.json:
            print(result.to_json())
        else:
            print_result(result)
        
        return 0 if result.threat_score < 60 else 1
    
    elif args.directory:
        # Directory scan
        logger.info(f"Scanning directory: {args.directory}")
        
        results = scanner.scan_directory(
            args.directory,
            recursive=not args.no_recursive,
            deep_scan=not args.quick,
            enable_yara=not args.no_yara
        )
        
        # Output results
        if args.json:
            import json
            print(json.dumps([r.to_dict() for r in results], indent=2))
        else:
            for result in results:
                print_result(result)
                print("-" * 60)
        
        # Return non-zero if any high threats found
        high_threats = [r for r in results if r.threat_score >= 60]
        return 1 if high_threats else 0
    
    else:
        logger.error("No file or directory specified")
        return 1


def print_result(result) -> None:
    """Print scan result to console"""
    from colorama import init, Fore, Style
    init()
    
    # Threat level colors
    threat_colors = {
        'safe': Fore.GREEN,
        'low': Fore.CYAN,
        'medium': Fore.YELLOW,
        'high': Fore.RED,
        'critical': Fore.RED + Style.BRIGHT
    }
    
    color = threat_colors.get(result.threat_level.value.lower(), Fore.WHITE)
    
    print(f"\n{'='*60}")
    print(f"{Style.BRIGHT}FILE: {result.file_name}{Style.RESET_ALL}")
    print(f"Path: {result.file_path}")
    print(f"Size: {result.file_size:,} bytes")
    print(f"Scan Time: {result.scan_duration_ms:.0f}ms")
    
    # Detected type
    if result.magic_result:
        print(f"\n{Style.BRIGHT}Detected Type:{Style.RESET_ALL}")
        print(f"  Type: {result.magic_result.detected_type}")
        print(f"  Category: {result.magic_result.category.value}")
        print(f"  Confidence: {result.magic_result.confidence:.0%}")
    
    # Extension mismatch
    if result.extension_mismatch:
        print(f"\n{Fore.RED}{Style.BRIGHT}⚠ EXTENSION MISMATCH:{Style.RESET_ALL}")
        print(f"  {result.extension_mismatch.get('message', 'Mismatch detected')}")
    
    # Entropy
    if result.entropy_result:
        ent = result.entropy_result
        print(f"\nEntropy: {ent.overall_entropy:.2f} ({ent.category.value})")
        if ent.is_suspicious:
            print(f"  {Fore.YELLOW}⚠ {ent.suspicion_reason}{Style.RESET_ALL}")
    
    # Hashes
    if result.hash_result:
        print(f"\n{Style.BRIGHT}Hashes:{Style.RESET_ALL}")
        print(f"  MD5:    {result.hash_result.md5}")
        print(f"  SHA256: {result.hash_result.sha256}")
    
    # YARA matches
    if result.yara_matches:
        print(f"\n{Fore.RED}{Style.BRIGHT}YARA Matches ({len(result.yara_matches)}):{Style.RESET_ALL}")
        for match in result.yara_matches[:5]:
            print(f"  [{match.get('severity')}] {match.get('rule')}")
    
    # Threat assessment
    print(f"\n{Style.BRIGHT}THREAT ASSESSMENT:{Style.RESET_ALL}")
    print(f"  Score: {color}{result.threat_score:.0f}/100{Style.RESET_ALL}")
    print(f"  Level: {color}{result.threat_level.value.upper()}{Style.RESET_ALL}")
    
    # Indicators
    if result.threat_indicators:
        print(f"\n{Style.BRIGHT}Threat Indicators:{Style.RESET_ALL}")
        for indicator in result.threat_indicators[:5]:
            print(f"  • {indicator}")
    
    # Recommendations
    if result.recommendations:
        print(f"\n{Style.BRIGHT}Recommendations:{Style.RESET_ALL}")
        for rec in result.recommendations[:3]:
            print(f"  → {rec}")
    
    # Errors
    if result.errors:
        print(f"\n{Fore.YELLOW}Errors:{Style.RESET_ALL}")
        for error in result.errors:
            print(f"  ! {error}")
    
    print()


def run_gui() -> int:
    """Run graphical user interface"""
    try:
        from PyQt6.QtWidgets import QApplication
        from .gui.app import FileIntelApp
        
        app = QApplication(sys.argv)
        app.setApplicationName("FILE-INTEL")
        app.setApplicationVersion("1.0.0")
        
        window = FileIntelApp()
        window.show()
        
        return app.exec()
        
    except ImportError as e:
        print(f"Error: PyQt6 not installed. Run: pip install PyQt6")
        print(f"Details: {e}")
        return 1


def main() -> int:
    """Main entry point"""
    parser = argparse.ArgumentParser(
        prog='FILE-INTEL',
        description='Military-Grade File Type Identifier',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  FILE-INTEL.py --gui                    Launch graphical interface
  FILE-INTEL.py -f suspicious.pdf        Scan single file
  FILE-INTEL.py -d /path/to/scan         Scan directory
  FILE-INTEL.py -f file.exe --online     Scan with VirusTotal lookup
  FILE-INTEL.py -d /path --json          Output as JSON
        """
    )
    
    # Mode selection
    parser.add_argument('--gui', action='store_true',
                       help='Launch graphical interface')
    
    # Target selection
    parser.add_argument('-f', '--file', type=str,
                       help='File to scan')
    parser.add_argument('-d', '--directory', type=str,
                       help='Directory to scan')
    
    # Scan options
    parser.add_argument('--quick', action='store_true',
                       help='Quick scan (skip deep analysis)')
    parser.add_argument('--no-yara', action='store_true',
                       help='Disable YARA scanning')
    parser.add_argument('--no-recursive', action='store_true',
                       help='Don\'t scan subdirectories')
    parser.add_argument('--online', action='store_true',
                       help='Enable online lookups (VirusTotal)')
    
    # Output options
    parser.add_argument('--json', action='store_true',
                       help='Output as JSON')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Determine mode
    if args.gui or (not args.file and not args.directory):
        return run_gui()
    else:
        return run_cli(args)


if __name__ == "__main__":
    sys.exit(main())
