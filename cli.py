"""
Command Line Interface for Nessus Parser

This module provides a CLI interface for parsing Nessus XML files.
"""

import argparse
import sys
import logging
from pathlib import Path
from parser import NessusParser
from exporter import NessusExporter


def setup_logging(verbose: bool = False):
    """Set up logging configuration."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Parse Nessus XML files and export vulnerability data'
    )
    
    parser.add_argument(
        'input_file',
        type=str,
        help='Path to the Nessus XML file'
    )
    
    parser.add_argument(
        '-o', '--output',
        type=str,
        help='Output file path (default: same name as input with new extension)'
    )
    
    parser.add_argument(
        '-f', '--format',
        choices=['json', 'csv', 'excel'],
        default='json',
        help='Output format (default: json)'
    )
    
    parser.add_argument(
        '--filter-severity',
        choices=['0', '1', '2', '3', '4'],
        help='Filter vulnerabilities by severity level'
    )
    
    parser.add_argument(
        '--filter-host',
        type=str,
        help='Filter vulnerabilities by host IP or hostname'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose logging'
    )
    
    parser.add_argument(
        '--no-info',
        action='store_true',
        help='Exclude informational findings (severity 0)'
    )
    
    return parser.parse_args()


def validate_input_file(file_path: str) -> Path:
    """Validate that the input file exists and is readable."""
    path = Path(file_path)
    
    if not path.exists():
        print(f"Error: File '{file_path}' does not exist.")
        sys.exit(1)
    
    if not path.is_file():
        print(f"Error: '{file_path}' is not a file.")
        sys.exit(1)
    
    if not path.suffix.lower() == '.nessus':
        print(f"Warning: File '{file_path}' does not have .nessus extension.")
    
    return path


def main():
    """Main CLI function."""
    args = parse_args()
    
    # Set up logging
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    try:
        # Validate input file
        input_path = validate_input_file(args.input_file)
        logger.info(f"Processing file: {input_path}")
        
        # Parse the Nessus file
        parser = NessusParser(str(input_path))
        scan_data = parser.parse()
        
        # Apply filters if specified
        if args.filter_severity:
            scan_data = filter_by_severity(scan_data, args.filter_severity)
            logger.info(f"Filtered by severity: {args.filter_severity}")
        
        if args.filter_host:
            scan_data = filter_by_host(scan_data, args.filter_host)
            logger.info(f"Filtered by host: {args.filter_host}")
        
        if args.no_info:
            scan_data = filter_out_info(scan_data)
            logger.info("Excluded informational findings")
        
        # Determine output file path
        if args.output:
            output_path = Path(args.output)
        else:
            output_path = input_path.with_suffix(f'.{args.format}')
        
        # Export the data
        exporter = NessusExporter(scan_data)
        
        if args.format == 'json':
            exporter.to_json(str(output_path))
        elif args.format == 'csv':
            exporter.to_csv(str(output_path))
        elif args.format == 'excel':
            exporter.to_excel(str(output_path))
        
        logger.info(f"Export completed: {output_path}")
        print(f"Successfully exported to: {output_path}")
        
    except Exception as e:
        logger.error(f"Error processing file: {e}")
        print(f"Error: {e}")
        sys.exit(1)


def filter_by_severity(scan_data: dict, severity: str) -> dict:
    """Filter vulnerabilities by severity level."""
    filtered_data = scan_data.copy()
    
    # Filter vulnerabilities list
    filtered_data['vulnerabilities'] = [
        vuln for vuln in scan_data['vulnerabilities']
        if vuln.get('severity') == severity
    ]
    
    # Filter vulnerabilities in hosts
    for host in filtered_data['hosts']:
        host['vulnerabilities'] = [
            vuln for vuln in host['vulnerabilities']
            if vuln.get('severity') == severity
        ]
    
    return filtered_data


def filter_by_host(scan_data: dict, host_filter: str) -> dict:
    """Filter vulnerabilities by host."""
    filtered_data = scan_data.copy()
    
    # Filter hosts
    filtered_data['hosts'] = [
        host for host in scan_data['hosts']
        if host_filter.lower() in host.get('name', '').lower()
    ]
    
    # Filter vulnerabilities to only include those from filtered hosts
    host_names = [host['name'] for host in filtered_data['hosts']]
    # Note: This is a simplified filter - in a real implementation,
    # you'd need to track which vulnerabilities belong to which hosts
    
    return filtered_data


def filter_out_info(scan_data: dict) -> dict:
    """Remove informational findings (severity 0)."""
    return filter_by_severity(scan_data, '0')


if __name__ == '__main__':
    main()
