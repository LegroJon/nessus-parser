"""
Export Module for Nessus Parser

This module provides functionality to export parsed Nessus data to various formats.
"""

import json
import csv
import logging
from typing import Dict, List
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    logger.warning("pandas not available. Excel export will not work.")


class NessusExporter:
    """Exporter for parsed Nessus vulnerability data."""
    
    def __init__(self, scan_data: Dict):
        """
        Initialize the exporter with parsed scan data.
        
        Args:
            scan_data (Dict): Parsed vulnerability data from NessusParser
        """
        self.scan_data = scan_data
    
    def to_json(self, output_path: str, indent: int = 2) -> None:
        """
        Export data to JSON format.
        
        Args:
            output_path (str): Path to save the JSON file
            indent (int): JSON indentation level
        """
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.scan_data, f, indent=indent, ensure_ascii=False)
            
            logger.info(f"Data exported to JSON: {output_path}")
            
        except Exception as e:
            logger.error(f"Error exporting to JSON: {e}")
            raise
    
    def to_csv(self, output_path: str) -> None:
        """
        Export vulnerabilities to CSV format.
        
        Args:
            output_path (str): Path to save the CSV file
        """
        try:
            vulnerabilities = self._flatten_vulnerabilities()
            
            if not vulnerabilities:
                logger.warning("No vulnerabilities to export")
                return
            
            # Get all unique fieldnames
            fieldnames = set()
            for vuln in vulnerabilities:
                fieldnames.update(vuln.keys())
            
            fieldnames = sorted(list(fieldnames))
            
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(vulnerabilities)
            
            logger.info(f"Data exported to CSV: {output_path}")
            
        except Exception as e:
            logger.error(f"Error exporting to CSV: {e}")
            raise
    
    def to_excel(self, output_path: str) -> None:
        """
        Export data to Excel format with multiple sheets.
        
        Args:
            output_path (str): Path to save the Excel file
        """
        if not PANDAS_AVAILABLE:
            raise ImportError("pandas is required for Excel export. Install with: pip install pandas openpyxl")
        
        try:
            with pd.ExcelWriter(output_path, engine='openpyxl') as writer:
                # Export vulnerabilities
                vulnerabilities = self._flatten_vulnerabilities()
                if vulnerabilities:
                    vuln_df = pd.DataFrame(vulnerabilities)
                    vuln_df.to_excel(writer, sheet_name='Vulnerabilities', index=False)
                
                # Export hosts summary
                hosts_summary = self._create_hosts_summary()
                if hosts_summary:
                    hosts_df = pd.DataFrame(hosts_summary)
                    hosts_df.to_excel(writer, sheet_name='Hosts', index=False)
                
                # Export scan metadata
                metadata = self._create_scan_metadata()
                metadata_df = pd.DataFrame([metadata])
                metadata_df.to_excel(writer, sheet_name='Scan_Info', index=False)
            
            logger.info(f"Data exported to Excel: {output_path}")
            
        except Exception as e:
            logger.error(f"Error exporting to Excel: {e}")
            raise
    
    def _flatten_vulnerabilities(self) -> List[Dict]:
        """
        Flatten vulnerability data for tabular export.
        
        Returns:
            List[Dict]: Flattened vulnerability records
        """
        flattened = []
        
        for host in self.scan_data.get('hosts', []):
            host_name = host.get('name', 'Unknown')
            host_ip = host.get('properties', {}).get('host-ip', host_name)
            operating_system = host.get('properties', {}).get('operating-system', 'Unknown')
            
            for vuln in host.get('vulnerabilities', []):
                record = {
                    'host_name': host_name,
                    'host_ip': host_ip,
                    'operating_system': operating_system,
                    'plugin_id': vuln.get('plugin_id'),
                    'plugin_name': vuln.get('plugin_name'),
                    'severity': vuln.get('severity'),
                    'severity_name': self._severity_to_name(vuln.get('severity')),
                    'port': vuln.get('port'),
                    'protocol': vuln.get('protocol'),
                    'service_name': vuln.get('service_name'),
                    'description': vuln.get('description'),
                    'solution': vuln.get('solution'),
                    'risk_factor': vuln.get('risk_factor'),
                    'cvss_score': vuln.get('cvss_score'),
                    'cve': ', '.join(vuln.get('cve', []))
                }
                
                flattened.append(record)
        
        return flattened
    
    def _create_hosts_summary(self) -> List[Dict]:
        """
        Create a summary of hosts and their vulnerability counts.
        
        Returns:
            List[Dict]: Host summary records
        """
        summary = []
        
        for host in self.scan_data.get('hosts', []):
            vuln_counts = {'0': 0, '1': 0, '2': 0, '3': 0, '4': 0}
            
            for vuln in host.get('vulnerabilities', []):
                severity = vuln.get('severity', '0')
                if severity in vuln_counts:
                    vuln_counts[severity] += 1
            
            record = {
                'host_name': host.get('name'),
                'host_ip': host.get('properties', {}).get('host-ip'),
                'operating_system': host.get('properties', {}).get('operating-system'),
                'total_vulnerabilities': len(host.get('vulnerabilities', [])),
                'critical': vuln_counts['4'],
                'high': vuln_counts['3'],
                'medium': vuln_counts['2'],
                'low': vuln_counts['1'],
                'info': vuln_counts['0']
            }
            
            summary.append(record)
        
        return summary
    
    def _create_scan_metadata(self) -> Dict:
        """
        Create scan metadata information.
        
        Returns:
            Dict: Scan metadata
        """
        total_hosts = len(self.scan_data.get('hosts', []))
        total_vulns = len(self.scan_data.get('vulnerabilities', []))
        
        # Count vulnerabilities by severity
        severity_counts = {'0': 0, '1': 0, '2': 0, '3': 0, '4': 0}
        for vuln in self.scan_data.get('vulnerabilities', []):
            severity = vuln.get('severity', '0')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        metadata = {
            'scan_name': self.scan_data.get('scan_name'),
            'policy_name': self.scan_data.get('policy_name'),
            'total_hosts': total_hosts,
            'total_vulnerabilities': total_vulns,
            'critical_vulnerabilities': severity_counts['4'],
            'high_vulnerabilities': severity_counts['3'],
            'medium_vulnerabilities': severity_counts['2'],
            'low_vulnerabilities': severity_counts['1'],
            'info_findings': severity_counts['0']
        }
        
        return metadata
    
    @staticmethod
    def _severity_to_name(severity: str) -> str:
        """
        Convert severity number to name.
        
        Args:
            severity (str): Severity level as string
            
        Returns:
            str: Severity name
        """
        severity_map = {
            '0': 'Info',
            '1': 'Low',
            '2': 'Medium',
            '3': 'High',
            '4': 'Critical'
        }
        
        return severity_map.get(severity, 'Unknown')
