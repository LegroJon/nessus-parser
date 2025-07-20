"""
Nessus XML Parser Module

This module provides functionality to parse Nessus XML files and extract vulnerability data.
"""

import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
import logging

logger = logging.getLogger(__name__)


class NessusParser:
    """Parser for Nessus XML vulnerability scan files."""
    
    def __init__(self, file_path: str):
        """
        Initialize the NessusParser with a file path.
        
        Args:
            file_path (str): Path to the Nessus XML file
        """
        self.file_path = file_path
        self.tree = None
        self.root = None
        
    def parse(self) -> Dict:
        """
        Parse the Nessus XML file and return structured data.
        
        Returns:
            Dict: Parsed vulnerability data
        """
        try:
            self.tree = ET.parse(self.file_path)
            self.root = self.tree.getroot()
            
            scan_data = {
                'policy_name': self._get_policy_name(),
                'scan_name': self._get_scan_name(),
                'hosts': self._parse_hosts(),
                'vulnerabilities': self._parse_vulnerabilities()
            }
            
            logger.info(f"Successfully parsed {self.file_path}")
            return scan_data
            
        except ET.ParseError as e:
            logger.error(f"Error parsing XML file: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            raise
    
    def _get_policy_name(self) -> Optional[str]:
        """Extract the policy name from the scan."""
        policy = self.root.find('.//Policy/policyName')
        return policy.text if policy is not None else None
    
    def _get_scan_name(self) -> Optional[str]:
        """Extract the scan name."""
        name = self.root.find('.//Policy/policyName')
        return name.text if name is not None else None
    
    def _parse_hosts(self) -> List[Dict]:
        """Parse host information from the scan."""
        hosts = []
        
        for report_host in self.root.findall('.//ReportHost'):
            host_data = {
                'name': report_host.get('name'),
                'properties': {},
                'vulnerabilities': []
            }
            
            # Extract host properties
            for tag in report_host.findall('.//tag'):
                tag_name = tag.get('name')
                host_data['properties'][tag_name] = tag.text
            
            # Extract vulnerabilities for this host
            for item in report_host.findall('.//ReportItem'):
                vuln = self._parse_vulnerability_item(item)
                host_data['vulnerabilities'].append(vuln)
            
            hosts.append(host_data)
        
        return hosts
    
    def _parse_vulnerabilities(self) -> List[Dict]:
        """Parse all vulnerabilities from the scan."""
        vulnerabilities = []
        
        for item in self.root.findall('.//ReportItem'):
            vuln = self._parse_vulnerability_item(item)
            vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _parse_vulnerability_item(self, item) -> Dict:
        """Parse a single vulnerability item."""
        vuln_data = {
            'plugin_id': item.get('pluginID'),
            'plugin_name': item.get('pluginName'),
            'severity': item.get('severity'),
            'port': item.get('port'),
            'protocol': item.get('protocol'),
            'service_name': item.get('svc_name'),
            'description': None,
            'solution': None,
            'risk_factor': None,
            'cvss_score': None,
            'cve': []
        }
        
        # Extract additional vulnerability details
        for child in item:
            if child.tag == 'description':
                vuln_data['description'] = child.text
            elif child.tag == 'solution':
                vuln_data['solution'] = child.text
            elif child.tag == 'risk_factor':
                vuln_data['risk_factor'] = child.text
            elif child.tag == 'cvss_base_score':
                vuln_data['cvss_score'] = child.text
            elif child.tag == 'cve':
                vuln_data['cve'].append(child.text)
        
        return vuln_data
