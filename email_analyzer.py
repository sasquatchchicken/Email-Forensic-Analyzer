#!/usr/bin/env python3
"""
Enhanced Email Security Analyzer

A comprehensive tool for analyzing email headers, authentication mechanisms,
attachments, and potential threats in email messages.
"""

import argparse
import dkim
import dns.resolver
import email
import geoip2.database
import hashlib
import ipaddress
import magic
import os
import re
import requests
import tempfile
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from email import policy
from email.parser import BytesParser
from oletools.olevba import VBA_Parser, VBA_Scanner
from urllib.parse import urlparse
from typing import List, Dict, Tuple, Optional

# Initialize colorama
init(autoreset=True)

class EmailAnalyzer:
    """Main email analysis class with enhanced features."""
    
    def __init__(self):
        # DNS Resolver Configuration
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 3
        self.resolver.lifetime = 5
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1']  # Google and Cloudflare DNS
        
        # Threat intelligence API configuration
        self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY', '')
        self.ipqualityscore_api_key = os.getenv('IPQS_API_KEY', '')
        
        # File type identification
        self.mime = magic.Magic(mime=True)
        
        # Regex patterns compiled once for performance
        self.ip_pattern = re.compile(
            r'(?<![:.\w])(?:'
            r'((?:(?:25[0-5]|2[0-4]\d|1\d\d|\d\d?)(?:\.(?!$)){3}'
            r'(?:25[0-5]|2[0-4]\d|1\d\d|\d\d?))'
            r'|([a-fA-F0-9:]+:+)+[a-fA-F0-9]+)'
            r')(?![:.\w])'
        )
        
        # Suspicious file extensions
        self.suspicious_exts = (
            ".exe", ".scr", ".bat", ".js", ".vbs", ".jar", 
            ".ps1", ".dll", ".cmd", ".wsf", ".hta", ".lnk"
        )
        
        # Known malicious domains/IPs cache
        self.threat_cache = set()

    def extract_ips_from_headers(self, headers) -> List[str]:
        """Extract and validate public IPs from email headers."""
        received_headers = headers.get_all("Received", [])
        originating_ip = headers.get("X-Originating-IP", "")
        x_sender_ip = headers.get("X-Sender-IP", "")

        public_ips = []

        # Process Received headers
        for header in received_headers:
            matches = self.ip_pattern.findall(header)
            for match in matches:
                ip = match[0]
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if not ip_obj.is_private and not ip_obj.is_loopback:
                        public_ips.append(ip)
                except ValueError:
                    continue

        # Process X-Originating-IP and X-Sender-IP
        for ip_field in [originating_ip, x_sender_ip]:
            if not ip_field:
                continue
            match = re.search(r'[\[\(]?((?:\d{1,3}\.){3}\d{1,3}|[a-fA-F0-9:]+)[\]\)]?', ip_field)
            if match:
                ip = match.group(1)
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    if not ip_obj.is_private and not ip_obj.is_loopback:
                        public_ips.append(ip)
                except ValueError:
                    pass

        return list(set(public_ips))  # Remove duplicates

    def validate_spf(self, ip: str, domain: str) -> str:
        """Validate SPF record with detailed results."""
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt = b''.join(rdata.strings).decode()
                if txt.startswith("v=spf1"):
                    if f"ip4:{ip}" in txt or f"ip6:{ip}" in txt:
                        return f"{Fore.GREEN}SPF pass (IP authorized){Style.RESET_ALL}"
                    elif "-all" in txt:
                        return f"{Fore.RED}SPF fail (strict policy, IP unauthorized){Style.RESET_ALL}"
                    elif "~all" in txt:
                        return f"{Fore.YELLOW}SPF softfail (IP not explicitly authorized){Style.RESET_ALL}"
                    elif "?all" in txt:
                        return f"{Fore.BLUE}SPF neutral (no explicit policy){Style.RESET_ALL}"
                    return f"{Fore.YELLOW}SPF record found, but unable to determine result{Style.RESET_ALL}"
        except dns.resolver.NXDOMAIN:
            return f"{Fore.RED}No SPF record found (domain does not exist){Style.RESET_ALL}"
        except dns.resolver.NoAnswer:
            return f"{Fore.RED}No SPF record found (no TXT records){Style.RESET_ALL}"
        except Exception as e:
            return f"{Fore.RED}SPF validation failed: {e}{Style.RESET_ALL}"
        return f"{Fore.RED}No SPF record found{Style.RESET_ALL}"

    def parse_dmarc_record(self, domain: str) -> str:
        """Parse DMARC record with detailed tag analysis."""
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = self.resolver.resolve(dmarc_domain, 'TXT')
            
            results = []
            for rdata in answers:
                txt = b''.join(rdata.strings).decode()
                if "v=DMARC1" in txt:
                    results.append(f"{Fore.CYAN}DMARC Record:{Style.RESET_ALL} {txt}")
                    
                    # Parse tags
                    tags = dict(re.findall(r'(\w+)=([^;\s]+)', txt))
                    
                    # Policy analysis
                    policy_map = {
                        'none': f"{Fore.BLUE}No action taken (monitoring only){Style.RESET_ALL}",
                        'quarantine': f"{Fore.YELLOW}Messages failing DMARC may be quarantined{Style.RESET_ALL}",
                        'reject': f"{Fore.RED}Messages failing DMARC should be rejected{Style.RESET_ALL}"
                    }
                    
                    if 'p' in tags:
                        results.append(f"Policy: {policy_map.get(tags['p'].lower(), tags['p'])}")
                    
                    # Subdomain policy
                    if 'sp' in tags:
                        results.append(f"Subdomain Policy: {policy_map.get(tags['sp'].lower(), tags['sp'])}")
                    
                    # Reporting
                    if 'rua' in tags:
                        results.append(f"Aggregate Reports: {tags['rua']}")
                    if 'ruf' in tags:
                        results.append(f"Forensic Reports: {tags['ruf']}")
                    
                    # Alignment
                    if 'adkim' in tags:
                        results.append(f"DKIM Alignment: {'Strict' if tags['adkim'] == 's' else 'Relaxed'}")
                    if 'aspf' in tags:
                        results.append(f"SPF Alignment: {'Strict' if tags['aspf'] == 's' else 'Relaxed'}")
                    
                    # Failure reporting options
                    if 'fo' in tags:
                        fo_map = {
                            '0': "Generate reports if all mechanisms fail",
                            '1': "Generate reports if any mechanism fails",
                            'd': "Generate DKIM failure reports",
                            's': "Generate SPF failure reports"
                        }
                        results.append("Failure Reporting: " + ", ".join(fo_map.get(c, c) for c in tags['fo']))
                    
                    # Percent enforcement
                    if 'pct' in tags:
                        results.append(f"Percentage Applied: {tags['pct']}%")
                    
                    return "\n".join(results)
        except dns.resolver.NXDOMAIN:
            return f"{Fore.RED}No DMARC record found (domain does not exist){Style.RESET_ALL}"
        except dns.resolver.NoAnswer:
            return f"{Fore.RED}No DMARC record found (no TXT records){Style.RESET_ALL}"
        except Exception as e:
            return f"{Fore.RED}DMARC check failed: {e}{Style.RESET_ALL}"
        return f"{Fore.RED}No DMARC policy found{Style.RESET_ALL}"

    def geolocate_ip(self, ip: str) -> str:
        """Get geolocation and ASN information for an IP address."""
        try:
            # Try local GeoLite2 database first
            with geoip2.database.Reader('GeoLite2-City.mmdb') as reader:
                response = reader.city(ip)
                location_parts = []
                if response.city.name:
                    location_parts.append(response.city.name)
                if response.subdivisions.most_specific.name:
                    location_parts.append(response.subdivisions.most_specific.name)
                if response.country.name:
                    location_parts.append(response.country.name)
                
                location = ", ".join(location_parts)
                asn = f"AS{response.traits.autonomous_system_number}" if response.traits.autonomous_system_number else ""
                org = response.traits.autonomous_system_organization or ""
                
                return f"{location} ({asn} {org})".strip()
        except Exception:
            pass
        
        # Fallback to ipinfo.io
        try:
            r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
            if r.status_code == 200:
                data = r.json()
                location_parts = [
                    data.get('city', ''),
                    data.get('region', ''),
                    data.get('country', '')
                ]
                location = ", ".join(filter(None, location_parts))
                asn = data.get('org', '')
                return f"{location} ({asn})" if location else asn
        except Exception:
            pass
        
        return "Geolocation unavailable"

    def verify_dkim(self, raw_bytes: bytes) -> Tuple[bool, str]:
        """Verify DKIM signature with detailed error reporting."""
        try:
            d = dkim.DKIM(raw_bytes)
            result = d.verify()
            return (True, f"{Fore.GREEN}DKIM signature valid{Style.RESET_ALL}")
        except dkim.DKIMException as e:
            error_msg = str(e).lower()
            if "body hash did not verify" in error_msg:
                return (False, f"{Fore.RED}DKIM verification failed: Body hash mismatch (email may have been altered){Style.RESET_ALL}")
            elif "signature verification failed" in error_msg:
                return (False, f"{Fore.RED}DKIM verification failed: Cryptographic signature invalid{Style.RESET_ALL}")
            elif "no signature" in error_msg:
                return (False, f"{Fore.YELLOW}No DKIM signature found{Style.RESET_ALL}")
            return (False, f"{Fore.RED}DKIM verification failed: {e}{Style.RESET_ALL}")
        except Exception as e:
            return (False, f"{Fore.RED}Unexpected error during DKIM verification: {e}{Style.RESET_ALL}")

    def extract_dkim_signature(self, raw_bytes: bytes) -> str:
        """Extract and format DKIM signature details."""
        try:
            raw = raw_bytes.decode(errors='ignore').replace('\r\n', '\n').replace('\r', '\n')
            unfolded = re.sub(r'\n([ \t]+)', ' ', raw)
            match = re.search(r'DKIM-Signature:\s*(.*?)(?=\n\S|$)', unfolded, re.DOTALL)
            if match:
                dkim_header = match.group(1).strip()
                details = [f"{Fore.CYAN}DKIM Signature Found:{Style.RESET_ALL}"]
                
                # Extract and explain common tags
                tag_explanations = {
                    'v': ('Version', None),
                    'a': ('Algorithm', {
                        'rsa-sha1': 'RSA with SHA-1 (weak)',
                        'rsa-sha256': 'RSA with SHA-256'
                    }),
                    'd': ('Signing Domain', None),
                    's': ('Selector', None),
                    'bh': ('Body Hash', None),
                    'b': ('Signature Data', None),
                    'h': ('Signed Headers', None),
                    't': ('Timestamp', lambda x: f"{x} ({self._format_timestamp(x)})"),
                    'x': ('Expiration', lambda x: f"{x} ({self._format_timestamp(x)})"),
                    'c': ('Canonicalization', {
                        'simple/simple': 'Both header and body use simple canonicalization',
                        'relaxed/relaxed': 'Both header and body use relaxed canonicalization',
                        'simple/relaxed': 'Simple header, relaxed body canonicalization',
                        'relaxed/simple': 'Relaxed header, simple body canonicalization'
                    })
                }
                
                for tag, value in re.findall(r'(\w+)=([^;]+)', dkim_header):
                    if tag in tag_explanations:
                        name, explanations = tag_explanations[tag]
                        formatted_value = value
                        
                        if explanations:
                            if isinstance(explanations, dict):
                                formatted_value = explanations.get(value, value)
                            elif callable(explanations):
                                formatted_value = explanations(value)
                        
                        details.append(f"{tag} ({name}): {formatted_value}")
                    else:
                        details.append(f"{tag}: {value}")
                
                return "\n".join(details)
            return f"{Fore.YELLOW}No DKIM signature found in headers.{Style.RESET_ALL}"
        except Exception as e:
            return f"{Fore.RED}Failed to extract DKIM signature: {e}{Style.RESET_ALL}"

    def _format_timestamp(self, ts: str) -> str:
        """Format UNIX timestamp for display."""
        try:
            from datetime import datetime
            return datetime.utcfromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M:%S UTC')
        except:
            return "Invalid timestamp"

    def analyze_authentication_results(self, msg) -> str:
        """Parse and interpret Authentication-Results header."""
        results = []
        auth_headers = msg.get_all("Authentication-Results", [])
        
        if not auth_headers:
            return f"{Fore.YELLOW}No Authentication-Results header found.{Style.RESET_ALL}"
        
        for header in auth_headers:
            results.append(f"{Fore.MAGENTA}Authentication-Results:{Style.RESET_ALL} {header}")
            
            # SPF results
            spf_matches = re.finditer(r'spf=(\w+)', header)
            for match in spf_matches:
                result = match.group(1).lower()
                if result == 'pass':
                    results.append(f"SPF: {Fore.GREEN}Pass{Style.RESET_ALL}")
                elif result == 'fail':
                    results.append(f"SPF: {Fore.RED}Fail{Style.RESET_ALL}")
                else:
                    results.append(f"SPF: {Fore.YELLOW}{result.title()}{Style.RESET_ALL}")
            
            # DKIM results
            dkim_matches = re.finditer(r'dkim=(\w+)', header)
            for match in dkim_matches:
                result = match.group(1).lower()
                if result == 'pass':
                    results.append(f"DKIM: {Fore.GREEN}Pass{Style.RESET_ALL}")
                elif result == 'fail':
                    results.append(f"DKIM: {Fore.RED}Fail{Style.RESET_ALL}")
                else:
                    results.append(f"DKIM: {Fore.YELLOW}{result.title()}{Style.RESET_ALL}")
            
            # DMARC results
            dmarc_matches = re.finditer(r'dmarc=(\w+)', header)
            for match in dmarc_matches:
                result = match.group(1).lower()
                if result == 'pass':
                    results.append(f"DMARC: {Fore.GREEN}Pass{Style.RESET_ALL}")
                elif result == 'fail':
                    results.append(f"DMARC: {Fore.RED}Fail{Style.RESET_ALL}")
                else:
                    results.append(f"DMARC: {Fore.YELLOW}{result.title()}{Style.RESET_ALL}")
            
            # Client IP
            ip_match = re.search(r'client-ip=([\d\.:a-fA-F]+)', header)
            if ip_match:
                ip = ip_match.group(1)
                results.append(f"Client IP: {ip}")
                results.append(f"Geolocation: {self.geolocate_ip(ip)}")
            
            # ARC results
            arc_result = re.search(r'arc=(\w+)', header)
            if arc_result:
                result = arc_result.group(1).lower()
                if result == 'pass':
                    results.append(f"ARC: {Fore.GREEN}Pass{Style.RESET_ALL}")
                elif result == 'fail':
                    results.append(f"ARC: {Fore.RED}Fail{Style.RESET_ALL}")
                else:
                    results.append(f"ARC: {Fore.YELLOW}{result.title()}{Style.RESET_ALL}")
            
            # BIMI results
            bimi_result = re.search(r'bimi=(\w+)', header)
            if bimi_result:
                result = bimi_result.group(1).lower()
                if result == 'pass':
                    results.append(f"BIMI: {Fore.GREEN}Pass{Style.RESET_ALL}")
                elif result == 'fail':
                    results.append(f"BIMI: {Fore.RED}Fail{Style.RESET_ALL}")
                else:
                    results.append(f"BIMI: {Fore.YELLOW}{result.title()}{Style.RESET_ALL}")
        
        return "\n".join(results)

    def extract_urls(self, msg) -> Dict[str, List[str]]:
        """Extract URLs from all parts of the email."""
        urls = {
            'html': [],
            'plaintext': [],
            'headers': []
        }
        
        # URLs from headers
        for header in ['From', 'To', 'Cc', 'Reply-To', 'Return-Path', 'List-Unsubscribe']:
            value = msg.get(header, '')
            if value:
                urls['headers'].extend(re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', value))
        
        # URLs from message body
        for part in msg.walk():
            content_type = part.get_content_type()
            payload = part.get_payload(decode=True)
            
            if not payload:
                continue
                
            try:
                payload_text = payload.decode('utf-8', errors='ignore')
            except:
                continue
                
            if 'html' in content_type:
                soup = BeautifulSoup(payload_text, 'html.parser')
                for a in soup.find_all('a', href=True):
                    urls['html'].append(a['href'])
                for img in soup.find_all('img', src=True):
                    urls['html'].append(img['src'])
                urls['html'].extend(re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', payload_text))
            elif 'plain' in content_type:
                urls['plaintext'].extend(re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', payload_text))
        
        # Deduplicate URLs
        for key in urls:
            urls[key] = list(set(urls[key]))
            
        return urls

    def analyze_urls(self, urls: List[str]) -> str:
        """Analyze URLs for potential threats."""
        if not urls:
            return "No URLs found to analyze."
        
        results = []
        suspicious_domains = set()
        
        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()
                
                # Check for IP addresses in URL
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
                    results.append(f"{Fore.RED}URL with IP address: {url}{Style.RESET_ALL}")
                    continue
                
                # Check for suspicious TLDs
                suspicious_tlds = ('.ru', '.su', '.cn', '.top', '.xyz', '.gq', '.ml', '.tk')
                if domain.endswith(suspicious_tlds):
                    results.append(f"{Fore.YELLOW}URL with suspicious TLD: {url}{Style.RESET_ALL}")
                    suspicious_domains.add(domain)
                    continue
                
                # Check for URL shorteners
                shorteners = ('bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co', 'is.gd')
                if any(s in domain for s in shorteners):
                    results.append(f"{Fore.YELLOW}URL shortener detected: {url}{Style.RESET_ALL}")
                    suspicious_domains.add(domain)
                    continue
                
                # Check for known malicious patterns
                malicious_patterns = (
                    'login', 'verify', 'account', 'secure', 'update', 'confirm',
                    'password', 'banking', 'paypal', 'amazon', 'ebay'
                )
                if any(p in parsed.path.lower() for p in malicious_patterns):
                    results.append(f"{Fore.YELLOW}URL with suspicious path: {url}{Style.RESET_ALL}")
                    suspicious_domains.add(domain)
                
            except Exception as e:
                results.append(f"{Fore.RED}Error analyzing URL {url}: {e}{Style.RESET_ALL}")
        
        if suspicious_domains:
            results.append(f"\n{Fore.RED}⚠ Suspicious domains detected:{Style.RESET_ALL}")
            for domain in sorted(suspicious_domains):
                results.append(f"- {domain}")
        
        return "\n".join(results) if results else "No obviously suspicious URLs found."

    def check_ip_reputation(self, ip: str) -> str:
        """Check IP reputation using multiple methods."""
        results = []
        
        # Check if IP is private
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return f"{Fore.YELLOW}Private IP address detected{Style.RESET_ALL}"
        except ValueError:
            pass
        
        # Check against known threat lists
        if self._check_ip_against_threat_lists(ip):
            results.append(f"{Fore.RED}IP found in threat intelligence feeds{Style.RESET_ALL}")
        
        # Check with VirusTotal if API key is available
        if self.virustotal_api_key:
            vt_result = self._check_ip_virustotal(ip)
            if vt_result:
                results.append(vt_result)
        
        # Check with IPQualityScore if API key is available
        if self.ipqualityscore_api_key:
            ipqs_result = self._check_ipqualityscore(ip)
            if ipqs_result:
                results.append(ipqs_result)
        
        # Basic geolocation risk assessment
        geo_info = self.geolocate_ip(ip)
        if any(r in geo_info.lower() for r in ('russia', 'china', 'iran', 'north korea')):
            results.append(f"{Fore.YELLOW}IP geolocated to high-risk country: {geo_info}{Style.RESET_ALL}")
        
        return "\n".join(results) if results else f"{Fore.GREEN}No reputation issues found{Style.RESET_ALL}"

    def _check_ip_against_threat_lists(self, ip: str) -> bool:
        """Check IP against local threat lists (placeholder implementation)."""
        # In a real implementation, you would check against known malicious IP lists
        return False

    def _check_ip_virustotal(self, ip: str) -> Optional[str]:
        """Check IP reputation with VirusTotal."""
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"x-apikey": self.virustotal_api_key}
            
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                last_analysis_stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = last_analysis_stats.get('malicious', 0)
                suspicious = last_analysis_stats.get('suspicious', 0)
                
                if malicious > 0 or suspicious > 0:
                    return f"{Fore.RED}VirusTotal: {malicious} malicious, {suspicious} suspicious detections{Style.RESET_ALL}"
                return f"{Fore.GREEN}VirusTotal: No malicious detections{Style.RESET_ALL}"
            return None
        except Exception:
            return None

    def _check_ipqualityscore(self, ip: str) -> Optional[str]:
        """Check IP reputation with IPQualityScore."""
        try:
            url = f"https://www.ipqualityscore.com/api/json/ip/{self.ipqualityscore_api_key}/{ip}"
            params = {
                'strictness': 1,
                'allow_public_access_points': 'true',
                'fast': 'false'
            }
            
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('success', False) is False:
                    return None
                
                results = []
                if data.get('proxy', False):
                    results.append("proxy")
                if data.get('vpn', False):
                    results.append("VPN")
                if data.get('tor', False):
                    results.append("TOR")
                if data.get('active_vpn', False):
                    results.append("active VPN")
                if data.get('active_tor', False):
                    results.append("active TOR")
                if data.get('bot_status', False):
                    results.append("bot")
                
                fraud_score = data.get('fraud_score', 0)
                if fraud_score > 85:
                    results.append(f"high risk ({fraud_score}%)")
                
                if results:
                    return f"{Fore.RED}IPQS: {', '.join(results)}{Style.RESET_ALL}"
                return f"{Fore.GREEN}IPQS: No issues detected{Style.RESET_ALL}"
            return None
        except Exception:
            return None

    def analyze_attachments(self, msg) -> Tuple[str, List[Dict]]:
        """Analyze email attachments for potential threats."""
        attachments = []
        analysis_results = []
        
        for part in msg.walk():
            content_type = part.get_content_type()
            filename = part.get_filename()
            content_disposition = str(part.get("Content-Disposition", ""))
            
            if not filename and 'attachment' not in content_disposition.lower():
                continue
                
            try:
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                    
                size_kb = len(payload) / 1024
                file_hash = hashlib.sha256(payload).hexdigest()
                
                # Get file type
                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                    temp_file.write(payload)
                    temp_path = temp_file.name
                
                try:
                    file_type = self.mime.from_file(temp_path)
                    os.unlink(temp_path)
                except:
                    file_type = "unknown"
                    try:
                        os.unlink(temp_path)
                    except:
                        pass
                
                attachment_info = {
                    'filename': filename or 'unnamed',
                    'content_type': content_type,
                    'size_kb': size_kb,
                    'file_type': file_type,
                    'sha256': file_hash,
                    'suspicious': False,
                    'threats': []
                }
                
                # Check for suspicious extensions
                if filename:
                    lower_filename = filename.lower()
                    if any(lower_filename.endswith(ext) for ext in self.suspicious_exts):
                        attachment_info['suspicious'] = True
                        attachment_info['threats'].append("suspicious file extension")
                
                # Check for Office documents with macros
                if filename and filename.lower().endswith(('.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm')):
                    macro_result = self._check_for_macros(payload, filename)
                    if macro_result:
                        attachment_info['suspicious'] = True
                        attachment_info['threats'].append(macro_result)
                
                # Check for executables
                if 'executable' in file_type.lower() or 'dll' in file_type.lower():
                    attachment_info['suspicious'] = True
                    attachment_info['threats'].append("executable file detected")
                
                attachments.append(attachment_info)
                
            except Exception as e:
                analysis_results.append(f"{Fore.RED}Error analyzing attachment {filename}: {e}{Style.RESET_ALL}")
                continue
        
        # Format results
        if not attachments:
            return "No attachments found.", []
            
        result_lines = [f"{Fore.CYAN}\nAttachment Analysis:{Style.RESET_ALL}"]
        
        for att in attachments:
            line = f"\n- {att['filename']} ({att['file_type']}, {att['size_kb']:.2f} KB)"
            if att['suspicious']:
                line = f"{Fore.RED}{line} ⚠{Style.RESET_ALL}"
                for threat in att['threats']:
                    line += f"\n  {Fore.RED}⚠ {threat}{Style.RESET_ALL}"
            result_lines.append(line)
            result_lines.append(f"  SHA256: {att['sha256']}")
        
        return "\n".join(result_lines), attachments

    def _check_for_macros(self, payload: bytes, filename: str) -> Optional[str]:
        """Check for VBA macros in Office documents."""
        try:
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_file.write(payload)
                temp_path = temp_file.name
            
            try:
                vba = VBA_Parser(temp_path)
                if vba.detect_vba_macros():
                    macro_code = vba.extract_macros()
                    if macro_code:
                        # Check for suspicious keywords
                        suspicious_keywords = (
                            'Shell', 'Execute', 'Run', 'CreateObject', 'ActiveX',
                            'WScript.Shell', 'ADODB.Stream', 'GetObject', 'Kill',
                            'DeleteFile', 'Write', 'Put', 'SendKeys', 'AutoOpen',
                            'DocumentOpen', 'Workbook_Open'
                        )
                        
                        for _, _, _, code in macro_code:
                            if any(keyword.lower() in code.lower() for keyword in suspicious_keywords):
                                return "suspicious VBA macros detected"
                        return "VBA macros detected"
                return None
            finally:
                try:
                    os.unlink(temp_path)
                except:
                    pass
        except Exception:
            return None

    def analyze_email_headers(self, msg) -> str:
        """Analyze email headers for anomalies."""
        results = []
        
        # Check for common spoofing indicators
        from_header = msg.get('From', '')
        return_path = msg.get('Return-Path', '')
        reply_to = msg.get('Reply-To', '')
        
        # Check for From/Return-Path mismatch
        if from_header and return_path:
            from_domain = re.search(r'@([\w\.-]+)', from_header)
            rp_domain = re.search(r'@([\w\.-]+)', return_path)
            
            if from_domain and rp_domain and from_domain.group(1).lower() != rp_domain.group(1).lower():
                results.append(
                    f"{Fore.RED}From/Return-Path domain mismatch: "
                    f"From={from_domain.group(1)}, Return-Path={rp_domain.group(1)}{Style.RESET_ALL}"
                )
        
        # Check for Reply-To different from From
        if from_header and reply_to:
            from_email = re.search(r'[\w\.-]+@[\w\.-]+', from_header)
            reply_email = re.search(r'[\w\.-]+@[\w\.-]+', reply_to)
            
            if from_email and reply_email and from_email.group(0).lower() != reply_email.group(0).lower():
                results.append(
                    f"{Fore.YELLOW}From/Reply-To address mismatch: "
                    f"From={from_email.group(0)}, Reply-To={reply_email.group(0)}{Style.RESET_ALL}"
                )
        
        # Check for missing Message-ID
        if not msg.get('Message-ID'):
            results.append(f"{Fore.YELLOW}Missing Message-ID header{Style.RESET_ALL}")
        
        # Check for suspicious headers
        suspicious_headers = {
            'X-Mailer': 'Generic mailer often used by spammers',
            'X-Priority': 'Potential priority inflation',
            'X-MSMail-Priority': 'Potential priority inflation',
            'X-Originating-IP': 'Could be forged',
            'X-Sender-IP': 'Could be forged'
        }
        
        for header, reason in suspicious_headers.items():
            if msg.get(header):
                results.append(f"{Fore.YELLOW}Suspicious header: {header} ({reason}){Style.RESET_ALL}")
        
        # Check for Received header anomalies
        received_headers = msg.get_all('Received', [])
        if len(received_headers) < 1:
            results.append(f"{Fore.RED}Only one or no Received headers (possible forgery){Style.RESET_ALL}")
        else:
            # Check for IP mismatches in Received headers
            ips = self.extract_ips_from_headers(msg)
            if len(ips) > 1:
                first_ip = ips[0]
                last_ip = ips[-1]
                if first_ip != last_ip:
                    results.append(
                        f"{Fore.YELLOW}First and last hop IPs differ: "
                        f"first={first_ip}, last={last_ip}{Style.RESET_ALL}"
                    )
        
        return "\n".join(results) if results else "No obvious header anomalies detected."

    def analyze(self, file_path: str) -> Dict:
        """Main analysis function."""
        try:
            with open(file_path, 'rb') as f:
                raw_bytes = f.read()
            
            msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
            
            results = {
                'basic_info': {},
                'headers': {},
                'authentication': {},
                'urls': {},
                'attachments': {},
                'threats': []
            }
            
            # Basic email information
            results['basic_info']['From'] = msg['From']
            results['basic_info']['To'] = msg['To']
            results['basic_info']['Subject'] = msg['Subject']
            results['basic_info']['Date'] = msg['Date']
            
            # Header analysis
            ip_list = self.extract_ips_from_headers(msg)
            results['headers']['ips'] = ip_list
            if ip_list:
                results['headers']['sender_ip'] = ip_list[-1]
                results['headers']['geolocation'] = self.geolocate_ip(ip_list[-1])
                results['headers']['ip_reputation'] = self.check_ip_reputation(ip_list[-1])
            
            results['headers']['anomalies'] = self.analyze_email_headers(msg)
            
            # Authentication checks
            from_header = msg['From']
            domain_match = re.search(r'@([\w\.-]+)', from_header)
            domain = domain_match.group(1) if domain_match else None
            
            if domain and ip_list:
                results['authentication']['spf'] = self.validate_spf(ip_list[-1], domain)
                results['authentication']['dmarc'] = self.parse_dmarc_record(domain)
            
            dkim_valid, dkim_result = self.verify_dkim(raw_bytes)
            results['authentication']['dkim'] = dkim_result
            results['authentication']['dkim_details'] = self.extract_dkim_signature(raw_bytes)
            
            results['authentication']['auth_results'] = self.analyze_authentication_results(msg)
            
            # URL analysis
            urls = self.extract_urls(msg)
            results['urls']['all'] = urls
            results['urls']['analysis'] = self.analyze_urls(urls['html'] + urls['plaintext'] + urls['headers'])
            
            # Attachment analysis
            attachment_report, attachments = self.analyze_attachments(msg)
            results['attachments']['report'] = attachment_report
            results['attachments']['details'] = attachments
            
            # Collect threats
            if "Fail" in results['authentication']['spf']:
                results['threats'].append("SPF validation failed")
            if "Fail" in results['authentication']['dmarc']:
                results['threats'].append("DMARC validation failed")
            if not dkim_valid:
                results['threats'].append("DKIM validation failed")
            
            for att in attachments:
                if att['suspicious']:
                    results['threats'].append(f"Suspicious attachment: {att['filename']}")
            
            if "suspicious" in results['urls']['analysis'].lower():
                results['threats'].append("Suspicious URLs detected")
            
            return results
            
        except Exception as e:
            return {'error': str(e)}

    def print_results(self, results: Dict):
        """Print analysis results in a readable format."""
        if 'error' in results:
            print(f"{Fore.RED}Error analyzing email: {results['error']}{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}{'='*40}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'Email Analysis Report':^40}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*40}{Style.RESET_ALL}")
        
        # Basic info
        print(f"\n{Fore.YELLOW}Basic Information:{Style.RESET_ALL}")
        for key, value in results['basic_info'].items():
            print(f"{key}: {value}")
        
        # Header analysis
        print(f"\n{Fore.YELLOW}Header Analysis:{Style.RESET_ALL}")
        if results['headers'].get('sender_ip'):
            print(f"Sender IP: {results['headers']['sender_ip']}")
            print(f"Geolocation: {results['headers']['geolocation']}")
            print(f"Reputation: {results['headers']['ip_reputation']}")
        
        print(f"\nHeader Anomalies:")
        print(results['headers']['anomalies'] or "No anomalies detected")
        
        # Authentication results
        print(f"\n{Fore.YELLOW}Authentication Results:{Style.RESET_ALL}")
        if results['authentication'].get('spf'):
            print(f"\nSPF Check:")
            print(results['authentication']['spf'])
        
        if results['authentication'].get('dmarc'):
            print(f"\nDMARC Check:")
            print(results['authentication']['dmarc'])
        
        print(f"\nDKIM Verification:")
        print(results['authentication']['dkim'])
        
        print(f"\nDKIM Signature Details:")
        print(results['authentication']['dkim_details'])
        
        print(f"\nAuthentication-Results Header:")
        print(results['authentication']['auth_results'])
        
        # URL analysis
        print(f"\n{Fore.YELLOW}URL Analysis:{Style.RESET_ALL}")
        print(results['urls']['analysis'])
        
        # Attachment analysis
        print(results['attachments']['report'])
        
        # Threat summary
        if results['threats']:
            print(f"\n{Fore.RED}{'⚠ Threat Summary ':-^40}{Style.RESET_ALL}")
            for threat in results['threats']:
                print(f"- {threat}")
        else:
            print(f"\n{Fore.GREEN}No significant threats detected{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}{'Analysis Complete':^40}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(
        description="Enhanced Email Security Analyzer",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("file", help="Path to the email file (.eml or .msg)")
    parser.add_argument("--json", help="Output results in JSON format", action="store_true")
    args = parser.parse_args()
    
    analyzer = EmailAnalyzer()
    results = analyzer.analyze(args.file)
    
    if args.json:
        import json
        print(json.dumps(results, indent=2))
    else:
        analyzer.print_results(results)

if __name__ == "__main__":
    main()
