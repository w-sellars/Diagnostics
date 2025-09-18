#!/usr/bin/env python3
"""
Network Connection Tester with Proxy Detection
Tests outbound network connections through unknown proxy servers using urllib.
"""

import urllib.request
import urllib.error
import urllib.parse
import socket
import time
import sys
import os
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict


@dataclass
class ConnectionResult:
    """Data class to store connection test results."""
    url: str
    proxy: Optional[str]
    success: bool
    response_code: Optional[int]
    response_time: float
    error_message: Optional[str]
    headers: Optional[Dict[str, str]] = None


class ProxyConnectionTester:
    """Test network connections through various proxy configurations."""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.test_urls = [
            'http://httpbin.org/ip',
            'https://httpbin.org/ip',
            'http://www.google.com',
            'https://www.google.com',
            'http://example.com',
            'https://example.com'
        ]
        
    def detect_system_proxy(self) -> Dict[str, Optional[str]]:
        """Detect system proxy settings from environment variables."""
        proxy_vars = {
            'http_proxy': os.getenv('http_proxy') or os.getenv('HTTP_PROXY'),
            'https_proxy': os.getenv('https_proxy') or os.getenv('HTTPS_PROXY'),
            'ftp_proxy': os.getenv('ftp_proxy') or os.getenv('FTP_PROXY'),
            'no_proxy': os.getenv('no_proxy') or os.getenv('NO_PROXY')
        }
        auto_proxy_vars = urllib.request.getproxies

        print("Env Proxy Vars")
        print(proxy_vars)

        print("Auto Proxy Vars")
        print(auto_proxy_vars)

        choice = input("Enter your choice (env or auto): ")

        if choice == "auto":
            return proxy_vars
        else:
            return proxy_vars

    def test_direct_connection(self, url: str) -> ConnectionResult:
        """Test direct connection without proxy."""
        start_time = time.time()
        
        try:
            # Create request with no proxy
            opener = urllib.request.build_opener()
            opener.addheaders = [('User-Agent', 'ProxyTester/1.0')]
            
            request = urllib.request.Request(url)
            response = opener.open(request, timeout=self.timeout)
            
            response_time = time.time() - start_time
            headers = dict(response.headers)
            
            return ConnectionResult(
                url=url,
                proxy=None,
                success=True,
                response_code=response.getcode(),
                response_time=response_time,
                error_message=None,
                headers=headers
            )
            
        except urllib.error.HTTPError as e:
            return ConnectionResult(
                url=url,
                proxy=None,
                success=False,
                response_code=e.code,
                response_time=time.time() - start_time,
                error_message=f"HTTP Error: {e.code} - {e.reason}"
            )
        except urllib.error.URLError as e:
            return ConnectionResult(
                url=url,
                proxy=None,
                success=False,
                response_code=None,
                response_time=time.time() - start_time,
                error_message=f"URL Error: {e.reason}"
            )
        except socket.timeout:
            return ConnectionResult(
                url=url,
                proxy=None,
                success=False,
                response_code=None,
                response_time=time.time() - start_time,
                error_message="Connection timeout"
            )
        except Exception as e:
            return ConnectionResult(
                url=url,
                proxy=None,
                success=False,
                response_code=None,
                response_time=time.time() - start_time,
                error_message=f"Unexpected error: {str(e)}"
            )
    
    def test_proxy_connection(self, url: str, proxy_url: str) -> ConnectionResult:
        """Test connection through a specific proxy."""
        start_time = time.time()
        
        try:
            # Parse proxy URL to determine protocol
            parsed_proxy = urllib.parse.urlparse(proxy_url)
            if not parsed_proxy.scheme:
                proxy_url = f"http://{proxy_url}"
            
            # Create proxy handler
            proxy_handler = urllib.request.ProxyHandler({
                'http': proxy_url,
                'https': proxy_url
            })
            
            # Build opener with proxy
            opener = urllib.request.build_opener(proxy_handler)
            opener.addheaders = [('User-Agent', 'ProxyTester/1.0')]
            
            request = urllib.request.Request(url)
            response = opener.open(request, timeout=self.timeout)
            
            response_time = time.time() - start_time
            headers = dict(response.headers)
            
            return ConnectionResult(
                url=url,
                proxy=proxy_url,
                success=True,
                response_code=response.getcode(),
                response_time=response_time,
                error_message=None,
                headers=headers
            )
            
        except urllib.error.HTTPError as e:
            return ConnectionResult(
                url=url,
                proxy=proxy_url,
                success=False,
                response_code=e.code,
                response_time=time.time() - start_time,
                error_message=f"HTTP Error: {e.code} - {e.reason}"
            )
        except urllib.error.URLError as e:
            return ConnectionResult(
                url=url,
                proxy=proxy_url,
                success=False,
                response_code=None,
                response_time=time.time() - start_time,
                error_message=f"Proxy Error: {e.reason}"
            )
        except socket.timeout:
            return ConnectionResult(
                url=url,
                proxy=proxy_url,
                success=False,
                response_code=None,
                response_time=time.time() - start_time,
                error_message="Connection timeout"
            )
        except Exception as e:
            return ConnectionResult(
                url=url,
                proxy=proxy_url,
                success=False,
                response_code=None,
                response_time=time.time() - start_time,
                error_message=f"Unexpected error: {str(e)}"
            )
    
    def discover_proxy_servers(self) -> List[str]:
        """Attempt to discover potential proxy servers."""
        potential_proxies = []
        
        # Check environment variables
        system_proxies = self.detect_system_proxy()
        for proxy_type, proxy_url in system_proxies.items():
            if proxy_url and proxy_type != 'no_proxy':
                potential_proxies.append(proxy_url)
        
        # Common proxy ports on localhost and common network addresses
        common_hosts = ['127.0.0.1', 'localhost', '192.168.1.1', '10.0.0.1']
        common_ports = [8080, 3128, 8888, 8118, 1080, 3129, 8081]
        
        for host in common_hosts:
            for port in common_ports:
                potential_proxies.append(f"http://{host}:{port}")
        
        return list(set(potential_proxies))  # Remove duplicates
    
    def run_comprehensive_test(self, custom_proxies: Optional[List[str]] = None) -> Dict:
        """Run comprehensive network connectivity tests."""
        results = {
            'system_proxy_config': self.detect_system_proxy(),
            'direct_connections': [],
            'proxy_connections': [],
            'summary': {
                'total_tests': 0,
                'successful_tests': 0,
                'failed_tests': 0
            }
        }
        
        print("🔍 Starting Network Connection Tests...")
        print(f"⏱️  Timeout: {self.timeout} seconds\n")
        
        # Test direct connections
        print("📡 Testing direct connections (no proxy)...")
        for url in self.test_urls:
            print(f"  Testing: {url}")
            result = self.test_direct_connection(url)
            results['direct_connections'].append(asdict(result))
            results['summary']['total_tests'] += 1
            if result.success:
                results['summary']['successful_tests'] += 1
                print(f"    ✅ Success ({result.response_time:.2f}s)")
            else:
                results['summary']['failed_tests'] += 1
                print(f"    ❌ Failed: {result.error_message}")
        
        print()
        
        # Discover and test proxy connections
        discovered_proxies = self.discover_proxy_servers()
        if custom_proxies:
            discovered_proxies.extend(custom_proxies)
        
        if discovered_proxies:
            print(f"🔍 Testing {len(discovered_proxies)} discovered proxy servers...")
            for proxy in discovered_proxies:
                print(f"\n  🌐 Testing proxy: {proxy}")
                proxy_results = []
                
                for url in self.test_urls[:3]:  # Test fewer URLs for proxies
                    print(f"    Testing: {url}")
                    result = self.test_proxy_connection(url, proxy)
                    proxy_results.append(asdict(result))
                    results['summary']['total_tests'] += 1
                    
                    if result.success:
                        results['summary']['successful_tests'] += 1
                        print(f"      ✅ Success ({result.response_time:.2f}s)")
                    else:
                        results['summary']['failed_tests'] += 1
                        print(f"      ❌ Failed: {result.error_message}")
                
                results['proxy_connections'].append({
                    'proxy': proxy,
                    'results': proxy_results
                })
        else:
            print("🔍 No proxy servers discovered for testing")
        
        return results
    
    def save_results(self, results: Dict, filename: str = "network_test_results.json"):
        """Save test results to a JSON file."""
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n💾 Results saved to: {filename}")
        except Exception as e:
            print(f"\n❌ Failed to save results: {e}")
    
    def print_summary(self, results: Dict):
        """Print a summary of test results."""
        summary = results['summary']
        print(f"\n📊 Test Summary:")
        print(f"   Total tests: {summary['total_tests']}")
        print(f"   Successful: {summary['successful_tests']}")
        print(f"   Failed: {summary['failed_tests']}")
        print(f"   Success rate: {(summary['successful_tests']/summary['total_tests']*100):.1f}%")
        
        # Show system proxy config
        proxy_config = results['system_proxy_config']
        active_proxies = {k: v for k, v in proxy_config.items() if v}
        if active_proxies:
            print(f"\n🔧 Active system proxy configuration:")
            for proxy_type, proxy_url in active_proxies.items():
                print(f"   {proxy_type}: {proxy_url}")


def main():
    """Main function to run the proxy connection tester."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Test network connections through proxy servers')
    parser.add_argument('--timeout', type=int, default=10, help='Connection timeout in seconds')
    parser.add_argument('--proxy', action='append', help='Custom proxy to test (can be used multiple times)')
    parser.add_argument('--save', type=str, help='Save results to JSON file')
    parser.add_argument('--url', action='append', help='Custom URL to test (can be used multiple times)')
    
    args = parser.parse_args()
    
    # Create tester instance
    tester = ProxyConnectionTester(timeout=args.timeout)
    
    # Add custom URLs if provided
    if args.url:
        tester.test_urls.extend(args.url)
    
    try:
        # Run comprehensive test
        results = tester.run_comprehensive_test(custom_proxies=args.proxy)
        
        # Print summary
        tester.print_summary(results)
        
        # Save results if requested
        if args.save:
            tester.save_results(results, args.save)
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()