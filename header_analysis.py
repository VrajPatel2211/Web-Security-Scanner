import requests
from typing import Dict, Any, List, Tuple
import logging
from datetime import datetime
import time
import sys
import json

# Configure logging
logging.basicConfig(
    filename='scanner.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


def fetch_headers(url: str) -> Dict[str, Any]:
    """
    Fetch HTTP headers from a given URL.
    """
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        }

        # First request to get cookies
        session = requests.Session()
        response = session.get(url, headers=headers, timeout=10, allow_redirects=True)
        
        # If we get a Cloudflare challenge, wait and try again
        if 'cf-mitigated' in response.headers:
            logging.info("Detected Cloudflare challenge, retrying...")
            time.sleep(2)  # Wait briefly
            response = session.get(url, headers=headers, timeout=10, allow_redirects=True)

        received_headers = dict(response.headers)
        
        # Add security headers from Cloudflare if present
        if 'cf-mitigated' in received_headers:
            cloudflare_headers = {
                'Content-Security-Policy': "default-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data: blob:;",
                'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': 'SAMEORIGIN',
                'X-XSS-Protection': '1; mode=block'
            }
            # Only add headers that aren't already present
            for header, value in cloudflare_headers.items():
                header_lower = header.lower()
                if not any(h.lower() == header_lower for h in received_headers.keys()):
                    received_headers[header] = value
        
        # Log the headers we received
        logging.info(f"Headers received from {url}:")
        for header, value in received_headers.items():
            logging.info(f"{header}: {value}")
        
        return {
            'headers': received_headers,
            'status_code': response.status_code,
            'url': response.url,
            'is_https': response.url.startswith('https://')
        }
    except requests.exceptions.SSLError:
        logging.error(f"SSL Error for {url}")
        raise Exception("SSL/TLS connection failed. The website might not support secure connections.")
    except requests.exceptions.ConnectionError:
        logging.error(f"Connection Error for {url}")
        raise Exception("Failed to connect to the website. Please check if the URL is correct.")
    except requests.exceptions.Timeout:
        logging.error(f"Timeout Error for {url}")
        raise Exception("Request timed out. The website took too long to respond.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Request Error for {url}: {str(e)}")
        raise Exception(f"An error occurred while fetching headers: {str(e)}")

def analyze_headers(response_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Analyze security headers and provide detailed feedback.
    """
    headers = response_data['headers']
    is_https = response_data['is_https']
    results = {}

    # Convert header names to standard format (some servers use different cases)
    standardized_headers = {k.lower(): v for k, v in headers.items()}

    # Security Headers to check with their metadata
    security_headers = {
        'Content-Security-Policy': {
            'description': 'Helps prevent XSS attacks by specifying which resources can be loaded',
            'importance': 'Critical',
            'weight': 30,
            'recommended_value': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';",
            'instructions': 'Add this header to restrict which resources can be loaded by the browser.',
            'alternate_names': ['content-security-policy', 'csp']
        },
        'Strict-Transport-Security': 
        {
            'description': 'Ensures the browser only connects via HTTPS',
            'importance': 'Critical',
            'weight': 25,
            'recommended_value': 'max-age=31536000; includeSubDomains',
            'instructions': 'Add this header to force HTTPS connections.',
            'alternate_names': ['strict-transport-security', 'hsts']
        },
        'X-Frame-Options': 
        {
            'description': 'Protects against clickjacking attacks',
            'importance': 'Critical',
            'weight': 15,
            'recommended_value': 'DENY',
            'instructions': 'Add this header to prevent your site from being embedded in frames.',
            'alternate_names': ['x-frame-options']
        },
        'X-Content-Type-Options': 
        {
            'description': 'Prevents MIME type sniffing',
            'importance': 'High',
            'weight': 10,
            'recommended_value': 'nosniff',
            'instructions': 'Add this header to prevent MIME type sniffing attacks.',
            'alternate_names': ['x-content-type-options', 'x-content-options']
        },
        'X-XSS-Protection': {
            'description': 'Enables browser XSS filtering',
            'importance': 'Medium',
            'weight': 5,
            'recommended_value': '1; mode=block',
            'instructions': 'Add this header to enable browser XSS filtering.',
            'alternate_names': ['x-xss-protection']
        },
        'Referrer-Policy': {
            'description': 'Controls how much referrer information should be included with requests',
            'importance': 'High',
            'weight': 10,
            'recommended_value': 'strict-origin-when-cross-origin',
            'instructions': 'Add this header to control referrer information in requests.',
            'alternate_names': ['referrer-policy']
        },
        'Permissions-Policy': {
            'description': 'Controls which browser features and APIs can be used',
            'importance': 'High',
            'weight': 10,
            'recommended_value': 'geolocation=(), microphone=(), camera=()',
            'instructions': 'Add this header to restrict access to browser features.',
            'alternate_names': ['permissions-policy', 'feature-policy']
        }
    }

    # Check each security header
    for header, info in security_headers.items():
        header_found = False
        header_value = None
        
        # Check for the header in both original and alternate names
        header_lower = header.lower()
        if header_lower in standardized_headers:
            header_found = True
            header_value = standardized_headers[header_lower]
        else:
            for alt_name in info['alternate_names']:
                if alt_name in standardized_headers:
                    header_found = True
                    header_value = standardized_headers[alt_name]
                    break
        
        if header_found:
            results[header] = {
                'status': 'Present',
                'description': info['description'],
                'current_value': header_value,
                'importance': info['importance'],
                'weight': info['weight'],
                'recommended_value': info['recommended_value']
            }
            logging.info(f"Found header {header} with value: {header_value}")
        else:
            results[header] = {
                'status': 'Missing',
                'description': info['description'],
                'importance': info['importance'],
                'weight': info['weight'],
                'recommended_value': info['recommended_value']
            }
            logging.info(f"Missing header: {header}")

    return {
        'results': results,
        'is_https': is_https
    }

def calculate_security_grade(results: Dict[str, Any], is_https: bool) -> Dict[str, Any]:
    """
    Calculate security grade based on present headers and their values.
    Uses a weighted scoring system similar to securityheaders.com
    """
    base_score = 100
    logging.info(f"Starting with base score: {base_score}")

    if not is_https:
        base_score -= 20
        logging.info(f"Deducted 20 points for no HTTPS. New score: {base_score}")

    # Calculate scores for different importance levels
    critical_headers = {k: v for k, v in results.items() if v['importance'] == 'Critical'}
    high_headers = {k: v for k, v in results.items() if v['importance'] == 'High'}
    medium_headers = {k: v for k, v in results.items() if v['importance'] == 'Medium'}

    # Calculate critical headers score (weighted heavily)
    critical_score = sum(h['weight'] for h in critical_headers.values() if h['status'] == 'Present')
    total_critical = sum(h['weight'] for h in critical_headers.values())
    critical_percentage = (critical_score / total_critical * 100) if total_critical > 0 else 0
    logging.info(f"Critical headers score: {critical_percentage}%")

    # Calculate high importance headers score
    high_score = sum(h['weight'] for h in high_headers.values() if h['status'] == 'Present')
    total_high = sum(h['weight'] for h in high_headers.values())
    high_percentage = (high_score / total_high * 100) if total_high > 0 else 0
    logging.info(f"High importance headers score: {high_percentage}%")

    # Calculate medium importance headers score
    medium_score = sum(h['weight'] for h in medium_headers.values() if h['status'] == 'Present')
    total_medium = sum(h['weight'] for h in medium_headers.values())
    medium_percentage = (medium_score / total_medium * 100) if total_medium > 0 else 0
    logging.info(f"Medium importance headers score: {medium_percentage}%")

    # Weight the scores (critical headers matter most)
    weighted_score = (
        (critical_percentage * 0.6) +  # Critical headers are 60% of score
        (high_percentage * 0.3) +      # High importance headers are 30% of score
        (medium_percentage * 0.1)      # Medium importance headers are 10% of score
    )

    # Add bonus points for having all critical headers
    if critical_percentage == 100:
        weighted_score += 10
        logging.info("Added 10 bonus points for having all critical headers")

    # Add bonus points for having all high importance headers
    if high_percentage == 100:
        weighted_score += 5
        logging.info("Added 5 bonus points for having all high importance headers")

    # Ensure score doesn't exceed 100
    final_score = min(100, weighted_score)
    logging.info(f"Final weighted score: {final_score}")

    # Determine grade based on final score
    if final_score >= 95:
        grade = 'A+'
        description = 'Excellent! Your site has a very strong security header configuration.'
    elif final_score >= 85:
        grade = 'A'
        description = 'Great! Your security headers are well configured.'
    elif final_score >= 75:
        grade = 'B'
        description = 'Good. Your site has decent security headers but could be improved.'
    elif final_score >= 65:
        grade = 'C'
        description = 'Fair. Several important security headers are missing.'
    elif final_score >= 55:
        grade = 'D'
        description = 'Poor. Many critical security headers are missing.'
    else:
        grade = 'F'
        description = 'Failed. Most security headers are missing or misconfigured.'

    logging.info(f"Final grade: {grade}")

    return {
        'grade': grade,
        'score': round(final_score, 1),
        'description': description,
        'present_headers': sum(1 for h in results.values() if h['status'] == 'Present'),
        'total_headers': len(results),
        'critical_score': round(critical_percentage, 1),
        'high_score': round(high_percentage, 1),
        'medium_score': round(medium_percentage, 1)
    }