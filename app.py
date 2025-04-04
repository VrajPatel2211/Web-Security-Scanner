from flask import Flask, render_template, request, jsonify, send_file
from header_analysis import fetch_headers, analyze_headers, calculate_security_grade
import threading
import json
from datetime import datetime
import os
import logging

# Create a Flask app
app = Flask(__name__)

# Configure logging
logging.basicConfig(
    filename='scanner.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Security header descriptions and fix instructions
SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "description": "Helps prevent XSS attacks by specifying which resources can be loaded",
        "importance": "Critical",
        "recommended_value": "default-src 'self'; script-src 'self' https://trusted.cdn.com;",
        "instructions": "Add a Content-Security-Policy header to your server configuration."
    },
    "Strict-Transport-Security": {
        "description": "Enforces HTTPS by telling browsers to always use secure connections",
        "importance": "Critical",
        "recommended_value": "max-age=31536000; includeSubDomains",
        "instructions": "Add the Strict-Transport-Security header to enforce HTTPS."
    },
    "X-Frame-Options": {
        "description": "Protects against clickjacking attacks",
        "importance": "Critical",
        "recommended_value": "DENY",
        "instructions": "Add the X-Frame-Options header to prevent embedding in frames."
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME type sniffing",
        "importance": "Medium",
        "recommended_value": "nosniff",
        "instructions": "Add the X-Content-Type-Options header with value 'nosniff'."
    },
    "X-XSS-Protection": {
        "description": "Enables browser XSS filtering",
        "importance": "Medium",
        "recommended_value": "1; mode=block",
        "instructions": "Add the X-XSS-Protection header to enable XSS protection."
    },
    "Referrer-Policy": {
        "description": "Controls referrer information in requests",
        "importance": "Medium",
        "recommended_value": "no-referrer-when-cross-origin",
        "instructions": "Add the Referrer-Policy header to control referrer information."
    },
    "Permissions-Policy": {
        "description": "Controls which browser features and APIs can be used",
        "importance": "Medium",
        "recommended_value": "geolocation=(), microphone=(), camera=()",
        "instructions": "Add the Permissions-Policy header to restrict feature access."
    }
}

@app.route("/", methods=["GET"])
def index():
    """Render the main page."""
    return render_template("index.html")

@app.route("/analyze", methods=["POST"])
def analyze():
    """Analyze the security headers of a given URL."""
    try:
        data = request.get_json()
        url = data.get("url")
        
        if not url:
            return jsonify({"error": "Please enter a valid URL."}), 400
        
        if not url.startswith("http"):
            url = "http://" + url
        
        # Log the analysis request
        logging.info(f"Analyzing headers for URL: {url}")
        
        try:
            # Fetch headers with metadata
            response_data = fetch_headers(url)
            
            # Analyze headers
            analysis_results = analyze_headers(response_data)
            
            # Calculate security grade
            security_grade = calculate_security_grade(analysis_results['results'], analysis_results['is_https'])
            
            # Prepare missing headers with fix instructions
            missing_headers = {}
            for header, data in analysis_results['results'].items():
                if data['status'] == 'Missing':
                    missing_headers[header] = {
                        'importance': SECURITY_HEADERS[header]['importance'],
                        'recommended_value': SECURITY_HEADERS[header]['recommended_value'],
                        'instructions': SECURITY_HEADERS[header]['instructions']
                    }
            
            response_data = {
                "results": analysis_results['results'],
                "security_grade": security_grade,
                "is_https": analysis_results['is_https'],
                "missing_headers": missing_headers,
                "scan_time": datetime.now().isoformat(),
                "metadata": response_data
            }
            
            # Log successful analysis
            logging.info(f"Analysis completed for {url} - Grade: {security_grade['grade']}")
            
            return jsonify(response_data)
        
        except Exception as e:
            # Log the error
            logging.error(f"Error analyzing {url}: {str(e)}")
            return jsonify({"error": str(e)}), 500
            
    except Exception as e:
        logging.error(f"Invalid request: {str(e)}")
        return jsonify({"error": "Invalid request format"}), 400

@app.route("/export", methods=["POST"])
def export():
    """Export the analysis results to a file."""
    try:
        data = request.get_json()
        results = data.get("results")
        
        if not results:
            return jsonify({"error": "No results to export"}), 400
        
        # Create exports directory if it doesn't exist
        if not os.path.exists('exports'):
            os.makedirs('exports')
        
        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"exports/security_scan_{timestamp}.txt"
        
        # Format results for export
        export_data = {
            "scan_time": datetime.now().isoformat(),
            "results": results
        }
        
        # Write results to file
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(export_data, f, indent=2)
        
        # Log export
        logging.info(f"Results exported to {filename}")
        
        return jsonify({
            "message": "Results exported successfully",
            "filename": filename
        })
        
    except Exception as e:
        logging.error(f"Export error: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/download/<path:filename>")
def download_file(filename):
    """Download an exported file."""
    try:
        return send_file(filename, as_attachment=True)
    except Exception as e:
        logging.error(f"Download error: {str(e)}")
        return jsonify({"error": "File not found"}), 404

@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors."""
    return jsonify({"error": "Resource not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    logging.error(f"Internal server error: {str(error)}")
    return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    print("\nSecurity Headers Scanner")
    print("=======================")
    print("Web interface running at: http://127.0.0.1:5000")
    print("GUI version available through main.py")
    print("Logs available in: scanner.log")
    print("=======================\n")
    app.run(debug=True)