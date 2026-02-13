from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from analyzer import scan_url, scan_text, fetch_and_update_threat_intel, get_threat_intel_status
import logging
import re
import time
import os
import secrets
from urllib.parse import urlparse
from typing import Dict, Any, Optional
from werkzeug.middleware.proxy_fix import ProxyFix
from apscheduler.schedulers.background import BackgroundScheduler
import atexit

# Load .env file for local development (no-op if python-dotenv not installed)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

class PrivacyFilter(logging.Filter):
    def filter(self, record):
        if hasattr(record, 'msg'):
            record.msg = re.sub(r'https?://[^\s]+', '[URL_REDACTED]', str(record.msg))
            record.msg = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[IP_REDACTED]', record.msg)
            record.msg = re.sub(r'(?i)(password|credit.?card|social.?security|bank.?details)', '[SENSITIVE_REDACTED]', record.msg)
        return True

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
    TESTING = os.environ.get('TESTING', 'False').lower() == 'true'
    RATE_LIMIT = os.environ.get('RATE_LIMIT', '10 per minute')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    TRUSTED_PROXIES = os.environ.get('TRUSTED_PROXIES', '').split(',')
    ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', 'http://localhost:3000,http://127.0.0.1:3000').split(',')
    # Threat Intelligence Update Interval (in hours)
    THREAT_INTEL_INTERVAL = int(os.environ.get('THREAT_INTEL_INTERVAL', 24))

app = Flask(__name__)
app.config.from_object(Config)

# Inject current datetime into all templates for dynamic copyright year, etc.
from datetime import datetime
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

# Apply proxy fix for correct client IP behind load balancers/reverse proxies
app.wsgi_app = ProxyFix(
    app.wsgi_app, 
    x_for=1, 
    x_proto=1, 
    x_host=1, 
    x_port=1, 
    x_prefix=1
)

@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    # Suppress server technology fingerprinting
    response.headers.pop('Server', None)
    response.headers['X-Powered-By'] = 'SalamaCheck'
    return response

# Initialize extensions with CORS configuration
CORS(app, resources={
    r"/api/*": {
        "origins": Config.ALLOWED_ORIGINS,
        "methods": ["POST", "GET"],
        "allow_headers": ["Content-Type"]
    }
})

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[Config.RATE_LIMIT],
    storage_uri="memory://",
    strategy="fixed-window",
)

# Logging configuration
logging.basicConfig(
    level=logging.INFO if not Config.DEBUG else logging.DEBUG,
    format='%(asctime)s %(levelname)s [%(name)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
for handler in logging.getLogger().handlers:
    handler.addFilter(PrivacyFilter())

if not Config.DEBUG:
    logging.getLogger('werkzeug').setLevel(logging.WARNING)

# =============================================================================
# THREAT INTELLIGENCE SCHEDULER
# =============================================================================
scheduler = BackgroundScheduler()
scheduler.add_job(
    func=fetch_and_update_threat_intel,
    trigger='interval',
    hours=Config.THREAT_INTEL_INTERVAL,
    id='threat_intel_update',
    name='Automated Threat Intelligence Update',
    replace_existing=True # FIX: Changed from 'replace_original' to 'replace_existing'
)

if not app.debug or os.environ.get('WERKZEUG_RUN_MAIN') == 'true':
    # Run initial update immediately on startup
    fetch_and_update_threat_intel()
    # Start scheduler only in the main thread (outside of Werkzeug reloader)
    scheduler.start()
    atexit.register(lambda: scheduler.shutdown())

@app.route('/api/threat-intel/status')
def threat_intel_status_endpoint():
    """Endpoint to check the status of the threat intelligence update"""
    return jsonify(ResponseBuilder.success(get_threat_intel_status(), "Threat intelligence status retrieved"))

# (InputValidator and ResponseBuilder classes remain unchanged, omitting for brevity)
class InputValidator:
    @staticmethod
    def validate_url(url: str) -> Dict[str, Any]:
        if not url or not url.strip():
            return {'valid': False, 'error': 'URL cannot be empty'}
        
        url = url.strip()
        
        if len(url) > 500:
            return {'valid': False, 'error': 'URL too long (maximum 500 characters)'}
        
        try:
            parsed = urlparse(url)
            if not parsed.scheme:
                url = 'https://' + url
                parsed = urlparse(url)
            
            if not parsed.netloc:
                return {'valid': False, 'error': 'Invalid URL format - missing domain'}
            
            if InputValidator._is_private_url(parsed):
                return {'valid': False, 'error': 'Private/internal URLs are not allowed for security reasons'}
            
            if InputValidator._has_suspicious_patterns(url):
                return {'valid': False, 'error': 'URL contains suspicious patterns'}
                
        except Exception as e:
            return {'valid': False, 'error': f'Invalid URL format: {str(e)}'}
        
        return {'valid': True, 'sanitized_url': url}
    
    @staticmethod
    def validate_text(text: str) -> Dict[str, Any]:
        if not text or not text.strip():
            return {'valid': False, 'error': 'Text cannot be empty'}
        
        text = text.strip()
        
        if len(text) > 5000:
            return {'valid': False, 'error': 'Text too long (maximum 5000 characters)'}
        
        if len(text) < 3:
            return {'valid': False, 'error': 'Text too short to analyze (minimum 3 characters)'}
        
        # Sanitize: strip control characters but preserve all Unicode letters/scripts
        sanitized = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
        sanitized = sanitized.strip()
        
        if len(sanitized) < 3:
            return {'valid': False, 'error': 'Text contains too many invalid characters'}
        
        return {'valid': True, 'sanitized_text': sanitized}
    
    @staticmethod
    def _is_private_url(parsed_url) -> bool:
        hostname = parsed_url.hostname
        
        if not hostname:
            return True
            
        if hostname in ['localhost', '127.0.0.1', '::1', '0.0.0.0']:
            return True
        
        private_patterns = [
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',
            r'^192\.168\.',
            r'^169\.254\.',
            r'^127\.',
            r'^::1$',
            r'^fc00:',
            r'^fd[0-9a-f]{2}:',
            r'^fe80:'
        ]
        
        for pattern in private_patterns:
            if re.match(pattern, hostname):
                return True
                
        return False
    
    @staticmethod
    def _has_suspicious_patterns(url: str) -> bool:
        suspicious_patterns = [
            r'javascript:',
            r'vbscript:',
            r'data:',
            r'file:',
            r'ftp:',
            r'\\x',
            r'%00',
            r'\.\./',
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        return False

class ResponseBuilder:
    @staticmethod
    def success(data: Dict[str, Any], message: str = "Success") -> Dict[str, Any]:
        return {
            'status': 'success',
            'message': message,
            'data': data,
            'timestamp': time.time(),
            'version': '2.0.0'
        }
    
    @staticmethod
    def error(message: str, code: str = 'UNKNOWN_ERROR', status_code: int = 400) -> tuple:
        return {
            'status': 'error',
            'message': message,
            'code': code,
            'timestamp': time.time(),
            'version': '2.0.0'
        }, status_code

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/safety-resources')
def safety_resources():
    return render_template('safety_resources.html')

@app.route('/robots.txt')
def robots_txt():
    """Serve robots.txt for search engine crawlers"""
    content = """User-agent: *\nAllow: /\nDisallow: /api/\n\nSitemap: https://salamacheck.onrender.com/sitemap.xml"""
    return app.response_class(content, mimetype='text/plain')

@app.route('/.well-known/security.txt')
@app.route('/security.txt')
def security_txt():
    """Serve security.txt for responsible vulnerability disclosure"""
    content = (
        "Contact: https://github.com/fredxotic/SalamaCheck/issues\n"
        "Preferred-Languages: en\n"
        "Canonical: https://salamacheck.onrender.com/.well-known/security.txt\n"
        "Policy: https://github.com/fredxotic/SalamaCheck/security/policy\n"
    )
    return app.response_class(content, mimetype='text/plain')

@app.route('/api/scan/url', methods=['POST'])
@limiter.limit("10 per minute")
def scan_url_endpoint():
    start_time = time.time()
    
    try:
        data = request.get_json()
        if not data or 'link' not in data:
            return ResponseBuilder.error('No URL provided', 'MISSING_URL', 400)
        
        validation = InputValidator.validate_url(data['link'])
        if not validation['valid']:
            return ResponseBuilder.error(validation['error'], 'INVALID_URL', 400)
        
        app.logger.info("URL scan requested - processing")
        
        result = scan_url(validation['sanitized_url'])
        
        result['processing_time'] = round(time.time() - start_time, 3)
        
        app.logger.info(f"URL scan completed in {result['processing_time']}s - Status: {result.get('status', 'unknown')}")
        
        return jsonify(ResponseBuilder.success(result, "URL analysis completed"))
        
    except Exception as e:
        processing_time = round(time.time() - start_time, 3)
        app.logger.error(f"URL scan error after {processing_time}s: {str(e)}")
        return ResponseBuilder.error(
            'Server error during URL analysis', 
            'SERVER_ERROR', 
            500
        )

@app.route('/api/scan/text', methods=['POST'])
@limiter.limit("15 per minute")
def scan_text_endpoint():
    start_time = time.time()
    
    try:
        data = request.get_json()
        if not data or 'message' not in data:
            return ResponseBuilder.error('No text provided', 'MISSING_TEXT', 400)
        
        validation = InputValidator.validate_text(data['message'])
        if not validation['valid']:
            return ResponseBuilder.error(validation['error'], 'INVALID_TEXT', 400)
        
        app.logger.info("Text analysis requested - processing")
        
        result = scan_text(validation['sanitized_text'])
        
        result['processing_time'] = round(time.time() - start_time, 3)
        
        app.logger.info(f"Text analysis completed in {result['processing_time']}s - Risk: {result.get('risk', 'unknown')}")
        
        return jsonify(ResponseBuilder.success(result, "Text analysis completed"))
        
    except Exception as e:
        processing_time = round(time.time() - start_time, 3)
        app.logger.error(f"Text analysis error after {processing_time}s: {str(e)}")
        return ResponseBuilder.error(
            'Server error during text analysis', 
            'SERVER_ERROR', 
            500
        )

@app.route('/api/health')
def health_check():
    health_status = {
        'status': 'healthy',
        'service': 'SalamaCheck',
        'timestamp': time.time(),
        'version': '2.0.0',
        'environment': 'development' if Config.DEBUG else 'production',
        'features': {
            'url_scanning': True,
            'text_analysis': True,
            'threat_detection': True,
            'rate_limiting': True,
            'threat_intel_update': get_threat_intel_status()
        }
    }
    return jsonify(health_status)

@app.route('/api/info')
def api_info():
    return jsonify({
        'name': 'SalamaCheck API',
        'version': '2.0.0',
        'description': 'Online safety scanner for detecting dangerous links and harmful messages',
        'endpoints': {
            '/api/scan/url': 'POST - Scan URL for security threats',
            '/api/scan/text': 'POST - Analyze text for harmful content',
            '/api/health': 'GET - Service health check',
            '/api/info': 'GET - API information',
            '/api/threat-intel/status': 'GET - Threat intelligence update status'
        }
    })

@app.errorhandler(404)
def not_found(error):
    return ResponseBuilder.error('Endpoint not found', 'NOT_FOUND', 404)

@app.errorhandler(405)
def method_not_allowed(error):
    return ResponseBuilder.error('Method not allowed', 'METHOD_NOT_ALLOWED', 405)

@app.errorhandler(429)
def ratelimit_handler(e):
    return ResponseBuilder.error(
        'Too many requests. Please wait a moment before trying again.', 
        'RATE_LIMIT_EXCEEDED', 
        429
    )

@app.errorhandler(500)
def internal_error(error):
    return ResponseBuilder.error(
        'Internal server error. Please try again later.', 
        'INTERNAL_ERROR', 
        500
    )

@app.errorhandler(413)
def too_large(error):
    return ResponseBuilder.error(
        'Request payload too large', 
        'PAYLOAD_TOO_LARGE', 
        413
    )

if __name__ == '__main__':
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    
    app.logger.info(f"Starting SalamaCheck on {host}:{port} (Debug: {Config.DEBUG}, Threat Intel Interval: {Config.THREAT_INTEL_INTERVAL}h)")
    
    app.run(
        host=host, 
        port=port, 
        debug=Config.DEBUG,
        threaded=True
    )