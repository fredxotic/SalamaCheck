import requests
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
import re
from urllib.parse import urlparse
import time
from typing import Dict, List, Tuple, Any, Optional
try:
    from bs4 import BeautifulSoup
    _HAS_BS4 = True
except Exception:
    BeautifulSoup = None
    _HAS_BS4 = False

import threading
import logging
import os

# Set up logging for module-level information
logger = logging.getLogger(__name__)

# Initialize the Sentiment Intensity Analyzer once at module level
analyzer = SentimentIntensityAnalyzer()

# =============================================================================
# THREAT AND SAFETY DATABASES - MUTABLE FOR UPDATES
# =============================================================================

# Base lists that can be updated dynamically
GLOBAL_DANGEROUS_DOMAINS = [
    'grabify.link', 'iplogger.org', 'iplogger.com', 'blasze.com',
    'cutt.ly', 'shorte.st', 'adf.ly', 'bc.vc', 'ouo.io', 'click.ru',
    'link.tl', 'soo.gd', 'thy.pw', 'ceesty.com', 'urlz.fr', 'zzb.bz',
    '2no.co', 'ipgrab.org', 'yip.su', 'iplo.ru', 'traceurl.com'
]

GLOBAL_SAFE_DOMAINS = [
    'google.com', 'github.com', 'microsoft.com', 'apple.com', 'amazon.com',
    'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com',
    'youtube.com', 'netflix.com', 'spotify.com', 'discord.com',
    'stackoverflow.com', 'reddit.com', 'wikipedia.org', 'medium.com',
    'deepseek.com', 'chat.deepseek.com', 'openai.com', 'chat.openai.com',
    'notion.so', 'figma.com', 'slack.com', 'zoom.us', 'teams.microsoft.com',
    'who.int', 'cdc.gov', 'cancer.org', 'healthline.com', 'webmd.com',
    'mayoclinic.org', 'nih.gov', 'medicalnewstoday.com', 'gov.uk',
    'bbc.com', 'cnn.com', 'nytimes.com', 'washingtonpost.com'
]

GLOBAL_SUSPICIOUS_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'shorturl.at', 't.co', 'goo.gl', 'ow.ly',
    'buff.ly', 'tiny.cc', 'is.gd', 'cli.gs', 'yfrog.com', 'migre.me',
    'ff.im', 'url4.eu', 'twit.ac', 'su.pr', 'twurl.nl', 'snipurl.com',
    'short.to', 'budurl.com', 'ping.fm', 'post.ly', 'just.as', 'bkite.com',
    'twitterfeed.com', 'shrten.com', 'short.ie', 'shorl.com', 'x.co'
]

# Threat intelligence status tracking
THREAT_INTEL_STATUS = {
    'last_updated': None,
    'sources_used': [],
    'domains_loaded': 0,
    'success': False,
    'error': None
}

# Thread lock for thread-safe updates
_threat_intel_lock = threading.Lock()

def fetch_and_update_threat_intel() -> bool:
    """
    Fetch threat intelligence data from external sources and update domain lists.
    Returns True if successful, False otherwise.
    """
    global GLOBAL_DANGEROUS_DOMAINS, THREAT_INTEL_STATUS
    
    try:
        with _threat_intel_lock:
            THREAT_INTEL_STATUS['last_attempt'] = time.time()
            THREAT_INTEL_STATUS['sources_used'] = []
            THREAT_INTEL_STATUS['error'] = None
            
            new_dangerous_domains = set(GLOBAL_DANGEROUS_DOMAINS)
            domains_loaded = 0
            
            # Source 1: Phishing Army (community-maintained phishing list)
            try:
                response = requests.get(
                    'https://phishing.army/download/phishing_army_blocklist.txt',
                    timeout=10
                )
                if response.status_code == 200:
                    domains = [
                        line.strip() for line in response.text.split('\n') 
                        if line.strip() and not line.startswith('#')
                    ]
                    new_dangerous_domains.update(domains)
                    domains_loaded += len(domains)
                    THREAT_INTEL_STATUS['sources_used'].append('phishing_army')
            except Exception as e:
                logger.warning(f"Failed to fetch from Phishing Army: {e}")
            
            # Source 2: URLHaus abuse.ch malware list
            try:
                response = requests.get(
                    'https://urlhaus.abuse.ch/downloads/text_online/',
                    timeout=10
                )
                if response.status_code == 200:
                    domains = []
                    for line in response.text.split('\n'):
                        if line.strip() and not line.startswith('#'):
                            # Extract domain from URL
                            url_parts = line.split('/')
                            if len(url_parts) > 2:
                                domain = url_parts[2].lower()
                                if domain and '.' in domain:
                                    domains.append(domain)
                    new_dangerous_domains.update(domains)
                    domains_loaded += len(domains)
                    THREAT_INTEL_STATUS['sources_used'].append('urlhaus')
            except Exception as e:
                logger.warning(f"Failed to fetch from URLHaus: {e}")
            
            # Update global lists if we got new data
            if domains_loaded > 0:
                GLOBAL_DANGEROUS_DOMAINS = list(new_dangerous_domains)
                THREAT_INTEL_STATUS.update({
                    'last_updated': time.time(),
                    'domains_loaded': domains_loaded,
                    'success': True
                })
                logger.info(f"Threat intelligence updated: {domains_loaded} total dangerous domains")
                return True
            else:
                THREAT_INTEL_STATUS.update({
                    'error': 'No new domains loaded from any source',
                    'success': False
                })
                return False
                
    except Exception as e:
        THREAT_INTEL_STATUS.update({
            'error': str(e),
            'success': False
        })
        logger.error(f"Threat intelligence update failed: {e}")
        return False

def get_threat_intel_status() -> Dict[str, Any]:
    """Get current threat intelligence status"""
    status = THREAT_INTEL_STATUS.copy()
    if status['last_updated']:
        status['last_updated_human'] = time.ctime(status['last_updated'])
        status['minutes_since_update'] = int((time.time() - status['last_updated']) / 60)
    status['current_dangerous_domains'] = len(GLOBAL_DANGEROUS_DOMAINS)
    status['current_safe_domains'] = len(GLOBAL_SAFE_DOMAINS)
    return status

# =============================================================================
# THREAT DETECTION PATTERNS
# =============================================================================

# SEVERE THREATS - Automatic high risk
SEVERE_THREATS = [
    r'rape\s+(you|her|him|them)', r'kill\s+(you|yourself|myself)', 
    r'murder\s+(you|her|him)', r'shoot\s+(you|her|him)', r'stab\s+(you|her|him)',
    r'cut\s+(your|my)\s+(throat|wrist)', r'hang\s+(yourself|myself)',
    r'beat\s+you\s+to\s+death', r'burn\s+(you|your)', r'throw\s+acid',
    r'strangle\s+(you|her|him)', r'slit\s+(your|my)\s+(throat|wrist)'
]

# CRITICAL: GROOMING AND AGE DISPARITY - Automatic high risk (Fix for reported vulnerability)
GROOMING_PHRASES = [
    r'(love|adore|care)\s+you.*(is|are)\s+\d{1,2}\s+(year|y)s?\s+old', # Affection + young age
    r'\d{1,2}\s+(year|y)s?\s+old.*(is|are)\s+\d{2,3}\s+(year|y)s?\s+old', # Explicit age disparity
    r'we\s+can\s+keep\s+it\s+a\s+secret', # Grooming indicator: secrecy
    r'don\'t\s+tell\s+(mom|dad|anyone|parents|teacher)', # Grooming indicator: secrecy
    r'no\s+one\s+needs\s+to\s+know', # Grooming indicator: secrecy
    r'let\'s\s+be\s+friends\s+in\s+secret', # Grooming indicator: secret relationship
    r'i\s+want\s+to\s+see\s+your\s+pics\s+private' # Request for private photos
]

# VIOLENT THREATS - High priority detection
VIOLENT_THREATS = [
    r'hurt\s+you', r'beat\s+you', r'attack\s+you', r'assault\s+you',
    r'break\s+your', r'smash\s+your', r'destroy\s+you', r'end\s+you',
    r'make\s+you\s+suffer', r'teach\s+you\s+a\s+lesson', r'punish\s+you',
    r'get\s+you', r'come\s+for\s+you', r'find\s+you', r'hunt\s+you\s+down'
]

# STALKING AND INTIMIDATION
STALKING_PHRASES = [
    r'i\s+know\s+where\s+you\s+live', r'i\'m\s+outside', r'waiting\s+outside',
    r'watching\s+you', r'following\s+you', r'i\s+see\s+you', r'i\'m\s+here',
    r'outside\s+your', r'at\s+your\s+(house|home|place)', r'parked\s+outside',
    r'see\s+you\s+soon', r'coming\s+over', r'be\s+there\s+soon'
]

# GENDERED HARASSMENT AND MISOGYNY
GENDERED_HARASSMENT = [
    r'know\s+your\s+place', r'shut\s+up\s+(woman|bitch)', r'women\s+shouldn\'t',
    r'female\s+shouldn\'t', r'no\s+place\s+for\s+a\s+woman', 
    r'back\s+to\s+the\s+kitchen', r'make\s+me\s+a\s+sandwich',
    r'women\s+belong\s+in', r'not\s+your\s+job\s+as\s+a\s+woman',
    r'shouldn\'t\s+be\s+(here|working|leading)', r'unqualified\s+woman',
    r'diversity\s+hire', r'only\s+got\s+the\s+job\s+because',
    r'sleep\s+with\s+the\s+boss', r'slept\s+her\s+way\s+to',
    r'value\s+between\s+your\s+legs', r'only\s+good\s+for\s+one\s+thing'
]

# SEXUAL HARASSMENT AND COERCION
SEXUAL_HARASSMENT = [
    r'send\s+nudes', r'show\s+your\s+(body|boobs|tits|ass)', 
    r'let\s+me\s+see\s+your', r'want\s+to\s+see\s+you\s+naked',
    r'get\s+naked', r'take\s+it\s+off', r'be\s+sexy\s+for\s+me',
    r'you\'d\s+be\s+prettier\s+if', r'smile\s+for\s+me', 
    r'you\s+should\s+wear\s+less', r'dress\s+like\s+a\s+slut',
    r'be\s+more\s+feminine', r'act\s+like\s+a\s+lady'
]

# GENDERED INSULTS AND SLURS
GENDERED_INSULTS = [
    r'\bbitch\b', r'\bslut\b', r'\bwhore\b', r'\bcunt\b', r'\bhysterical\b',
    r'\bemotional\b', r'\bdrama\b', r'\bhormonal\b', r'\bbossy\b', 
    r'\bdifficult\b', r'\baggressive\b', r'\bshrill\b', r'\bfeisty\b',
    r'\bdumb\s+blonde\b', r'\bgold\s+digger\b', r'\bfeminazi\b',
    r'\bboss\s+lady\b', r'\bprincess\b', r'\bdiva\b', r'\bhigh\s+maintenance\b'
]

# FINANCIAL AND PERSONAL COERCION
COERCION_PHRASES = [
    r'send\s+money', r'wire\s+transfer', r'bank\s+details', 
    r'credit\s+card', r'social\s+security', r'password',
    r'account\s+information', r'login\s+details', r'verify\s+your',
    r'urgent\s+action', r'immediately', r'right\s+now',
    r'or\s+else', r'something\s+bad\s+will\s+happen',
    r'i\s+have\s+your\s+(information|pictures)'
]

# HIGH-CONFIDENCE EXPLICIT TERMS
EXPLICIT_TERMS = [
    r'\bporn\b', r'\bpornography\b', r'\bxxx\b', r'\bhardcore\b', 
    r'\bfuck\b', r'\bdick\b', r'\bcock\b', r'\bpussy\b', 
    r'\bcum\b', r'\borgasm\b', r'\bmasturbat\b', r'\bgangbang\b', 
    r'\banal\b', r'\bmilf\b', r'\bincest\b', r'\btaboo\b'
]

# CONTEXT-SENSITIVE TERMS WITH SAFE INDICATORS (Unchanged)
CONTEXT_SENSITIVE_TERMS = {
    'adult': ['education', 'learning', 'content', 'awareness', 'health', 'cancer', 'literacy'],
    'sex': ['education', 'health', 'therapy', 'advice', 'relationship', 'marriage', 'education'],
    'nude': ['art', 'painting', 'photography', 'beach', 'model', 'drawing', 'study'],
    'naked': ['truth', 'facts', 'eye', 'beach', 'ambition', 'aggression'],
    'erotic': ['literature', 'art', 'fiction', 'poetry', 'novel'],
    'sexy': ['costume', 'halloween', 'outfit', 'dress', 'fashion', 'style'],
    'massage': ['therapy', 'therapist', 'health', 'sports', 'relaxation', 'chair'],
    'breast': ['cancer', 'feeding', 'health', 'awareness', 'examination'],
    'ass': ['donkey', 'animal', 'kick', 'bass', 'whole', 'smart']
}

# =============================================================================
# SCORING CONFIGURATION
# =============================================================================

THREAT_WEIGHTS = {
    'severe_threat': 15,      
    'grooming': 12,           # CRITICAL: New category for age disparity and secrecy
    'violent_threat': 10,     
    'stalking': 9,           
    'gendered_harassment': 8, 
    'sexual_harassment': 8,   
    'coercion': 7,           
    'gendered_insult': 6,     
    'explicit_content': 5,    
    'suspicious_phrase': 4,   
    'negative_sentiment': 2   
}

RISK_THRESHOLDS = {
    'high': 8,
    'medium': 4,
    'low': 0
}

# =============================================================================
# CORE ANALYSIS FUNCTIONS
# =============================================================================

def get_domain_from_url(url: str) -> str:
    """Extract the main domain from a URL"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain
    except:
        return ""

# (is_safe_domain, is_dangerous_domain, is_suspicious_shortener remain unchanged as they use the global lists)
def is_safe_domain(domain: str) -> bool:
    """Check if a domain is in the safe whitelist"""
    for safe_domain in GLOBAL_SAFE_DOMAINS:
        if domain == safe_domain or domain.endswith('.' + safe_domain):
            return True
    return False

def is_dangerous_domain(domain: str) -> bool:
    """Check if a domain is explicitly dangerous"""
    for dangerous_domain in GLOBAL_DANGEROUS_DOMAINS:
        if domain == dangerous_domain or domain.endswith('.' + dangerous_domain):
            return True
    return False

def is_suspicious_shortener(domain: str) -> bool:
    """Check if a domain is a suspicious URL shortener"""
    for shortener in GLOBAL_SUSPICIOUS_SHORTENERS:
        if domain == shortener or domain.endswith('.' + shortener):
            return True
    return False

def analyze_context(text: str, keyword: str) -> bool:
    """
    Analyze context around a keyword to determine if it's actually explicit
    Returns True if explicit, False if safe
    """
    # ... (function body remains unchanged)
    text_lower = text.lower()
    
    pattern = r'\b' + re.escape(keyword) + r'\b'
    occurrences = []
    
    for match in re.finditer(pattern, text_lower):
        occurrences.append(match.start())
    
    for idx in occurrences:
        start_ctx = max(0, idx - 50)
        end_ctx = min(len(text_lower), idx + len(keyword) + 50)
        context = text_lower[start_ctx:end_ctx]
        
        safe_indicators = CONTEXT_SENSITIVE_TERMS.get(keyword, [])
        for indicator in safe_indicators:
            if re.search(r'\b' + re.escape(indicator) + r'\b', context):
                return False
    
    return True

def detect_threat_patterns(text: str) -> Dict[str, List[str]]:
    """
    Threat pattern detection using regex patterns
    Returns categorized threats with their matches
    """
    text_lower = text.lower()
    threats_detected = {
        'severe_threat': [],
        'grooming': [], # New threat category
        'violent_threat': [],
        'stalking': [],
        'gendered_harassment': [],
        'sexual_harassment': [],
        'coercion': [],
        'gendered_insult': [],
        'explicit_content': []
    }
    
    # Severe threats (automatic high risk)
    for pattern in SEVERE_THREATS:
        matches = re.findall(pattern, text_lower)
        if matches:
            threats_detected['severe_threat'].extend(matches)
            
    # Grooming (CRITICAL)
    for pattern in GROOMING_PHRASES:
        matches = re.findall(pattern, text_lower)
        if matches:
            threats_detected['grooming'].extend(matches)
    
    # Violent threats
    for pattern in VIOLENT_THREATS:
        matches = re.findall(pattern, text_lower)
        if matches:
            threats_detected['violent_threat'].extend(matches)
    
    # Stalking and intimidation
    for pattern in STALKING_PHRASES:
        matches = re.findall(pattern, text_lower)
        if matches:
            threats_detected['stalking'].extend(matches)
    
    # Gendered harassment
    for pattern in GENDERED_HARASSMENT:
        matches = re.findall(pattern, text_lower)
        if matches:
            threats_detected['gendered_harassment'].extend(matches)
    
    # Sexual harassment
    for pattern in SEXUAL_HARASSMENT:
        matches = re.findall(pattern, text_lower)
        if matches:
            threats_detected['sexual_harassment'].extend(matches)
    
    # Gendered insults
    for pattern in GENDERED_INSULTS:
        matches = re.findall(pattern, text_lower)
        if matches:
            threats_detected['gendered_insult'].extend(matches)
    
    # Coercion phrases
    for pattern in COERCION_PHRASES:
        matches = re.findall(pattern, text_lower)
        if matches:
            threats_detected['coercion'].extend(matches)
    
    # Explicit content with context analysis
    for pattern in EXPLICIT_TERMS:
        matches = re.findall(pattern, text_lower)
        if matches:
            keyword = pattern.strip(r'\b')
            if analyze_context(text_lower, keyword):
                threats_detected['explicit_content'].extend(matches)
    
    return threats_detected

def calculate_comprehensive_risk(threats_detected: Dict[str, List[str]], 
                               sentiment_score: float, 
                               explicit_score: int) -> Tuple[str, int, List[str]]:
    """
    Calculate comprehensive risk score with weighted threats
    Returns: (risk_level, total_score, risk_factors)
    """
    total_score = 0
    risk_factors = []
    
    # Immediate high risk checks
    if threats_detected['severe_threat']:
        return ('high', 100, ['severe_violent_threats'])
        
    if threats_detected['grooming']: # New immediate high risk check
        return ('high', 80, ['grooming_behavior'])
    
    for category, matches in threats_detected.items():
        if matches:
            weight = THREAT_WEIGHTS.get(category, 0)
            category_score = min(len(matches) * weight, weight * 3)
            total_score += category_score
            
            if category == 'grooming':
                risk_factors.append('grooming_behavior')
            elif category == 'violent_threat':
                risk_factors.append('violent_threats')
            elif category == 'stalking':
                risk_factors.append('stalking_behavior')
            elif category == 'gendered_harassment':
                risk_factors.append('gendered_harassment')
            elif category == 'sexual_harassment':
                risk_factors.append('sexual_harassment')
            elif category == 'coercion':
                risk_factors.append('coercive_language')
            elif category == 'gendered_insult':
                risk_factors.append('gendered_insults')
            elif category == 'explicit_content':
                risk_factors.append('explicit_content')
    
    if sentiment_score < -0.7:
        total_score += THREAT_WEIGHTS['negative_sentiment']
        risk_factors.append('highly_negative_sentiment')
    elif sentiment_score < -0.4:
        total_score += THREAT_WEIGHTS['negative_sentiment'] // 2
        risk_factors.append('negative_sentiment')
    
    if explicit_score > 0:
        total_score += min(explicit_score, THREAT_WEIGHTS['explicit_content'])
    
    if total_score >= RISK_THRESHOLDS['high']:
        risk_level = 'high'
    elif total_score >= RISK_THRESHOLDS['medium']:
        risk_level = 'medium'
    else:
        risk_level = 'low'
    
    return (risk_level, total_score, risk_factors)

def scan_text(message: str) -> Dict[str, Any]:
    """
    Text analysis for threats, harassment, and safety risks
    """
    start_time = time.time()
    
    try:
        message_lower = message.lower()
        
        sentiment_scores = analyzer.polarity_scores(message_lower)
        compound_score = sentiment_scores['compound']
        
        threats_detected = detect_threat_patterns(message_lower)
        
        explicit_score = 0
        explicit_terms_found = []
        
        # Explicit terms check
        for pattern in EXPLICIT_TERMS:
            matches = re.findall(pattern, message_lower)
            if matches:
                keyword = pattern.strip(r'\b')
                if analyze_context(message_lower, keyword):
                    explicit_score += 3 * len(matches)
                    explicit_terms_found.extend(matches)
        
        # Context-sensitive terms check
        for term, safe_indicators in CONTEXT_SENSITIVE_TERMS.items():
            if re.search(r'\b' + re.escape(term) + r'\b', message_lower):
                if analyze_context(message_lower, term):
                    explicit_score += 2
                    explicit_terms_found.append(term)
        
        risk_level, risk_score, risk_factors = calculate_comprehensive_risk(
            threats_detected, compound_score, explicit_score
        )
        
        all_detected_threats = []
        for category, matches in threats_detected.items():
            if matches:
                for match in matches[:3]:
                    all_detected_threats.append(f"{category}: {match}")
        
        result = {
            'risk': risk_level,
            'risk_score': risk_score,
            'sentiment_score': round(compound_score, 3),
            'detected_threats': all_detected_threats[:10],
            'threat_categories': {k: len(v) for k, v in threats_detected.items() if v},
            'adult_content_detected': explicit_score >= 3,
            'adult_content_score': explicit_score,
            'explicit_terms_found': explicit_terms_found[:5],
            'risk_factors': risk_factors,
            'sentiment_breakdown': {
                'negative': round(sentiment_scores['neg'], 3),
                'neutral': round(sentiment_scores['neu'], 3),
                'positive': round(sentiment_scores['pos'], 3)
            },
            'scan_time': round(time.time() - start_time, 2),
            'message_length': len(message)
        }
        
        result['flags'] = []
        if any(cat in risk_factors for cat in ['violent_threats', 'severe_violent_threats']):
            result['flags'].append('violent_language')
        if any(cat in risk_factors for cat in ['gendered_harassment', 'sexual_harassment', 'gendered_insults']):
            result['flags'].append('harassment')
        if 'stalking_behavior' in risk_factors:
            result['flags'].append('stalking')
        if 'coercive_language' in risk_factors:
            result['flags'].append('coercion')
        if 'explicit_content' in risk_factors:
            result['flags'].append('explicit_content')
        if 'grooming_behavior' in risk_factors:
            result['flags'].append('grooming') # New flag
        
        return result
        
    except Exception as e:
        logger.error(f"Text analysis runtime error: {e}")
        return {
            'risk': 'error',
            'error': f'Text analysis failed: {str(e)}',
            'scan_time': round(time.time() - start_time, 2)
        }

# =============================================================================
# URL SCANNING FUNCTIONS
# =============================================================================

def scan_url(link: str) -> Dict[str, Any]:
    """
    Analyze a URL for potential dangers by following redirects, checking domains, and analyzing content.
    """
    start_time = time.time()
    
    try:
        if not link.startswith(('http://', 'https://')):
            link = 'https://' + link
        
        initial_domain = get_domain_from_url(link)
        
        # Check initial domain
        if is_safe_domain(initial_domain):
            return {
                'status': 'safe',
                'final_url': link,
                'message': 'This link is from a trusted domain',
                'risk_reason': 'trusted_domain',
                'scan_time': round(time.time() - start_time, 2)
            }
        
        if is_dangerous_domain(initial_domain):
            return {
                'status': 'danger',
                'final_url': link,
                'message': f'Warning: This is a known suspicious domain ({initial_domain})',
                'risk_reason': 'suspicious_domain',
                'scan_time': round(time.time() - start_time, 2)
            }
        
        # Follow redirects and check each domain in the chain (with a shorter timeout)
        response = requests.get(
            link, 
            timeout=(3, 5), # (Connect timeout, Read timeout)
            allow_redirects=True,
            headers={
                'User-Agent': os.environ.get('USER_AGENT', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            },
            verify=True
        )
        
        final_url = response.url.lower()
        final_domain = get_domain_from_url(final_url)
        
        # Collect all domains in redirect chain for analysis
        redirect_domains = []
        if initial_domain:
            redirect_domains.append(initial_domain)
            
        if response.history:
            for resp in response.history:
                redirect_url = resp.url.lower()
                redirect_domain = get_domain_from_url(redirect_url)
                if redirect_domain and redirect_domain not in redirect_domains:
                    redirect_domains.append(redirect_domain)
        
        if final_domain and final_domain not in redirect_domains:
            redirect_domains.append(final_domain)
        
        # Check every domain in the redirect chain
        dangerous_redirects = []
        suspicious_redirects = []
        
        for domain in redirect_domains:
            if is_safe_domain(domain):
                continue
            elif is_dangerous_domain(domain):
                dangerous_redirects.append(domain)
            elif is_suspicious_shortener(domain):
                suspicious_redirects.append(domain)
        
        # Return appropriate result based on redirect analysis
        if dangerous_redirects:
            return {
                'status': 'danger',
                'final_url': final_url,
                'message': f'Warning: Link redirects through known suspicious domains: {", ".join(dangerous_redirects[:3])}',
                'risk_reason': 'suspicious_redirect_chain',
                'redirect_chain': redirect_domains,
                'dangerous_redirects': dangerous_redirects,
                'scan_time': round(time.time() - start_time, 2)
            }
        
        if suspicious_redirects:
            return {
                'status': 'warning',
                'final_url': final_url,
                'message': f'Caution: Link uses URL shortener services. Proceed with caution.',
                'risk_reason': 'url_shortener_chain',
                'redirect_chain': redirect_domains,
                'suspicious_redirects': suspicious_redirects,
                'scan_time': round(time.time() - start_time, 2)
            }
        
        # Check final destination
        if is_safe_domain(final_domain):
            return {
                'status': 'safe',
                'final_url': final_url,
                'message': 'This link redirects to a trusted domain',
                'risk_reason': 'trusted_redirect',
                'redirect_chain': redirect_domains,
                'scan_time': round(time.time() - start_time, 2)
            }
        
        if is_dangerous_domain(final_domain):
            return {
                'status': 'danger',
                'final_url': final_url,
                'message': f'Warning: Link redirects to known suspicious domain ({final_domain})',
                'risk_reason': 'suspicious_domain',
                'redirect_chain': redirect_domains,
                'scan_time': round(time.time() - start_time, 2)
            }
        
        if is_suspicious_shortener(final_domain):
            return {
                'status': 'warning',
                'final_url': final_url,
                'message': f'Caution: This is a URL shortener service. Proceed with caution.',
                'risk_reason': 'url_shortener',
                'redirect_chain': redirect_domains,
                'scan_time': round(time.time() - start_time, 2)
            }
        
        # Analyze page content if we reached a destination
        if response.status_code == 200 and len(response.text) > 100:
            content_analysis = analyze_page_content(response.text, final_url)
            if content_analysis['is_adult']:
                return {
                    'status': 'danger',
                    'final_url': final_url,
                    'message': f'Explicit Content Detected: {content_analysis["reason"]}',
                    'risk_reason': 'explicit_content',
                    'content_analysis': content_analysis,
                    'redirect_chain': redirect_domains,
                    'scan_time': round(time.time() - start_time, 2)
                }
        
        # If no issues found in entire chain, consider it safe
        return {
            'status': 'safe',
            'final_url': final_url,
            'message': 'This link appears to be safe',
            'risk_reason': 'clean',
            'redirect_chain': redirect_domains,
            'scan_time': round(time.time() - start_time, 2)
        }
        
    except requests.exceptions.Timeout:
        return {
            'status': 'error',
            'message': 'Request timed out. The link may be invalid or unresponsive.',
            'scan_time': round(time.time() - start_time, 2)
        }
    except requests.exceptions.ConnectionError:
        return {
            'status': 'error', 
            'message': 'Connection error. Unable to reach the provided link.',
            'scan_time': round(time.time() - start_time, 2)
        }
    except requests.exceptions.RequestException as e:
        return {
            'status': 'error',
            'message': f'Invalid link or network error: {str(e)}',
            'scan_time': round(time.time() - start_time, 2)
        }
    except Exception as e:
        logger.error(f"URL analysis unexpected error: {e}")
        return {
            'status': 'error',
            'message': f'Unexpected error during URL analysis: {str(e)}',
            'scan_time': round(time.time() - start_time, 2)
        }

def analyze_page_content(html_content: str, url: str) -> Dict[str, Any]:
    """
    Analyze HTML content for adult/explicit material with contextual analysis.
    """
    # ... (function body remains mostly unchanged, using improved text extraction)
    content_lower = html_content.lower()
    
    text_content = extract_text_from_html(content_lower)
    
    explicit_terms_found = []
    explicit_score = 0
    
    for term in EXPLICIT_TERMS:
        if re.search(term, text_content):
            explicit_score += 3
            explicit_terms_found.append(term.strip(r'\b'))
    
    context_sensitive_found = []
    for term, safe_indicators in CONTEXT_SENSITIVE_TERMS.items():
        if re.search(r'\b' + re.escape(term) + r'\b', text_content):
            if analyze_context(text_content, term):
                explicit_score += 2
                context_sensitive_found.append(term)
            else:
                explicit_score += 0.1
    
    explicit_phrases = [
        r'porn', r'xxx', r'hardcore.*video', r'sex.*video', r'nsfw',
        r'explicit.*content', r'mature.*content', r'you must be 18',
        r'age.*verification', r'adult.*warning', r'enter.*if.*over.*18'
    ]
    
    for phrase in explicit_phrases:
        if re.search(phrase, text_content, re.IGNORECASE):
            explicit_score += 2
    
    is_adult = explicit_score >= 5
    
    return {
        'is_adult': is_adult,
        'explicit_score': explicit_score,
        'explicit_terms_found': explicit_terms_found[:5],
        'context_sensitive_found': context_sensitive_found[:5],
        'reason': f"Detected {len(explicit_terms_found)} explicit content indicators" if is_adult else "No explicit content detected",
        'risk_level': 'high' if explicit_score >= 7 else 'medium' if explicit_score >= 5 else 'low'
    }

def extract_text_from_html(html: str) -> str:
    """
    Extract visible text from HTML using BeautifulSoup or fallback to regex.
    """
    if not _HAS_BS4:
        # Fallback to basic regex extraction if BeautifulSoup is not available
        html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL)
        html = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL)
        text = re.sub(r'<[^>]+>', ' ', html)
        text = re.sub(r'\s+', ' ', text)
        return text.strip()
    
    try:
        soup = BeautifulSoup(html, 'html.parser')
        
        for script in soup(["script", "style"]):
            script.decompose()
        
        text = soup.get_text()
        
        lines = (line.strip() for line in text.splitlines())
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        text = ' '.join(chunk for chunk in chunks if chunk)
        
        return text
    except Exception as e:
        logger.error(f"BeautifulSoup extraction failed: {e}. Falling back to regex.")
        # Fallback to basic regex extraction if BeautifulSoup fails
        html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL)
        html = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL)
        text = re.sub(r'<[^>]+>', ' ', html)
        text = re.sub(r'\s+', ' ', text)
        return text.strip()

# (test_analyzer remains unchanged)
def test_analyzer() -> None:
    """Test function to validate the analyzer with known examples"""
    test_cases = [
        "I'm going to rape you and kill your family",
        "Someone should just rape her already",
        "I will hurt you so badly",
        "I know where you live and I'm outside right now",
        "Know your place, women shouldn't be in leadership",
        "Send me nudes or I'll get you fired",
        "Send me money immediately or something bad will happen",
        "I love you, even though you are 12 years old and am 62 years old", # CRITICAL TEST CASE
        "We can keep it a secret, don't tell anyone",
        "This is a normal business message",
    ]
    
    print("=== SalamaCheck Analyzer Test Results ===")
    for i, test_case in enumerate(test_cases, 1):
        result = scan_text(test_case)
        print(f"\nTest {i}: {test_case[:50]}...")
        print(f"Risk: {result['risk']}, Score: {result.get('risk_score', 'N/A')}")
        print(f"Threats: {result.get('detected_threats', [])[:2]}")
    
    print("\n=== Testing Complete ===")

if __name__ == "__main__":
    test_analyzer()