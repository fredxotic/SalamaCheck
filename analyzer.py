import requests
from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
import re
from urllib.parse import urlparse
import time
import json
from typing import Dict, List, Tuple, Any, Optional

# Initialize the Sentiment Intensity Analyzer once at module level
analyzer = SentimentIntensityAnalyzer()

# =============================================================================
# COMPREHENSIVE THREAT AND SAFETY DATABASES
# =============================================================================

# Known dangerous/suspicious URL shorteners and tracking domains
DANGEROUS_DOMAINS = [
    'grabify.link', 'iplogger.org', 'iplogger.com', 'blasze.com',
    'cutt.ly', 'shorte.st', 'adf.ly', 'bc.vc', 'ouo.io', 'click.ru',
    'link.tl', 'soo.gd', 'thy.pw', 'ceesty.com', 'urlz.fr', 'zzb.bz',
    '2no.co', 'ipgrab.org', 'yip.su', 'iplo.ru', 'traceurl.com'
]

# Known legitimate domains that should never be flagged (whitelist)
SAFE_DOMAINS = [
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

# Suspicious URL shorteners (check more carefully)
SUSPICIOUS_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'shorturl.at', 't.co', 'goo.gl', 'ow.ly',
    'buff.ly', 'tiny.cc', 'is.gd', 'cli.gs', 'yfrog.com', 'migre.me',
    'ff.im', 'url4.eu', 'twit.ac', 'su.pr', 'twurl.nl', 'snipurl.com',
    'short.to', 'budurl.com', 'ping.fm', 'post.ly', 'just.as', 'bkite.com',
    'twitterfeed.com', 'shrten.com', 'short.ie', 'shorl.com', 'x.co'
]

# =============================================================================
# ADVANCED THREAT DETECTION PATTERNS
# =============================================================================

# SEVERE THREATS - Automatic high risk
SEVERE_THREATS = [
    r'rape\s+(you|her|him|them)', r'kill\s+(you|yourself|myself)', 
    r'murder\s+(you|her|him)', r'shoot\s+(you|her|him)', r'stab\s+(you|her|him)',
    r'cut\s+(your|my)\s+(throat|wrist)', r'hang\s+(yourself|myself)',
    r'beat\s+you\s+to\s+death', r'burn\s+(you|your)', r'throw\s+acid',
    r'strangle\s+(you|her|him)', r'slit\s+(your|my)\s+(throat|wrist)'
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
    r'don\'t\s+tell\s+anyone', r'keep\s+this\s+between\s+us',
    r'this\s+is\s+confidential', r'delete\s+this', r'secret',
    r'or\s+else', r'something\s+bad\s+will\s+happen',
    r'i\s+have\s+your\s+(information|pictures)'
]

# HIGH-CONFIDENCE EXPLICIT TERMS
EXPLICIT_TERMS = [
    r'\bporn\b', r'\bpornography\b', r'\bxxx\b', r'\bhardcore\b', 
    r'\bblowjob\b', r'\bfuck\b', r'\bdick\b', r'\bcock\b', r'\bpussy\b', 
    r'\bcum\b', r'\borgasm\b', r'\bmasturbat\b', r'\bgangbang\b', 
    r'\banal\b', r'\bmilf\b', r'\bincest\b', r'\btaboo\b'
]

# CONTEXT-SENSITIVE TERMS WITH SAFE INDICATORS
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
    'severe_threat': 15,      # Automatic high risk
    'violent_threat': 10,     # Very high risk
    'stalking': 9,           # Very high risk
    'gendered_harassment': 8, # High risk
    'sexual_harassment': 8,   # High risk
    'coercion': 7,           # Medium-high risk
    'gendered_insult': 6,     # Medium risk
    'explicit_content': 5,    # Medium risk
    'suspicious_phrase': 4,   # Low-medium risk
    'negative_sentiment': 2   # Low risk
}

RISK_THRESHOLDS = {
    'high': 8,      # Score >= 8 = High risk
    'medium': 4,    # Score >= 4 = Medium risk
    'low': 0        # Score < 4 = Low risk
}

# =============================================================================
# CORE ANALYSIS FUNCTIONS
# =============================================================================

def get_domain_from_url(url: str) -> str:
    """Extract the main domain from a URL"""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        # Remove www. prefix if present
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain
    except:
        return ""

def is_safe_domain(domain: str) -> bool:
    """Check if a domain is in the safe whitelist"""
    for safe_domain in SAFE_DOMAINS:
        if domain == safe_domain or domain.endswith('.' + safe_domain):
            return True
    return False

def is_dangerous_domain(domain: str) -> bool:
    """Check if a domain is explicitly dangerous"""
    for dangerous_domain in DANGEROUS_DOMAINS:
        if domain == dangerous_domain or domain.endswith('.' + dangerous_domain):
            return True
    return False

def is_suspicious_shortener(domain: str) -> bool:
    """Check if a domain is a suspicious URL shortener"""
    for shortener in SUSPICIOUS_SHORTENERS:
        if domain == shortener or domain.endswith('.' + shortener):
            return True
    return False

def analyze_context(text: str, keyword: str) -> bool:
    """
    Analyze context around a keyword to determine if it's actually explicit
    Returns True if explicit, False if safe
    """
    text_lower = text.lower()
    
    # Find all occurrences with word boundaries
    pattern = r'\b' + re.escape(keyword) + r'\b'
    occurrences = []
    
    for match in re.finditer(pattern, text_lower):
        occurrences.append(match.start())
    
    # Analyze context around each occurrence
    for idx in occurrences:
        # Get context window (50 characters before and after)
        start_ctx = max(0, idx - 50)
        end_ctx = min(len(text_lower), idx + len(keyword) + 50)
        context = text_lower[start_ctx:end_ctx]
        
        # Check for safe context indicators
        safe_indicators = CONTEXT_SENSITIVE_TERMS.get(keyword, [])
        for indicator in safe_indicators:
            if re.search(r'\b' + re.escape(indicator) + r'\b', context):
                return False  # Safe context found
    
    return True  # No safe context found, assume explicit

def detect_threat_patterns(text: str) -> Dict[str, List[str]]:
    """
    Advanced threat pattern detection using regex patterns
    Returns categorized threats with their matches
    """
    text_lower = text.lower()
    threats_detected = {
        'severe_threat': [],
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
    
    # Gendered insults (word boundaries)
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
            # Check context for explicit terms
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
    
    # Automatic high risk for severe threats
    if threats_detected['severe_threat']:
        return ('high', 100, ['severe_violent_threats'])
    
    # Calculate weighted score from all threat categories
    for category, matches in threats_detected.items():
        if matches:
            weight = THREAT_WEIGHTS.get(category, 0)
            category_score = min(len(matches) * weight, weight * 3)  # Cap per category
            total_score += category_score
            
            # Add risk factor description
            if category == 'violent_threat':
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
    
    # Add sentiment influence (much lower weight than threats)
    if sentiment_score < -0.7:
        total_score += THREAT_WEIGHTS['negative_sentiment']
        risk_factors.append('highly_negative_sentiment')
    elif sentiment_score < -0.4:
        total_score += THREAT_WEIGHTS['negative_sentiment'] // 2
        risk_factors.append('negative_sentiment')
    
    # Add explicit content score
    if explicit_score > 0:
        total_score += min(explicit_score, THREAT_WEIGHTS['explicit_content'])
    
    # Determine risk level
    if total_score >= RISK_THRESHOLDS['high']:
        risk_level = 'high'
    elif total_score >= RISK_THRESHOLDS['medium']:
        risk_level = 'medium'
    else:
        risk_level = 'low'
    
    return (risk_level, total_score, risk_factors)

def scan_text(message: str) -> Dict[str, Any]:
    """
    Comprehensive text analysis for threats, harassment, and safety risks
    """
    start_time = time.time()
    
    try:
        message_lower = message.lower()
        
        # Perform sentiment analysis
        sentiment_scores = analyzer.polarity_scores(message_lower)
        compound_score = sentiment_scores['compound']
        
        # Threat pattern detection
        threats_detected = detect_threat_patterns(message_lower)
        
        # Calculate explicit content score separately
        explicit_score = 0
        explicit_terms_found = []
        
        for pattern in EXPLICIT_TERMS:
            matches = re.findall(pattern, message_lower)
            if matches:
                keyword = pattern.strip(r'\b')
                if analyze_context(message_lower, keyword):
                    explicit_score += 3 * len(matches)
                    explicit_terms_found.extend(matches)
        
        # Context-sensitive explicit terms
        for term, safe_indicators in CONTEXT_SENSITIVE_TERMS.items():
            if re.search(r'\b' + re.escape(term) + r'\b', message_lower):
                if analyze_context(message_lower, term):
                    explicit_score += 2
                    explicit_terms_found.append(term)
        
        # Calculate comprehensive risk
        risk_level, risk_score, risk_factors = calculate_comprehensive_risk(
            threats_detected, compound_score, explicit_score
        )
        
        # Prepare detailed results
        all_detected_threats = []
        for category, matches in threats_detected.items():
            if matches:
                for match in matches[:3]:  # Limit to top 3 per category
                    all_detected_threats.append(f"{category}: {match}")
        
        # Create comprehensive result
        result = {
            'risk': risk_level,
            'risk_score': risk_score,
            'sentiment_score': round(compound_score, 3),
            'detected_threats': all_detected_threats[:10],  # Limit for display
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
        
        # Add specific flags for UI display
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
        
        return result
        
    except Exception as e:
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
        # Ensure the link has a protocol prefix
        if not link.startswith(('http://', 'https://')):
            link = 'https://' + link
        
        # Extract domain for initial checks
        initial_domain = get_domain_from_url(link)
        
        # First, check if it's a safe domain (whitelist)
        if is_safe_domain(initial_domain):
            return {
                'status': 'safe',
                'final_url': link,
                'message': 'This link is from a trusted domain',
                'risk_reason': 'trusted_domain',
                'scan_time': round(time.time() - start_time, 2)
            }
        
        # Check if it's an explicitly dangerous domain
        if is_dangerous_domain(initial_domain):
            return {
                'status': 'danger',
                'final_url': link,
                'message': f'Warning: This is a known suspicious domain ({initial_domain})',
                'risk_reason': 'suspicious_domain',
                'scan_time': round(time.time() - start_time, 2)
            }
        
        # Follow redirects with timeout protection (reduced timeout)
        response = requests.get(
            link, 
            timeout=5,  # Reduced from 10 to 5 seconds
            allow_redirects=True,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            verify=True
        )
        
        final_url = response.url.lower()
        final_domain = get_domain_from_url(final_url)
        
        # Check if final domain is safe
        if is_safe_domain(final_domain):
            return {
                'status': 'safe',
                'final_url': final_url,
                'message': 'This link redirects to a trusted domain',
                'risk_reason': 'trusted_redirect',
                'scan_time': round(time.time() - start_time, 2)
            }
        
        # Check if it's an explicitly dangerous domain
        if is_dangerous_domain(final_domain):
            return {
                'status': 'danger',
                'final_url': final_url,
                'message': f'Warning: Link redirects to known suspicious domain ({final_domain})',
                'risk_reason': 'suspicious_domain',
                'scan_time': round(time.time() - start_time, 2)
            }
        
        # Check for suspicious URL shorteners
        if is_suspicious_shortener(final_domain):
            return {
                'status': 'warning',
                'final_url': final_url,
                'message': f'Caution: This is a URL shortener service. Proceed with caution.',
                'risk_reason': 'url_shortener',
                'scan_time': round(time.time() - start_time, 2)
            }
        
        # Analyze page content for adult/explicit material (only if we have content)
        if response.status_code == 200 and len(response.text) > 100:
            content_analysis = analyze_page_content(response.text, final_url)
            if content_analysis['is_adult']:
                return {
                    'status': 'danger',
                    'final_url': final_url,
                    'message': f'Explicit Content Detected: {content_analysis["reason"]}',
                    'risk_reason': 'explicit_content',
                    'content_analysis': content_analysis,
                    'scan_time': round(time.time() - start_time, 2)
                }
        
        # If no issues found, consider it safe
        return {
            'status': 'safe',
            'final_url': final_url,
            'message': 'This link appears to be safe',
            'risk_reason': 'clean',
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
        return {
            'status': 'error',
            'message': f'Unexpected error during URL analysis: {str(e)}',
            'scan_time': round(time.time() - start_time, 2)
        }

def analyze_page_content(html_content: str, url: str) -> Dict[str, Any]:
    """
    Analyze HTML content for adult/explicit material with contextual analysis.
    """
    # Convert to lowercase for case-insensitive matching
    content_lower = html_content.lower()
    
    # Extract text content (basic extraction)
    text_content = extract_text_from_html(content_lower)
    
    # Check for explicit terms (high confidence)
    explicit_terms_found = []
    explicit_score = 0
    
    for term in EXPLICIT_TERMS:
        if re.search(term, text_content):
            explicit_score += 3
            explicit_terms_found.append(term.strip(r'\b'))
    
    # Check for context-sensitive terms (medium confidence)
    context_sensitive_found = []
    for term, safe_indicators in CONTEXT_SENSITIVE_TERMS.items():
        if re.search(r'\b' + re.escape(term) + r'\b', text_content):
            # Analyze context to determine if it's actually explicit
            if analyze_context(text_content, term):
                explicit_score += 2
                context_sensitive_found.append(term)
            else:
                # Safe context found, don't penalize
                explicit_score += 0.1  # Minimal penalty for presence
    
    # Check for explicit phrases and patterns
    explicit_phrases = [
        r'porn', r'xxx', r'hardcore.*video', r'sex.*video', r'nsfw',
        r'explicit.*content', r'mature.*content', r'you must be 18',
        r'age.*verification', r'adult.*warning', r'enter.*if.*over.*18'
    ]
    
    for phrase in explicit_phrases:
        if re.search(phrase, text_content, re.IGNORECASE):
            explicit_score += 2
    
    # Determine if content is adult (higher threshold to reduce false positives)
    is_adult = explicit_score >= 5  # Increased threshold for adult content detection
    
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
    Basic HTML text extraction (removes tags and extracts visible text).
    """
    # Remove script and style elements
    html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL)
    html = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL)
    
    # Remove HTML tags
    text = re.sub(r'<[^>]+>', ' ', html)
    
    # Remove extra whitespace
    text = re.sub(r'\s+', ' ', text)
    
    return text.strip()

# =============================================================================
# TESTING AND VALIDATION
# =============================================================================

def test_analyzer() -> None:
    """Test function to validate the analyzer with known examples"""
    test_cases = [
        # Severe threats
        "I'm going to rape you and kill your family",
        "Someone should just rape her already",
        
        # Violent threats
        "I will hurt you so badly",
        "I'm going to beat you to death",
        
        # Stalking
        "I know where you live and I'm outside right now",
        "I'm watching you from across the street",
        
        # Gendered harassment
        "Know your place, women shouldn't be in leadership",
        "You're just a diversity hire who slept with the boss",
        
        # Sexual harassment  
        "Send me nudes or I'll get you fired",
        "I want to see your body right now",
        
        # Coercion
        "Send me money immediately or something bad will happen",
        "Don't tell anyone about this, it's our secret",
        
        # Safe examples
        "This is a normal business message",
        "I disagree with your approach to the project"
    ]
    
    print("=== SalamaCheck Analyzer Test Results ===")
    for i, test_case in enumerate(test_cases, 1):
        result = scan_text(test_case)
        print(f"\nTest {i}: {test_case[:50]}...")
        print(f"Risk: {result['risk']}, Score: {result.get('risk_score', 'N/A')}")
        print(f"Threats: {result.get('detected_threats', [])[:2]}")
    
    print("\n=== Testing Complete ===")

if __name__ == "__main__":
    # Run tests if executed directly
    test_analyzer()