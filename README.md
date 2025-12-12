# SalamaCheck - Online Safety Scanner

**Advanced protection against dangerous links and harmful messages**

[![Live Demo](https://img.shields.io/badge/demo-online-green.svg)](https://salamacheck.onrender.com/)


## 🛡️ Overview

SalamaCheck is a comprehensive web-based safety scanner designed to protect individuals from digital threats.The platform provides real-time analysis of suspicious URLs and messages, helping users identify potential dangers before they cause harm.

### 🎯 The Problem
In today's digital landscape, users face constant threats:
- **Malicious URLs**: Phishing attacks, tracking domains, and malicious redirects
- **Harmful Messages**: Coercion, harassment, and suspicious content in communications
- **Privacy Risks**: Personal information exposure through deceptive links

### 💡 The Solution
SalamaCheck combines advanced URL analysis with sophisticated text sentiment detection to provide instant safety assessments, empowering users to make informed decisions about their online interactions.

## ✨ Key Features

### 🔗 Link Scanner
- **Real-time URL Analysis**: Follows redirects and checks final destinations
- **Dangerous Domain Detection**: Identifies known malicious and tracking domains
- **Content Safety Assessment**: Analyzes page content for explicit material
- **Contextual Intelligence**: Reduces false positives with smart context analysis

### 💬 Message Analyzer  
- **Sentiment Analysis**: Uses VADER sentiment analysis to detect negative intent
- **Red Flag Detection**: Identifies coercive language and suspicious phrases
- **Risk Assessment**: Provides clear risk levels (Low, Medium, High)
- **Detailed Breakdown**: Shows specific triggers and sentiment scores

### 🎨 User Experience
- **Dark/Light Theme**: User-friendly interface with theme toggle
- **Instant Results**: Fast scanning with performance optimization
- **Privacy-First**: No data storage, minimal logging
- **Responsive Design**: Works seamlessly across all devices

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- pip (Python package manager)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/fredxotic/SalamaCheck.git
   cd SalamaCheck
   ```

2. **Create virtual environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**
   ```bash
   python app.py
   ```

5. **Access the application**
   ```
   Open http://localhost:5000 in your browser
   ```

## 🏗️ Architecture

### Backend (Flask)
```
app.py
├── /api/scan/url (POST) - URL safety analysis
├── /api/scan/text (POST) - Message safety analysis
└── /api/health (GET) - Service health check
```

### Analysis Engine
```
analyzer.py
├── scan_url() - Comprehensive URL safety checks
├── scan_text() - Message sentiment and risk analysis
└── Contextual analysis for reduced false positives
```

### Frontend
- **Bootstrap 5** - Responsive UI framework
- **Vanilla JavaScript** - Lightweight, no framework dependencies
- **CSS Variables** - Dynamic theming system

## 🔧 Technical Implementation

### URL Analysis Pipeline
1. **Domain Validation** - Checks against whitelisted safe domains
2. **Redirect Tracking** - Follows URL redirects to final destination
3. **Content Analysis** - Scans page content for explicit material
4. **Risk Classification** - Determines safety level (Safe/Warning/Danger)

### Text Analysis Pipeline
1. **Sentiment Scoring** - VADER sentiment analysis
2. **Pattern Matching** - Red flag phrase detection
3. **Context Evaluation** - Contextual analysis for ambiguous terms
4. **Risk Calculation** - Multi-factor risk assessment

### Security Features
- **Rate Limiting** - Prevents API abuse
- **Privacy Filtering** - Scrubs sensitive data from logs
- **Input Validation** - Protects against injection attacks
- **Timeout Protection** - Prevents resource exhaustion

## 📊 API Documentation

### Scan URL Endpoint
```http
POST /api/scan/url
Content-Type: application/json

{
  "link": "https://example.com"
}
```

**Response:**
```json
{
  "status": "safe|danger|warning|error",
  "final_url": "https://final-destination.com",
  "message": "Safety assessment message",
  "risk_reason": "trusted_domain|suspicious_domain|explicit_content",
  "scan_time": 1.23
}
```

### Analyze Text Endpoint
```http
POST /api/scan/text
Content-Type: application/json

{
  "message": "Text to analyze"
}
```

**Response:**
```json
{
  "risk": "low|medium|high|error",
  "score": -0.456,
  "flags": ["suspicious_phrase_1", "suspicious_phrase_2"],
  "adult_content_detected": false,
  "risk_factors": ["negative_sentiment", "suspicious_phrases"],
  "sentiment_scores": {
    "negative": 0.123,
    "neutral": 0.456,
    "positive": 0.321
  },
  "scan_time": 0.45
}
```

## 🛠️ Development

### Project Structure
```
SalamaCheck/
├── app.py                 # Flask application
├── analyzer.py           # Core analysis logic
├── requirements.txt      # Python dependencies
├── static/
│   ├── css/
│   │   └── style.css    # Styling with dark/light theme
│   ├── js/
│   │   └── script.js    # Frontend functionality
│   └── images/
│       └── icon.png     # Application icon
└── templates/
    └── index.html       # Main application interface
```

### Testing
```bash
# Run the development server
python app.py

# Test URL scanning with:
curl -X POST http://localhost:5000/api/scan/url \
  -H "Content-Type: application/json" \
  -d '{"link":"https://example.com"}'

# Test text analysis with:
curl -X POST http://localhost:5000/api/scan/text \
  -H "Content-Type: application/json" \
  -d '{"message":"Test message for analysis"}'
```

## 🔒 Privacy & Security

### Our Commitment
- **No Data Storage**: We don't store URLs, messages, or personal information
- **Minimal Logging**: Only essential operational data is logged
- **Transparent Processing**: All analysis happens in real-time, no background processing
- **Local Processing**: For self-hosted instances, all data stays within your infrastructure

### Data Handling
- **URLs**: Processed in real-time, not stored
- **Messages**: Analyzed immediately, discarded after processing
- **Logs**: Contain only timestamps and anonymized request counts

## 🌟 Why SalamaCheck?

### For Individuals
- **Peace of Mind**: Verify links before clicking
- **Digital Literacy**: Understand potential risks in messages
- **Privacy Protection**: Avoid tracking and malicious sites

### For Organizations
- **Employee Safety**: Protect team members from digital threats
- **Educational Tool**: Train staff on digital safety practices
- **Customizable**: Self-hosted deployment options

## 🚨 Limitations & Considerations

### Current Limitations
- **Synchronous Processing**: Not optimized for high-volume concurrent requests
- **Basic Context Analysis**: Relies on keyword matching with contextual checks
- **Manual Domain Lists**: Requires periodic updates for new threats

### Production Considerations
- **Scalability**: For high-traffic deployment, i am considering async task queues (Celery)
- **Domain List Maintenance**: Implement automated threat intelligence feeds
- **Rate Limiting**: Enhance with Redis for distributed systems

### Areas for Improvement
- Enhanced machine learning for context understanding
- Browser extension integration
- Advanced threat intelligence integration

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **VADER Sentiment Analysis**: For powerful text sentiment detection
- **Bootstrap**: For responsive UI components
- **Flask**: For lightweight web framework
- **Security Researchers**: For ongoing threat intelligence

---

**Built with ❤️ for a safer digital world**

*SalamaCheck - Your trusted partner in online safety*
