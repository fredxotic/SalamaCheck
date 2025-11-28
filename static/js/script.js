// DOM Elements
const scanLinkBtn = document.getElementById('scanLinkBtn');
const analyzeTextBtn = document.getElementById('analyzeTextBtn');
const linkInput = document.getElementById('linkInput');
const textInput = document.getElementById('textInput');
const themeToggle = document.getElementById('themeToggle');

// Utility Functions
class SalamaCheckUI {
    // Show loading state for buttons
    static setButtonLoading(button, isLoading) {
        if (!button) return;
        
        const spinner = button.querySelector('.spinner-border');
        const btnText = button.querySelector('.btn-text');
        
        if (isLoading) {
            button.disabled = true;
            if (spinner) spinner.classList.remove('d-none');
            if (btnText) {
                btnText.textContent = button === scanLinkBtn ? 'Scanning...' : 'Analyzing...';
            }
            button.classList.add('loading');
        } else {
            button.disabled = false;
            if (spinner) spinner.classList.add('d-none');
            if (btnText) {
                btnText.textContent = button === scanLinkBtn ? 'Scan Link Security' : 'Analyze Message Safety';
            }
            button.classList.remove('loading');
        }
    }

    // Hide result containers
    static hideResults() {
        const urlResult = document.getElementById('urlResult');
        const textResult = document.getElementById('textResult');
        
        if (urlResult) urlResult.classList.add('d-none');
        if (textResult) textResult.classList.add('d-none');
    }

    // Show help button for dangerous results
    static showHelpButton(containerId) {
        const container = document.getElementById(containerId);
        if (!container) return;
        
        const existingHelpBtn = container.querySelector('.help-btn');
        if (existingHelpBtn) {
            existingHelpBtn.remove();
        }

        const helpBtn = document.createElement('a');
        // This links to an internal path which you can render an HTML page for
        helpBtn.href = '/safety-resources'; 
        helpBtn.className = 'btn btn-outline-danger mt-3 help-btn';
        helpBtn.innerHTML = `
            <i class="bi bi-life-preserver"></i>
            <span>Safety Resources & Reporting Guide</span>
        `;
        
        container.appendChild(helpBtn);
    }

    // Remove help button
    static removeHelpButton(containerId) {
        const container = document.getElementById(containerId);
        if (!container) return;
        
        const helpBtn = container.querySelector('.help-btn');
        if (helpBtn) {
            helpBtn.remove();
        }
    }

    // Show temporary feedback message
    static showFeedback(message, type = 'info') {
        // Remove existing feedback
        const existingFeedback = document.querySelector('.salama-feedback');
        if (existingFeedback) {
            existingFeedback.remove();
        }

        const feedback = document.createElement('div');
        feedback.className = `salama-feedback alert alert-${type} position-fixed`;
        feedback.style.cssText = `
            top: 100px;
            right: 20px;
            z-index: 1060;
            min-width: 300px;
            max-width: 90vw;
            animation: slideInRight 0.3s ease;
            border-radius: 12px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.15);
        `;
        feedback.innerHTML = `
            <div class="d-flex align-items-center">
                <i class="bi bi-${this.getFeedbackIcon(type)} me-2"></i>
                <span class="flex-grow-1">${this.escapeHtml(message)}</span>
                <button type="button" class="btn-close ms-2" onclick="this.parentElement.parentElement.remove()"></button>
            </div>
        `;
        
        document.body.appendChild(feedback);
        
        // Auto-remove after 5 seconds
        setTimeout(() => {
            if (feedback.parentElement) {
                feedback.style.animation = 'slideOutRight 0.3s ease';
                setTimeout(() => feedback.remove(), 300);
            }
        }, 5000);
    }

    static getFeedbackIcon(type) {
        const icons = {
            'info': 'info-circle',
            'success': 'check-circle',
            'warning': 'exclamation-triangle',
            'error': 'x-circle'
        };
        return icons[type] || 'info-circle';
    }

    // FIXED: Ensure proper HTML escaping for link/text display
    static escapeHtml(unsafe) {
        if (typeof unsafe !== 'string') return '';
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
}

// API Service
class SalamaCheckAPI {
    static async scanUrl(url) {
        try {
            const response = await fetch('/api/scan/url', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ link: url })
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            
            if (data.status === 'error') {
                throw new Error(data.message || 'Unknown API error');
            }

            return data;

        } catch (error) {
            console.error('URL scan API error:', error);
            throw new Error(error.message || 'Network error occurred');
        }
    }

    static async scanText(message) {
        try {
            const response = await fetch('/api/scan/text', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ message: message })
            });

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({}));
                throw new Error(errorData.message || `HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            
            if (data.status === 'error') {
                throw new Error(data.message || 'Unknown API error');
            }

            return data;

        } catch (error) {
            console.error('Text scan API error:', error);
            throw new Error(error.message || 'Network error occurred');
        }
    }
}

// Form Validation
class FormValidator {
    static validateUrl(url) {
        if (!url || !url.trim()) {
            return { isValid: false, message: 'Please enter a URL to scan' };
        }

        // Basic URL validation
        try {
            const urlObj = new URL(url.startsWith('http') ? url : `https://${url}`);
            
            if (!urlObj.hostname) {
                return { isValid: false, message: 'Please enter a valid URL' };
            }

            if (url.length > 500) {
                return { isValid: false, message: 'URL is too long' };
            }

            return { isValid: true, sanitizedUrl: urlObj.href };

        } catch (error) {
            return { isValid: false, message: 'Please enter a valid URL (e.g., example.com or https://example.com)' };
        }
    }

    static validateMessage(message) {
        if (!message || !message.trim()) {
            return { isValid: false, message: 'Please enter a message to analyze' };
        }

        if (message.trim().length < 3) {
            return { isValid: false, message: 'Message is too short to analyze (minimum 3 characters)' };
        }

        if (message.length > 5000) {
            return { isValid: false, message: 'Message is too long (maximum 5000 characters)' };
        }

        return { isValid: true, sanitizedMessage: message.trim() };
    }
}

// Theme Management
class ThemeManager {
    static init() {
        if (!themeToggle) return;
        
        const savedTheme = localStorage.getItem('salama-theme') || 'light';
        this.setTheme(savedTheme);
        
        themeToggle.addEventListener('click', () => {
            const currentTheme = document.documentElement.getAttribute('data-theme') || 'light';
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            this.setTheme(newTheme);
        });
    }
    
    static setTheme(theme) {
        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('salama-theme', theme);
        
        const icon = themeToggle?.querySelector('i');
        if (!icon) return;
        
        if (theme === 'dark') {
            icon.className = 'bi bi-sun-fill';
            themeToggle.setAttribute('aria-label', 'Switch to light theme');
            themeToggle.title = 'Switch to light theme';
        } else {
            icon.className = 'bi bi-moon-fill';
            themeToggle.setAttribute('aria-label', 'Switch to dark theme');
            themeToggle.title = 'Switch to dark theme';
        }

        window.dispatchEvent(new CustomEvent('themeChanged', { detail: { theme } }));
    }

    static getCurrentTheme() {
        return document.documentElement.getAttribute('data-theme') || 'light';
    }
}

// Link Scanner Logic
if (scanLinkBtn && linkInput) {
    scanLinkBtn.addEventListener('click', async () => {
        const url = linkInput.value.trim();
        
        // Validation
        const validation = FormValidator.validateUrl(url);
        if (!validation.isValid) {
            SalamaCheckUI.showFeedback(validation.message, 'warning');
            linkInput.classList.add('is-invalid');
            return;
        }

        // Clear previous states
        linkInput.classList.remove('is-invalid');
        SalamaCheckUI.setButtonLoading(scanLinkBtn, true);
        SalamaCheckUI.hideResults();
        SalamaCheckUI.removeHelpButton('urlResult');

        try {
            SalamaCheckUI.showFeedback('Scanning URL for safety...', 'info');
            const result = await SalamaCheckAPI.scanUrl(validation.sanitizedUrl);
            displayUrlResult(result.data || result);
            SalamaCheckUI.showFeedback('URL scan completed!', 'success');
        } catch (error) {
            console.error('URL scan error:', error);
            showError('urlResult', error.message);
            SalamaCheckUI.showFeedback(`Scan failed: ${error.message}`, 'error');
        } finally {
            SalamaCheckUI.setButtonLoading(scanLinkBtn, false);
        }
    });
}

// Text Analyzer Logic
if (analyzeTextBtn && textInput) {
    analyzeTextBtn.addEventListener('click', async () => {
        const message = textInput.value.trim();
        
        // Validation
        const validation = FormValidator.validateMessage(message);
        if (!validation.isValid) {
            SalamaCheckUI.showFeedback(validation.message, 'warning');
            textInput.classList.add('is-invalid');
            return;
        }

        // Clear previous states
        textInput.classList.remove('is-invalid');
        SalamaCheckUI.setButtonLoading(analyzeTextBtn, true);
        SalamaCheckUI.hideResults();
        SalamaCheckUI.removeHelpButton('textResult');

        try {
            SalamaCheckUI.showFeedback('Analyzing message content...', 'info');
            const result = await SalamaCheckAPI.scanText(validation.sanitizedMessage);
            displayTextResult(result.data || result);
            SalamaCheckUI.showFeedback('Message analysis completed!', 'success');
        } catch (error) {
            console.error('Text analysis error:', error);
            showError('textResult', error.message);
            SalamaCheckUI.showFeedback(`Analysis failed: ${error.message}`, 'error');
        } finally {
            SalamaCheckUI.setButtonLoading(analyzeTextBtn, false);
        }
    });
}

// Display URL Scan Results
function displayUrlResult(result) {
    const resultContainer = document.getElementById('urlResult');
    const alertElement = document.getElementById('urlAlert');
    const titleElement = document.getElementById('urlResultTitle');
    const messageElement = document.getElementById('urlResultMessage');
    const detailsElement = document.getElementById('urlResultDetails');

    if (!resultContainer || !alertElement || !titleElement || !messageElement || !detailsElement) {
        console.error('URL result elements not found');
        return;
    }

    // Reset classes and content
    alertElement.className = 'alert';
    detailsElement.innerHTML = '';

    let statusConfig = {
        'danger': {
            class: 'danger-result',
            icon: '⚠️',
            title: 'Danger Detected',
            showHelp: true
        },
        'safe': {
            class: 'safe-result',
            icon: '✅',
            title: 'Safe',
            showHelp: false
        },
        'warning': {
            class: 'warning-result',
            icon: '🔍',
            title: 'Caution',
            showHelp: false
        },
        'error': {
            class: 'warning-result',
            icon: '❌',
            title: 'Scan Error',
            showHelp: false
        }
    };

    const config = statusConfig[result.status] || statusConfig.error;

    // Apply styling and content
    alertElement.classList.add(config.class);
    titleElement.textContent = `${config.icon} ${config.title}`;
    messageElement.textContent = result.message || 'No message provided';

    // Add details with proper URL display
    if (result.final_url) {
        const urlDetail = document.createElement('div');
        urlDetail.className = 'mb-3';
        
        const urlLabel = document.createElement('div');
        urlLabel.className = 'fw-bold mb-2';
        urlLabel.textContent = 'Final URL:';
        urlDetail.appendChild(urlLabel);
        
        const urlDisplay = document.createElement('div');
        urlDisplay.className = 'url-display';
        // Use escapeHtml for safety
        urlDisplay.innerHTML = `<code>${SalamaCheckUI.escapeHtml(result.final_url)}</code>`;
        urlDetail.appendChild(urlDisplay);
        
        detailsElement.appendChild(urlDetail);
    }

    // Display redirect chain if available (New logic for clarity)
    if (result.redirect_chain && result.redirect_chain.length > 1) {
        const redirectDetail = document.createElement('div');
        redirectDetail.className = 'mb-3';
        
        const redirectLabel = document.createElement('div');
        redirectLabel.className = 'fw-bold mb-2';
        redirectLabel.textContent = 'Redirect Path:';
        redirectDetail.appendChild(redirectLabel);
        
        const redirectList = document.createElement('div');
        redirectList.className = 'redirect-chain small';
        
        result.redirect_chain.forEach((domain, index) => {
            const domainItem = document.createElement('div');
            domainItem.className = 'd-flex align-items-center mb-1';
            
            if (index > 0) {
                const arrow = document.createElement('span');
                arrow.className = 'me-2 text-muted';
                arrow.innerHTML = '↳';
                domainItem.appendChild(arrow);
            }
            
            const domainBadge = document.createElement('span');
            domainBadge.className = 'badge bg-light text-dark me-2';
            domainBadge.textContent = domain;
            domainItem.appendChild(domainBadge);
            
            // Highlight dangerous/suspicious domains
            if (result.dangerous_redirects && result.dangerous_redirects.includes(domain)) {
                domainBadge.className = 'badge bg-danger text-white me-2';
            } else if (result.suspicious_redirects && result.suspicious_redirects.includes(domain)) {
                domainBadge.className = 'badge bg-warning text-dark me-2';
            }
            
            redirectList.appendChild(domainItem);
        });
        
        redirectDetail.appendChild(redirectList);
        detailsElement.appendChild(redirectDetail);
    }
    
    if (result.risk_reason && result.risk_reason !== 'clean') {
        const reasonDetail = document.createElement('div');
        reasonDetail.className = 'mb-2';
        reasonDetail.innerHTML = `<strong>Reason:</strong> ${formatRiskReason(result.risk_reason)}`;
        detailsElement.appendChild(reasonDetail);
    }

    // Add scan time
    if (result.scan_time) {
        const timeElement = document.createElement('small');
        timeElement.className = 'text-muted d-block mt-2';
        timeElement.textContent = `Scan completed in ${result.scan_time}s`;
        detailsElement.appendChild(timeElement);
    }

    // Show/hide help button
    if (config.showHelp) {
        SalamaCheckUI.showHelpButton('urlResult');
    } else {
        SalamaCheckUI.removeHelpButton('urlResult');
    }

    // Show result container with animation
    resultContainer.classList.remove('d-none');
    resultContainer.style.animation = 'slideIn 0.3s ease-out';
}

// Format risk reason for display
function formatRiskReason(reason) {
    const reasonMap = {
        'trusted_domain': 'Domain is in trusted list',
        'suspicious_domain': 'Known suspicious domain',
        'trusted_redirect': 'Redirects to trusted domain',
        'url_shortener': 'URL shortener service detected',
        'explicit_content': 'Explicit content detected',
        'clean': 'No issues found',
        'suspicious_redirect_chain': 'Redirects through known malicious domains',
        'url_shortener_chain': 'Uses multiple URL shorteners'
    };
    return reasonMap[reason] || reason.replace(/_/g, ' ');
}

// Display Text Analysis Results
function displayTextResult(result) {
    const resultContainer = document.getElementById('textResult');
    const alertElement = document.getElementById('textAlert');
    const titleElement = document.getElementById('textResultTitle');
    const messageElement = document.getElementById('textResultMessage');
    const scoreElement = document.getElementById('textScore');
    const flagsElement = document.getElementById('textFlags');

    if (!resultContainer || !alertElement || !titleElement || !messageElement || !scoreElement || !flagsElement) {
        console.error('Text result elements not found');
        return;
    }

    // Reset classes and content
    alertElement.className = 'alert';
    flagsElement.innerHTML = '';

    let riskConfig = {
        'high': {
            class: 'danger-result',
            icon: '🚨',
            title: 'High Risk Detected',
            showHelp: true
        },
        'medium': {
            class: 'warning-result',
            icon: '⚠️',
            title: 'Medium Risk',
            showHelp: false
        },
        'low': {
            class: 'safe-result',
            icon: '✅',
            title: 'Low Risk',
            showHelp: false
        },
        'error': {
            class: 'warning-result',
            icon: '❌',
            title: 'Analysis Error',
            showHelp: false
        }
    };

    const config = riskConfig[result.risk] || riskConfig.error;

    // Apply styling and content
    alertElement.classList.add(config.class);
    titleElement.textContent = `${config.icon} ${config.title}`;

    // Enhanced message based on risk factors
    let riskMessage = getRiskMessage(result);
    messageElement.textContent = riskMessage;

    // Score display - handle both old and new result formats
    let scoreText = '';
    if (result.risk_score !== undefined) {
        scoreText = `Risk Score: ${result.risk_score}`;
    } else if (result.score !== undefined) {
        scoreText = `Sentiment Score: ${result.score}`;
    }
    
    if (result.sentiment_score !== undefined) {
        scoreText += ` | Sentiment: ${result.sentiment_score}`;
    }
    scoreElement.textContent = scoreText;

    // Display detected threats
    if (result.detected_threats && result.detected_threats.length > 0) {
        const threatsTitle = document.createElement('div');
        threatsTitle.className = 'fw-bold mt-3 mb-2 text-danger';
        threatsTitle.textContent = '🚨 Threats Detected:';
        flagsElement.appendChild(threatsTitle);
        
        result.detected_threats.forEach(threat => {
            const threatBadge = document.createElement('span');
            threatBadge.className = 'flag-item bg-danger text-white me-2 mb-2';
            threatBadge.textContent = threat.length > 50 ? threat.substring(0, 47) + '...' : threat;
            flagsElement.appendChild(threatBadge);
        });
    }

    // Display threat categories
    if (result.threat_categories && Object.keys(result.threat_categories).length > 0) {
        const categoriesTitle = document.createElement('div');
        categoriesTitle.className = 'fw-bold mt-3 mb-2';
        categoriesTitle.textContent = '📊 Threat Categories:';
        flagsElement.appendChild(categoriesTitle);
        
        Object.entries(result.threat_categories).forEach(([category, count]) => {
            if (count > 0) {
                const categoryBadge = document.createElement('span');
                // Use danger background for high-priority threats like grooming
                const isHighRisk = category === 'grooming' || category === 'severe_threat';
                categoryBadge.className = `flag-item me-2 mb-2 ${isHighRisk ? 'bg-danger text-white' : 'bg-warning text-dark'}`;
                categoryBadge.textContent = `${formatCategoryName(category)}: ${count}`;
                flagsElement.appendChild(categoryBadge);
            }
        });
    }

    // Display flags (backward compatibility/general safety)
    if (result.flags && result.flags.length > 0) {
        const flagsTitle = document.createElement('div');
        flagsTitle.className = 'fw-bold mt-3 mb-2';
        flagsTitle.textContent = '🚩 Safety Flags:';
        flagsElement.appendChild(flagsTitle);
        
        result.flags.forEach(flag => {
            const flagBadge = document.createElement('span');
            flagBadge.className = 'flag-item bg-info text-white me-2 mb-2';
            flagBadge.textContent = formatFlagName(flag);
            flagsElement.appendChild(flagBadge);
        });
    }

    // Show explicit content warning if detected
    if (result.adult_content_detected) {
        const adultWarning = document.createElement('div');
        adultWarning.className = 'mt-3 p-3 rounded small';
        adultWarning.style.background = 'rgba(239, 68, 68, 0.1)';
        adultWarning.style.border = '1px solid rgba(239, 68, 68, 0.2)';
        adultWarning.innerHTML = `
            <strong>⚠️ Explicit Content Detected:</strong> 
            Content score ${result.adult_content_score} with terms: 
            ${(result.explicit_terms_found?.slice(0, 3).join(', ') || 'various indicators')}
        `;
        flagsElement.appendChild(adultWarning);
    }

    // Show risk factors
    if (result.risk_factors && result.risk_factors.length > 0) {
        const factorsTitle = document.createElement('div');
        factorsTitle.className = 'fw-bold mt-3 mb-2';
        factorsTitle.textContent = '🔍 Risk Factors:';
        flagsElement.appendChild(factorsTitle);
        
        result.risk_factors.forEach(factor => {
            const factorBadge = document.createElement('span');
            factorBadge.className = 'flag-item me-2 mb-2';
            factorBadge.style.background = 'rgba(245, 158, 11, 0.1)';
            factorBadge.style.borderColor = 'rgba(245, 158, 11, 0.3)';
            factorBadge.textContent = formatRiskFactor(factor);
            flagsElement.appendChild(factorBadge);
        });
    }

    // Add sentiment breakdown
    if (result.sentiment_breakdown) {
        const sentimentDetails = document.createElement('div');
        sentimentDetails.className = 'mt-3 pt-3 border-top';
        sentimentDetails.innerHTML = `
            <div class="small text-muted mb-2">Sentiment Breakdown:</div>
            <div class="d-flex justify-content-between align-items-center" style="max-width: 400px;">
                <div class="text-center">
                    <div class="fw-bold text-danger">${(result.sentiment_breakdown.negative * 100).toFixed(0)}%</div>
                    <small>Negative</small>
                </div>
                <div class="text-center">
                    <div class="fw-bold text-muted">${(result.sentiment_breakdown.neutral * 100).toFixed(0)}%</div>
                    <small>Neutral</small>
                </div>
                <div class="text-center">
                    <div class="fw-bold text-success">${(result.sentiment_breakdown.positive * 100).toFixed(0)}%</div>
                    <small>Positive</small>
                </div>
            </div>
        `;
        flagsElement.appendChild(sentimentDetails);
    }

    // Add scan time and message length
    const metaInfo = document.createElement('div');
    metaInfo.className = 'mt-3 pt-2 border-top small text-muted';
    let metaText = `Analysis completed in ${result.scan_time || 0}s`;
    if (result.message_length) {
        metaText += ` • ${result.message_length} characters analyzed`;
    }
    metaInfo.innerHTML = metaText;
    flagsElement.appendChild(metaInfo);

    // Show/hide help button
    if (config.showHelp) {
        SalamaCheckUI.showHelpButton('textResult');
    } else {
        SalamaCheckUI.removeHelpButton('textResult');
    }

    // Show result container with animation
    resultContainer.classList.remove('d-none');
    resultContainer.style.animation = 'slideIn 0.3s ease-out';
}

// Format category names for display
function formatCategoryName(category) {
    const categoryMap = {
        'severe_threat': 'Severe Threats',
        'grooming': 'Grooming Behavior', // NEW: Added mapping
        'violent_threat': 'Violent Threats',
        'stalking': 'Stalking',
        'gendered_harassment': 'Gendered Harassment',
        'sexual_harassment': 'Sexual Harassment',
        'coercion': 'Coercion',
        'gendered_insult': 'Gendered Insults',
        'explicit_content': 'Explicit Content'
    };
    return categoryMap[category] || category.replace(/_/g, ' ');
}

// Format flag names for display
function formatFlagName(flag) {
    const flagMap = {
        'violent_language': 'Violent Language',
        'harassment': 'Harassment',
        'stalking': 'Stalking Behavior',
        'coercion': 'Coercion',
        'explicit_content': 'Explicit Content',
        'grooming': 'Grooming/Social Engineering' // NEW: Added mapping
    };
    return flagMap[flag] || flag.replace(/_/g, ' ');
}

// Format risk factor names
function formatRiskFactor(factor) {
    const factorMap = {
        'severe_violent_threats': 'Severe Violent Threats',
        'grooming_behavior': 'Grooming Behavior', // NEW: Added mapping
        'violent_threats': 'Violent Threats',
        'stalking_behavior': 'Stalking Behavior',
        'gendered_harassment': 'Gendered Harassment',
        'sexual_harassment': 'Sexual Harassment',
        'coercive_language': 'Coercive Language',
        'gendered_insults': 'Gendered Insults',
        'explicit_content': 'Explicit Content',
        'highly_negative_sentiment': 'Highly Negative',
        'negative_sentiment': 'Negative Sentiment'
    };
    return factorMap[factor] || factor.replace(/_/g, ' ');
}

// Generate appropriate risk message
function getRiskMessage(result) {
    if (result.risk === 'high') {
        if (result.threat_categories?.grooming) { // Prioritize Grooming
            return '🚨 Critical Risk: Grooming behavior and social engineering tactics detected. Do not engage.';
        } else if (result.threat_categories?.severe_threat) {
            return 'Severe violent threats detected. This content requires immediate attention.';
        } else if (result.threat_categories?.violent_threat) {
            return 'Violent threats and dangerous content detected.';
        } else if (result.threat_categories?.stalking) {
            return 'Stalking behavior and location-based threats detected.';
        } else if (result.threat_categories?.gendered_harassment || result.threat_categories?.sexual_harassment) {
            return 'Severe harassment and inappropriate content detected.';
        } else {
            return 'Multiple high-risk factors detected that require attention.';
        }
    } else if (result.risk === 'medium') {
        return 'This message shows concerning patterns. Proceed with caution.';
    } else if (result.risk === 'low') {
        return 'This message appears to be safe with no significant concerns detected.';
    } else {
        return result.error || 'Unable to analyze the message.';
    }
}

// Error Handler
function showError(containerId, errorMessage) {
    const resultContainer = document.getElementById(containerId);
    const alertElement = document.getElementById(containerId === 'urlResult' ? 'urlAlert' : 'textAlert');
    const titleElement = document.getElementById(containerId === 'urlResult' ? 'urlResultTitle' : 'textResultTitle');
    const messageElement = document.getElementById(containerId === 'urlResult' ? 'urlResultMessage' : 'textResultMessage');

    if (!resultContainer || !alertElement || !titleElement || !messageElement) {
        console.error('Error display elements not found');
        return;
    }

    // Reset and set error styling
    alertElement.className = 'alert warning-result';
    titleElement.textContent = '🔌 Connection Error';
    messageElement.textContent = errorMessage;

    // Clear details
    if (containerId === 'urlResult') {
        const detailsElement = document.getElementById('urlResultDetails');
        if (detailsElement) detailsElement.textContent = '';
    } else {
        const scoreElement = document.getElementById('textScore');
        const flagsElement = document.getElementById('textFlags');
        if (scoreElement) scoreElement.textContent = '';
        if (flagsElement) flagsElement.innerHTML = '';
    }

    // Remove help button
    SalamaCheckUI.removeHelpButton(containerId);

    // Show result container
    resultContainer.classList.remove('d-none');
}

// Function to check threat intelligence status (Used for logging/testing, no user-facing alerts)
function checkThreatIntelStatus() {
    fetch('/api/threat-intel/status')
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                console.log('Threat Intelligence Status:', data.data);
            }
        })
        .catch(error => {
            console.error('Failed to check threat intelligence status:', error);
        });
}

// Enhanced initialization
document.addEventListener('DOMContentLoaded', function() {
    // Initialize theme manager
    ThemeManager.init();

    // Check threat intelligence status (quietly runs in the background)
    checkThreatIntelStatus();
    
    // Add smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Feature list animation
    const featureItems = document.querySelectorAll('.feature-item');
    featureItems.forEach((item, index) => {
        item.style.animationDelay = `${index * 0.2}s`;
    });
    
    // Enhanced input validation with real-time feedback
    if (linkInput) {
        linkInput.addEventListener('blur', () => {
            const validation = FormValidator.validateUrl(linkInput.value);
            if (!validation.isValid && linkInput.value.trim()) {
                linkInput.classList.add('is-invalid');
            } else {
                linkInput.classList.remove('is-invalid');
            }
        });
        
        linkInput.addEventListener('input', () => {
            linkInput.classList.remove('is-invalid');
        });

        linkInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && scanLinkBtn && !scanLinkBtn.disabled) {
                scanLinkBtn.click();
            }
        });
    }
    
    if (textInput) {
        textInput.addEventListener('blur', () => {
            const validation = FormValidator.validateMessage(textInput.value);
            if (!validation.isValid && textInput.value.trim()) {
                textInput.classList.add('is-invalid');
            } else {
                textInput.classList.remove('is-invalid');
            }
        });
        
        textInput.addEventListener('input', () => {
            textInput.classList.remove('is-invalid');
        });

        textInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && e.ctrlKey && analyzeTextBtn && !analyzeTextBtn.disabled) {
                analyzeTextBtn.click();
            }
        });

        // Add character counter for text input
        textInput.addEventListener('input', function() {
            const charCount = this.value.length;
            let counter = this.parentElement.querySelector('.char-counter');
            
            if (!counter) {
                counter = document.createElement('div');
                counter.className = 'char-counter form-text mt-1';
                this.parentElement.appendChild(counter);
            }
            
            counter.textContent = `${charCount}/5000 characters`;
            
            if (charCount > 4500) {
                counter.classList.add('text-warning');
            } else {
                counter.classList.remove('text-warning');
            }
        });
    }

    // Enhanced error handling
    window.addEventListener('unhandledrejection', (event) => {
        console.error('Unhandled promise rejection:', event.reason);
        SalamaCheckUI.showFeedback('An unexpected error occurred. Please try again.', 'error');
    });

    console.log('SalamaCheck initialized successfully');
});