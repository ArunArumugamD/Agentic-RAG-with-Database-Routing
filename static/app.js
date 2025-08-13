// ThreatRAG - JavaScript Frontend Application

class ThreatRAG {
    constructor() {
        this.apiBase = '/api/v1';
        this.isConnected = false;
        this.currentQuery = '';
        
        this.initializeElements();
        this.bindEvents();
        this.checkSystemStatus();
    }

    initializeElements() {
        // Query elements
        this.queryInput = document.getElementById('queryInput');
        this.searchBtn = document.getElementById('searchBtn');
        this.searchMode = document.getElementById('searchMode');
        
        // Example buttons
        this.exampleBtns = document.querySelectorAll('.example-btn');
        
        // Section elements
        this.loadingSection = document.getElementById('loadingSection');
        this.resultsSection = document.getElementById('resultsSection');
        this.loadingMessage = document.getElementById('loadingMessage');
        
        // Results elements
        this.resultsTitle = document.getElementById('resultsTitle');
        this.resultCount = document.getElementById('resultCount');
        this.responseTime = document.getElementById('responseTime');
        this.sourcesUsed = document.getElementById('sourcesUsed');
        this.routingInfo = document.getElementById('routingInfo');
        this.routingText = document.getElementById('routingText');
        this.relevanceInfo = document.getElementById('relevanceInfo');
        this.relevanceText = document.getElementById('relevanceText');
        this.limitationsInfo = document.getElementById('limitationsInfo');
        this.limitationsList = document.getElementById('limitationsList');
        this.selfCorrectionInfo = document.getElementById('selfCorrectionInfo');
        this.resultsData = document.getElementById('resultsData');
        this.resultsList = document.getElementById('resultsList');
        this.noResults = document.getElementById('noResults');
    }

    bindEvents() {
        // Search button click
        this.searchBtn.addEventListener('click', () => this.executeQuery());
        
        // Enter key in query input
        this.queryInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.executeQuery();
            }
        });
        
        // Query input changes
        this.queryInput.addEventListener('input', () => {
            this.updateSearchButton();
        });
        
        // Example button clicks
        this.exampleBtns.forEach(btn => {
            btn.addEventListener('click', () => {
                const query = btn.getAttribute('data-query');
                this.queryInput.value = query;
                this.executeQuery();
            });
        });
    }

    updateSearchButton() {
        const hasQuery = this.queryInput.value.trim().length > 0;
        this.searchBtn.disabled = !hasQuery;
    }

    async checkSystemStatus() {
        try {
            const response = await fetch('/health');
            if (response.ok) {
                this.isConnected = true;
            } else {
                this.isConnected = false;
            }
        } catch (error) {
            console.error('System check failed:', error);
            this.isConnected = false;
        }
        this.updateSearchButton();
    }


    async executeQuery() {
        const query = this.queryInput.value.trim();
        if (!query) return;

        this.currentQuery = query;
        this.showLoading();
        
        try {
            const response = await fetch(`${this.apiBase}/query`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    query: query,
                    mode: this.searchMode.value
                })
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const result = await response.json();
            this.displayResults(result);
            
        } catch (error) {
            console.error('Query execution failed:', error);
            this.showError(`Query failed: ${error.message}`);
        }
    }

    showLoading() {
        this.loadingMessage.textContent = `Analyzing: ${this.currentQuery}`;
        this.loadingSection.style.display = 'block';
        this.resultsSection.style.display = 'none';
        this.loadingSection.classList.add('fade-in');
    }

    showError(message) {
        this.loadingSection.style.display = 'none';
        this.resultsSection.style.display = 'block';
        this.resultsSection.classList.add('fade-in');
        
        // Clear previous results
        this.clearResults();
        
        // Show error message
        this.noResults.style.display = 'block';
        this.noResults.innerHTML = `
            <div class="no-results-icon">
                <i class="fas fa-exclamation-triangle"></i>
            </div>
            <h3>Query Failed</h3>
            <div class="suggestions">
                <p>${message}</p>
                <p>Please check:</p>
                <ul>
                    <li>Your internet connection</li>
                    <li>That the ThreatRAG API is running (python main.py)</li>
                    <li>That all database services are available</li>
                </ul>
            </div>
        `;
    }

    displayResults(result) {
        this.loadingSection.style.display = 'none';
        this.resultsSection.style.display = 'block';
        this.resultsSection.classList.add('fade-in');
        
        // Clear previous results
        this.clearResults();
        
        // Update title
        this.resultsTitle.textContent = `Results for: "${this.currentQuery}"`;
        
        // Update metrics
        const metadata = result.metadata || {};
        const relevanceMetrics = result.relevance_metrics || {};
        
        if (this.resultCount) this.resultCount.textContent = metadata.result_count || 0;
        if (this.responseTime) this.responseTime.textContent = `${metadata.response_time_ms || 0}ms`;
        if (this.sourcesUsed) this.sourcesUsed.textContent = (metadata.sources_used || []).length;
        
        // Show routing info
        if (metadata.sources_used && metadata.sources_used.length > 0 && this.routingInfo && this.routingText) {
            this.routingInfo.style.display = 'block';
            this.routingText.textContent = metadata.sources_used.join(' + ');
        }
        
        // Show relevance analysis
        if (relevanceMetrics.explanation && this.relevanceInfo && this.relevanceText) {
            this.relevanceInfo.style.display = 'block';
            this.relevanceText.textContent = relevanceMetrics.explanation;
        }
        
        // Show limitations
        if (relevanceMetrics.limitations && relevanceMetrics.limitations.length > 0) {
            this.limitationsInfo.style.display = 'block';
            this.limitationsList.innerHTML = relevanceMetrics.limitations
                .map(limitation => `<li>${limitation}</li>`)
                .join('');
        }
        
        // Show self-correction notice
        if (metadata.self_corrected) {
            this.selfCorrectionInfo.style.display = 'block';
        }
        
        // Display results data
        const results = result.results || [];
        if (results.length > 0) {
            this.resultsData.style.display = 'block';
            this.displayResultsList(results);
        } else {
            this.noResults.style.display = 'block';
        }
    }

    displayResultsList(results) {
        this.resultsList.innerHTML = '';
        
        results.slice(0, 10).forEach((item, index) => {
            const resultElement = this.createResultElement(item, index + 1);
            this.resultsList.appendChild(resultElement);
        });
        
        if (results.length > 10) {
            const moreElement = document.createElement('div');
            moreElement.className = 'result-item';
            moreElement.innerHTML = `
                <div class="result-content">
                    <p style="text-align: center; color: #a0a0a0; font-style: italic;">
                        ... and ${results.length - 10} more results
                    </p>
                </div>
            `;
            this.resultsList.appendChild(moreElement);
        }
    }

    createResultElement(item, index) {
        const element = document.createElement('div');
        element.className = 'result-item';
        
        // Determine content preview
        let preview = '';
        let fields = [];
        
        if (typeof item === 'object' && item !== null) {
            // Create a better title preview for CVEs
            if (item.metadata && item.metadata.cve_id) {
                // For CVE items, create a concise title
                const cveId = item.metadata.cve_id;
                const severity = item.metadata.severity || 'UNKNOWN';
                const cvssScore = item.metadata.cvss_score || 'N/A';
                preview = `${cveId} - ${severity} (CVSS: ${cvssScore})`;
            } else if (item.cve_id) {
                // Direct CVE object
                preview = `${item.cve_id} - ${item.severity || 'UNKNOWN'} (CVSS: ${item.cvss_score || 'N/A'})`;
            } else {
                // Fallback for other item types
                preview = item.value || item.description || item.name || 'Data item';
            }
            
            // Format fields based on item type
            if (item.metadata && item.metadata.cve_id) {
                // Handle Qdrant vector search results with metadata
                const meta = item.metadata;
                fields = [
                    { label: 'CVE ID', value: meta.cve_id },
                    { label: 'Content', value: item.content },
                    { label: 'Severity', value: meta.severity },
                    { label: 'CVSS Score', value: meta.cvss_score },
                    { label: 'Has Exploit', value: meta.has_exploit ? 'Yes' : 'No' },
                    { label: 'EPSS Score', value: meta.epss_score },
                    { label: 'Source', value: meta.source },
                    { label: 'Collected At', value: meta.collected_at }
                ].filter(field => field.value !== undefined && field.value !== null);
            } else if (item.cve_id) {
                // Handle direct CVE objects from PostgreSQL
                fields = [
                    { label: 'CVE ID', value: item.cve_id },
                    { label: 'Description', value: item.description },
                    { label: 'Severity', value: item.severity },
                    { label: 'CVSS Score', value: item.cvss_score },
                    { label: 'Published', value: item.published_date }
                ].filter(field => field.value);
            } else if (item.value) {
                fields = [
                    { label: 'Value', value: item.value },
                    { label: 'Type', value: item.type },
                    { label: 'Source', value: item.source },
                    { label: 'Description', value: item.description }
                ].filter(field => field.value);
            } else {
                // Generic object handling
                Object.entries(item).forEach(([key, value]) => {
                    if (value && typeof value !== 'object') {
                        fields.push({ 
                            label: key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()), 
                            value: value 
                        });
                    }
                });
            }
        } else {
            preview = String(item);
        }
        
        // Removed truncation for titles to show full CVE descriptions
        // if (preview.length > 500) {
        //     preview = preview.substring(0, 500) + '...';
        // }
        
        element.innerHTML = `
            <div class="result-header">
                <div class="result-title">Result ${index}: ${preview}</div>
                <div class="result-meta">
                    <span><i class="fas fa-hashtag"></i> Item ${index}</span>
                    ${item.score ? `<span><i class="fas fa-chart-line"></i> Score: ${(item.score * 100).toFixed(1)}%</span>` : ''}
                </div>
            </div>
            <div class="result-content">
                ${fields.length > 0 
                    ? fields.map(field => `
                        <div class="result-field">
                            <strong>${field.label}:</strong> ${this.formatValue(field.value)}
                        </div>
                    `).join('')
                    : `<pre style="white-space: pre-wrap; color: #a0a0a0;">${JSON.stringify(item, null, 2)}</pre>`
                }
            </div>
        `;
        
        return element;
    }

    formatValue(value) {
        if (!value) return 'N/A';
        
        // Format dates
        if (typeof value === 'string' && value.match(/^\d{4}-\d{2}-\d{2}/)) {
            try {
                const date = new Date(value);
                return date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
            } catch (e) {
                return value;
            }
        }
        
        // Limit long values - increased from 1000 to 2000 for better readability
        if (typeof value === 'string' && value.length > 2000) {
            return value.substring(0, 2000) + '...';
        }
        
        return value;
    }

    clearResults() {
        // Hide all result sections
        this.routingInfo.style.display = 'none';
        this.relevanceInfo.style.display = 'none';
        this.limitationsInfo.style.display = 'none';
        this.selfCorrectionInfo.style.display = 'none';
        this.resultsData.style.display = 'none';
        this.noResults.style.display = 'none';
        
        // Clear content
        this.resultsList.innerHTML = '';
        this.limitationsList.innerHTML = '';
    }
}

// Initialize the application when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new ThreatRAG();
});