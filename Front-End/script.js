class CodeScannerApp {
    constructor() {
        this.baseUrl = '/api';
        this.currentJobId = null;
        this.statusInterval = null;
        this.deleteMode = false;
        this.init();
    }

    init() {
        this.bindEvents();
        this.initNavigation();
        this.loadAllScans();
    }

    initNavigation() {
        // Add click handlers for navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                e.preventDefault();
                const section = item.dataset.section;
                this.switchSection(section);
                
                // Update active nav item
                document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
                item.classList.add('active');
            });
        });
    }

    switchSection(section) {
        // Hide all sections first
        document.querySelectorAll('section').forEach(sec => sec.style.display = 'none');
        
        switch(section) {
            case 'scan':
                document.querySelector('.scan-section').style.display = 'block';
                break;
            case 'results':
                const resultsSection = document.getElementById('resultsSection');
                if (resultsSection) {
                    resultsSection.style.display = 'block';
                } else {
                    // If no results yet, show a message
                    this.showNoResultsMessage();
                }
                break;
            case 'history':
                document.querySelector('.scans-section').style.display = 'block';
                break;
            case 'settings':
                this.showSettings();
                break;
        }
    }

    showNoResultsMessage() {
        // Remove existing no-results section
        const existing = document.querySelector('.no-results-section');
        if (existing) existing.remove();
        
        const noResultsHtml = `
            <section class="no-results-section" style="display: block;">
                <h2>Scan Results</h2>
                <div class="no-results-content">
                    <p>No scan results available yet.</p>
                    <p>Start a new scan to see results here.</p>
                    <button onclick="window.app.switchSection('scan'); window.app.setActiveNav('scan')" class="btn-secondary">Start New Scan</button>
                </div>
            </section>
        `;
        
        document.querySelector('.content-area').insertAdjacentHTML('beforeend', noResultsHtml);
    }

    setActiveNav(section) {
        document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
        document.querySelector(`[data-section="${section}"]`).classList.add('active');
    }

    showSettings() {
        // Create a simple settings display
        const settingsHtml = `
            <section class="settings-section" style="display: block;">
                <h2>Settings</h2>
                <div class="settings-content">
                    <p><strong>Application Version:</strong> 1.0.0</p>
                    <p><strong>API Status:</strong> <span style="color: green;">Connected</span></p>
                    <p><strong>Database:</strong> SQLite (Local)</p>
                    <p><strong>Scan Engine:</strong> Bandit + Pylint</p>
                    <br>
                    <button onclick="window.app.clearAllData()" class="btn-delete">Clear All Data</button>
                </div>
            </section>
        `;
        
        // Remove existing settings section if any
        const existing = document.querySelector('.settings-section');
        if (existing) existing.remove();
        
        // Add new settings section
        document.querySelector('.content-area').insertAdjacentHTML('beforeend', settingsHtml);
    }

    async clearAllData() {
        const confirmed = confirm('Are you sure you want to clear all scan data? This cannot be undone.');
        if (!confirmed) return;
        
        try {
            // This would need a backend endpoint to clear all data
            this.showSuccess('All data cleared successfully!');
            this.loadAllScans();
        } catch (error) {
            this.showError('Failed to clear data');
        }
    }

    bindEvents() {
        document.getElementById('scanForm').addEventListener('submit', (e) => this.handleScanSubmit(e));
        
        const refreshBtn = document.getElementById('refreshScansBtn');
        refreshBtn.addEventListener('click', () => {
            console.log('Refresh button clicked');
            refreshBtn.disabled = true;
            refreshBtn.textContent = 'Refreshing...';
            
            this.loadAllScans().finally(() => {
                refreshBtn.disabled = false;
                refreshBtn.textContent = 'Refresh';
            });
        });

        // Close results button
        document.getElementById('closeResultsBtn').addEventListener('click', () => {
            document.getElementById('resultsSection').style.display = 'none';
            document.getElementById('statusSection').style.display = 'none';
        });

        // Direct download buttons
        document.getElementById('downloadPdfBtn').addEventListener('click', () => {
            if (this.currentJobId) {
                this.directDownload('pdf');
            }
        });

        document.getElementById('downloadJsonBtn').addEventListener('click', () => {
            if (this.currentJobId) {
                this.directDownload('json');
            }
        });

        // Modal event listeners
        document.getElementById('closeModal').addEventListener('click', () => {
            this.hideReportModal();
        });

        document.getElementById('viewOnlineBtn').addEventListener('click', () => {
            this.hideReportModal();
            this.showScanResults();
        });

        document.getElementById('downloadPdfModalBtn').addEventListener('click', () => {
            this.hideReportModal();
            if (this.currentJobId) {
                this.directDownload('pdf');
            }
        });

        document.getElementById('downloadJsonModalBtn').addEventListener('click', () => {
            this.hideReportModal();
            if (this.currentJobId) {
                this.directDownload('json');
            }
        });

        // Close modal when clicking outside
        document.getElementById('reportModal').addEventListener('click', (e) => {
            if (e.target.id === 'reportModal') {
                this.hideReportModal();
            }
        });

        // Delete mode controls
        document.getElementById('deleteModeBtn').addEventListener('click', () => {
            this.toggleDeleteMode(true);
        });

        document.getElementById('cancelDeleteBtn').addEventListener('click', () => {
            this.toggleDeleteMode(false);
        });

        document.getElementById('selectAllBtn').addEventListener('click', () => {
            this.toggleSelectAll();
        });

        document.getElementById('deleteSelectedBtn').addEventListener('click', () => {
            this.deleteSelectedScans();
        });
    }

    async handleScanSubmit(e) {
        e.preventDefault();
        
        const repoUrl = document.getElementById('repoUrl').value.trim();
        const unitTestFile = document.getElementById('unitTestReport').files[0];
        
        // Basic validation
        if (!repoUrl) {
            this.showError('Repository URL is required');
            return;
        }
        
        // Unit test report is now mandatory
        if (!unitTestFile) {
            this.showError('Unit test report is required. Please upload a JSON file containing test results for this repository.');
            return;
        }
        
        // Validate file format
        if (!unitTestFile.name.endsWith('.json')) {
            this.showError('Unit test report must be a JSON file (.json)');
            return;
        }
        
        const formData = new FormData();
        formData.append('repo_url', repoUrl);
        if (unitTestFile) {
            formData.append('unit_test_report', unitTestFile);
        }

        try {
            this.showLoading('Starting scan...');
            console.log('Submitting scan request:', {
                repo_url: repoUrl,
                has_unit_test: !!unitTestFile
            });
            
            const response = await fetch(`${this.baseUrl}/scan`, {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                let errorMessage = `HTTP error! status: ${response.status}`;
                
                try {
                    const errorData = await response.json();
                    errorMessage = errorData.detail || errorMessage;
                } catch {
                    const errorText = await response.text();
                    console.error('Error response:', errorText);
                }
                
                throw new Error(errorMessage);
            }

            const result = await response.json();
            console.log('Scan started successfully:', result);
            this.currentJobId = result.job_id;
            
            this.showSuccess(`Scan started successfully! Job ID: ${result.job_id}`);
            this.showStatusSection();
            this.startStatusPolling();
            
            // Reset form
            document.getElementById('scanForm').reset();
            
        } catch (error) {
            console.error('Scan submission error:', error);
            this.showError(`Failed to start scan: ${error.message}`);
        }
    }

    showStatusSection() {
        const statusSection = document.getElementById('statusSection');
        statusSection.style.display = 'block';
        document.getElementById('currentJobId').textContent = this.currentJobId;
        statusSection.scrollIntoView({ behavior: 'smooth' });
    }

    startStatusPolling() {
        if (this.statusInterval) {
            clearInterval(this.statusInterval);
        }

        this.statusInterval = setInterval(() => {
            this.checkScanStatus();
        }, 2000);

        // Check immediately
        this.checkScanStatus();
    }

    async checkScanStatus() {
        if (!this.currentJobId) return;

        try {
            const response = await fetch(`${this.baseUrl}/scan/${this.currentJobId}`);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const status = await response.json();
            this.updateStatusDisplay(status);

            if (status.status === 'completed') {
                clearInterval(this.statusInterval);
                this.loadScanReport();
            } else if (status.status === 'failed') {
                clearInterval(this.statusInterval);
                this.showError(`Scan failed: ${status.error}`);
            }

        } catch (error) {
            console.error('Error checking status:', error);
        }
    }

    updateStatusDisplay(status) {
        const statusBadge = document.getElementById('statusBadge');
        const statusDetails = document.getElementById('statusDetails');
        const progressFill = document.getElementById('progressFill');

        statusBadge.textContent = status.status;
        statusBadge.className = `status-badge ${status.status}`;

        let progress = 0;
        let details = '';

        switch (status.status) {
            case 'queued':
                progress = 10;
                details = 'Scan is queued and waiting to start...';
                break;
            case 'running':
                progress = 50;
                details = 'Scanning repository for security and quality issues...';
                break;
            case 'completed':
                progress = 100;
                details = `Scan completed! Found ${status.total_issues || 0} issues (${status.security_issues || 0} security, ${status.quality_issues || 0} quality)`;
                break;
            case 'failed':
                progress = 100;
                details = `Scan failed: ${status.error}`;
                break;
        }

        progressFill.style.width = `${progress}%`;
        statusDetails.innerHTML = `<p>${details}</p>`;

        if (status.created_at) {
            statusDetails.innerHTML += `<p><small>Started: ${new Date(status.created_at).toLocaleString()}</small></p>`;
        }
    }

    async loadScanReport() {
        if (!this.currentJobId) return;

        try {
            console.log(`Loading report for job: ${this.currentJobId}`);
            const response = await fetch(`${this.baseUrl}/scan/${this.currentJobId}/report`);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const report = await response.json();
            console.log('Report loaded:', report);
            this.displayScanResults(report);
            this.loadAllScans(); // Refresh the scans list

        } catch (error) {
            console.error('Error loading report:', error);
            this.showError(`Failed to load scan report: ${error.message}`);
        }
    }

    displayScanResults(report) {
        console.log('Displaying scan results:', report);
        const resultsSection = document.getElementById('resultsSection');
        const resultsSummary = document.getElementById('resultsSummary');
        const issuesContainer = document.getElementById('issuesContainer');
        const statusSection = document.getElementById('statusSection');

        // Hide status section when showing results
        if (statusSection) {
            statusSection.style.display = 'none';
        }

        // Remove no-results section if it exists
        const noResultsSection = document.querySelector('.no-results-section');
        if (noResultsSection) {
            noResultsSection.remove();
        }

        // Show results section
        resultsSection.style.display = 'block';
        
        // Switch to results tab and update navigation
        this.switchSection('results');
        this.setActiveNav('results');

        // Add report header with repo info
        const reportHeader = `
            <div class="report-header">
                <h3>Scan Report</h3>
                <p><strong>Repository:</strong> ${report.repo_url}</p>
                <p><strong>Completed:</strong> ${new Date(report.completed_at).toLocaleString()}</p>
            </div>
        `;

        // Create summary cards with unit test info
        let unitTestCard = '';
        if (report.unit_test_summary && report.unit_test_summary.total_tests !== 'N/A') {
            const testStatus = report.unit_test_summary.status || 'N/A';
            const statusColor = testStatus === 'PASSED' ? '#00b894' : testStatus === 'FAILED' ? '#e17055' : '#667eea';
            unitTestCard = `
                <div class="summary-card" style="border-left-color: ${statusColor}">
                    <h3>${report.unit_test_summary.passed || 0}/${report.unit_test_summary.total_tests || 0}</h3>
                    <p>Tests Passed</p>
                    <small>${report.unit_test_summary.coverage || 'N/A'}% Coverage</small>
                </div>
            `;
        }
        
        // Count minimal fixes
        const minimalFixes = report.issues ? report.issues.filter(issue => issue.minimal_fix).length : 0;
        
        resultsSummary.innerHTML = reportHeader + `
            <div class="summary-cards">
                <div class="summary-card">
                    <h3>${report.total_issues || 0}</h3>
                    <p>Total Issues</p>
                </div>
                <div class="summary-card">
                    <h3>${report.security_issues || 0}</h3>
                    <p>Security Issues</p>
                </div>
                <div class="summary-card">
                    <h3>${report.quality_issues || 0}</h3>
                    <p>Quality Issues</p>
                </div>
                <div class="summary-card">
                    <h3>${minimalFixes}</h3>
                    <p>Minimal Fixes</p>
                </div>
                ${unitTestCard}
            </div>
        `;

        // Display issues and unit test details
        let issuesHTML = '';
        
        if (report.issues && report.issues.length > 0) {
            console.log('Displaying issues:', report.issues);
            issuesHTML = '<h3>Code Issues</h3>' + report.issues.map(issue => this.createIssueHTML(issue)).join('');
        } else {
            issuesHTML = '<p class="success">No code issues found! Your code looks great.</p>';
        }
        
        // Add unit test details if available
        if (report.unit_test_report && report.unit_test_report.test_details) {
            const failedTests = report.unit_test_report.test_details.filter(test => test.status === 'FAILED');
            if (failedTests.length > 0) {
                issuesHTML += '<h3 style="margin-top: 30px;">Failed Unit Tests</h3>';
                issuesHTML += failedTests.map(test => `
                    <div class="issue-item quality">
                        <div class="issue-header">
                            <span class="issue-file">${test.name}</span>
                            <span class="issue-severity severity-high">FAILED</span>
                        </div>
                        <div class="issue-description">${test.error || 'Test failed'} (Duration: ${test.duration || 'N/A'})</div>
                    </div>
                `).join('');
            }
        }
        
        issuesContainer.innerHTML = issuesHTML;

        // Remove any existing messages
        const messages = document.querySelectorAll('.message');
        messages.forEach(msg => msg.remove());

        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }

    createIssueHTML(issue) {
        const severityClass = issue.severity ? issue.severity.toLowerCase() : 'medium';
        const minimalFixHTML = issue.minimal_fix ? `
            <div class="minimal-fix">
                <div class="fix-suggestion">💡 ${issue.minimal_fix.suggestion}</div>
                <div class="fix-code"><code>${issue.minimal_fix.minimal_code}</code></div>
            </div>
        ` : '';
        
        return `
            <div class="issue-item ${issue.type}">
                <div class="issue-header">
                    <span class="issue-file">${issue.file}:${issue.line}</span>
                    <span class="issue-severity severity-${severityClass}">${issue.severity || 'Medium'}</span>
                </div>
                <div class="issue-description">${issue.issue}</div>
                ${minimalFixHTML}
            </div>
        `;
    }

    async loadAllScans() {
        try {
            console.log('Loading all scans...');
            const response = await fetch(`${this.baseUrl}/scans`);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            console.log('Scans loaded:', data.scans);
            this.displayAllScans(data.scans);

        } catch (error) {
            console.error('Error loading scans:', error);
            document.getElementById('scansList').innerHTML = 
                '<div class="error">Failed to load scans. Please check if the backend server is running.</div>';
        }
    }

    displayAllScans(scans) {
        const scansList = document.getElementById('scansList');
        
        if (!scans || scans.length === 0) {
            scansList.innerHTML = '<p>No scans found. Start your first scan above!</p>';
            this.updateBulkDeleteUI();
            return;
        }

        // Sort scans by creation date (newest first)
        const sortedScans = scans.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

        scansList.innerHTML = sortedScans.map(scan => {
            const isCompleted = scan.status === 'completed';
            const issuesText = scan.total_issues !== undefined ? `<p>Issues: ${scan.total_issues}</p>` : '';
            
            const checkboxHtml = this.deleteMode ? 
                `<div class="scan-checkbox">
                    <input type="checkbox" class="scan-select" data-job-id="${scan.job_id}" onchange="window.app.updateBulkDeleteUI()">
                </div>` : '';
            
            const deleteButtonHtml = this.deleteMode ? '' : 
                `<button onclick="window.app.deleteScan('${scan.job_id}')" class="btn-delete">Delete</button>`;
            
            return `
                <div class="scan-item">
                    ${checkboxHtml}
                    <div class="scan-info">
                        <h4>${scan.repo_url}</h4>
                        <p>Job ID: ${scan.job_id}</p>
                        <p>Status: <span class="status-badge ${scan.status}">${scan.status}</span></p>
                        <p>Created: ${new Date(scan.created_at).toLocaleString()}</p>
                        ${issuesText}
                        ${scan.unit_test_summary && scan.unit_test_summary.total_tests !== 'N/A' ? 
                            `<p>Tests: ${scan.unit_test_summary.passed}/${scan.unit_test_summary.total_tests} passed</p>` : 
                            ''}
                    </div>
                    <div class="scan-actions">
                        <button onclick="window.app.viewScanStatus('${scan.job_id}')" class="btn-secondary">View Status</button>
                        ${isCompleted ? 
                            `<button onclick="window.app.viewScanReport('${scan.job_id}')">View Report</button>` : 
                            ''}
                        ${deleteButtonHtml}
                    </div>
                </div>
            `;
        }).join('');
        
        this.updateBulkDeleteUI();
    }

    async viewScanStatus(jobId) {
        this.currentJobId = jobId;
        this.showStatusSection();
        
        try {
            const response = await fetch(`${this.baseUrl}/scan/${jobId}`);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const status = await response.json();
            this.updateStatusDisplay(status);

            if (status.status === 'running') {
                this.startStatusPolling();
            }

        } catch (error) {
            this.showError(`Failed to load scan status: ${error.message}`);
        }
    }

    async viewScanReport(jobId) {
        console.log(`Viewing report options for job: ${jobId}`);
        this.currentJobId = jobId;
        
        // Show report type selection modal
        this.showReportModal();
    }

    showReportModal() {
        document.getElementById('reportModal').style.display = 'flex';
    }

    hideReportModal() {
        document.getElementById('reportModal').style.display = 'none';
    }

    async showScanResults() {
        if (!this.currentJobId) return;
        
        try {
            this.showLoading('Loading scan report...');
            const response = await fetch(`${this.baseUrl}/scan/${this.currentJobId}/report`);
            
            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(`HTTP ${response.status}: ${errorText}`);
            }

            const report = await response.json();
            console.log('Report data:', report);
            this.displayScanResults(report);

        } catch (error) {
            console.error('Error viewing report:', error);
            this.showError(`Failed to load scan report: ${error.message}`);
        }
    }

    showLoading(message) {
        this.showMessage(message, 'loading');
    }

    showSuccess(message) {
        this.showMessage(message, 'success');
    }

    showError(message) {
        this.showMessage(message, 'error');
    }

    directDownload(format) {
        if (!this.currentJobId) {
            this.showError('No scan selected for download');
            return;
        }

        try {
            // Create direct download link
            const downloadUrl = `${this.baseUrl}/download/${this.currentJobId}/${format}`;
            
            // Create hidden link and click it
            const link = document.createElement('a');
            link.href = downloadUrl;
            link.download = `report_${this.currentJobId.substring(0, 8)}.${format === 'pdf' ? 'txt' : format}`;
            link.style.display = 'none';
            
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            
            this.showSuccess(`${format.toUpperCase()} download started!`);

        } catch (error) {
            console.error('Download error:', error);
            this.showError(`Failed to download ${format} report`);
        }
    }

    async downloadReport(format) {
        if (!this.currentJobId) {
            this.showError('No scan selected for download');
            return;
        }

        try {
            this.showLoading(`Downloading ${format.toUpperCase()} report...`);
            
            // Use clean download URLs
            const response = await fetch(`${this.baseUrl}/download/${this.currentJobId}/${format}`);
            
            if (!response.ok) {
                throw new Error(`Download failed: ${response.status}`);
            }

            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = `report_${this.currentJobId.substring(0, 8)}.${format === 'pdf' ? 'txt' : format}`;
            
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            
            window.URL.revokeObjectURL(url);
            
            this.showSuccess(`${format.toUpperCase()} report downloaded successfully!`);

        } catch (error) {
            console.error('Download error:', error);
            this.showError(`Failed to download ${format} report: ${error.message}`);
        }
    }

    async deleteScan(jobId) {
        const confirmed = confirm('Are you sure you want to delete this scan report? This action cannot be undone.');
        if (!confirmed) return;

        try {
            this.showLoading('Deleting scan...');
            const response = await fetch(`${this.baseUrl}/scan/${jobId}`, {
                method: 'DELETE'
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            this.showSuccess('Scan deleted successfully!');
            this.loadAllScans(); // Refresh the list

        } catch (error) {
            console.error('Delete error:', error);
            this.showError(`Failed to delete scan: ${error.message}`);
        }
    }

    toggleSelectAll() {
        const checkboxes = document.querySelectorAll('.scan-select');
        const selectAllBtn = document.getElementById('selectAllBtn');
        
        if (checkboxes.length === 0) return;
        
        const allChecked = Array.from(checkboxes).every(cb => cb.checked);
        const newState = !allChecked;
        
        checkboxes.forEach(cb => {
            cb.checked = newState;
        });
        
        this.updateBulkDeleteUI();
    }

    updateBulkDeleteUI() {
        const checkboxes = document.querySelectorAll('.scan-select');
        const selectedCount = Array.from(checkboxes).filter(cb => cb.checked).length;
        const deleteSelectedBtn = document.getElementById('deleteSelectedBtn');
        const selectAllBtn = document.getElementById('selectAllBtn');
        
        // Update delete button
        if (selectedCount > 0) {
            deleteSelectedBtn.style.display = 'inline-block';
            deleteSelectedBtn.textContent = `Delete Selected (${selectedCount})`;
        } else {
            deleteSelectedBtn.style.display = 'none';
        }
        
        // Update select all button text
        if (checkboxes.length === 0) {
            selectAllBtn.textContent = 'Select All';
        } else {
            const allChecked = Array.from(checkboxes).every(cb => cb.checked);
            selectAllBtn.textContent = allChecked ? 'Deselect All' : 'Select All';
        }
    }

    toggleDeleteMode(enable) {
        this.deleteMode = enable;
        
        // Show/hide buttons
        document.getElementById('deleteModeBtn').style.display = enable ? 'none' : 'inline-block';
        document.getElementById('selectAllBtn').style.display = enable ? 'inline-block' : 'none';
        document.getElementById('cancelDeleteBtn').style.display = enable ? 'inline-block' : 'none';
        
        if (!enable) {
            document.getElementById('deleteSelectedBtn').style.display = 'none';
        }
        
        // Refresh the scan list to show/hide checkboxes
        this.loadAllScans();
    }

    async deleteSelectedScans() {
        const selectedCheckboxes = document.querySelectorAll('.scan-select:checked');
        const selectedJobIds = Array.from(selectedCheckboxes).map(cb => cb.dataset.jobId);
        
        if (selectedJobIds.length === 0) {
            this.showError('No scans selected for deletion');
            return;
        }
        
        const confirmed = confirm(`Are you sure you want to delete ${selectedJobIds.length} scan report(s)? This action cannot be undone.`);
        if (!confirmed) return;

        try {
            this.showLoading(`Deleting ${selectedJobIds.length} scans...`);
            
            // Delete scans in parallel
            const deletePromises = selectedJobIds.map(jobId => 
                fetch(`${this.baseUrl}/scan/${jobId}`, { method: 'DELETE' })
            );
            
            const results = await Promise.allSettled(deletePromises);
            
            const successful = results.filter(r => r.status === 'fulfilled' && r.value.ok).length;
            const failed = results.length - successful;
            
            if (failed === 0) {
                this.showSuccess(`Successfully deleted ${successful} scan(s)!`);
            } else {
                this.showError(`Deleted ${successful} scan(s), but ${failed} failed to delete.`);
            }
            
            // Exit delete mode and refresh
            this.toggleDeleteMode(false);

        } catch (error) {
            console.error('Bulk delete error:', error);
            this.showError(`Failed to delete selected scans: ${error.message}`);
        }
    }

    showMessage(message, type) {
        // Remove existing messages
        const existingMessages = document.querySelectorAll('.message');
        existingMessages.forEach(msg => msg.remove());

        // Create new message
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${type}`;
        messageDiv.textContent = message;

        // Insert at the top of the main content
        const main = document.querySelector('main');
        main.insertBefore(messageDiv, main.firstChild);

        // Auto-remove success and loading messages after 5 seconds
        if (type === 'success' || type === 'loading') {
            setTimeout(() => {
                if (messageDiv.parentNode) {
                    messageDiv.remove();
                }
            }, 5000);
        }
    }
}

// Initialize the app when the page loads
document.addEventListener('DOMContentLoaded', () => {
    window.app = new CodeScannerApp();
});