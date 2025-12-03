#!/usr/bin/env python3
"""Minimal Code Scanner - Essential functionality only"""
from fastapi import FastAPI, HTTPException, File, UploadFile, Form
from fastapi.responses import FileResponse
import json, os, re, subprocess, tempfile, shutil, uuid, threading
from datetime import datetime

app = FastAPI()
jobs = {}

def scan_code(code_dir):
    """Minimal code scanning"""
    issues = []
    
    # Security patterns
    patterns = [
        (r'password\s*=\s*["\'][^"\']{6,}["\']', 'Hardcoded password', 'HIGH'),
        (r'api_key\s*=\s*["\'][A-Za-z0-9_-]{20,}["\']', 'Hardcoded API key', 'HIGH'),
        (r'eval\s*\(', 'Code injection risk', 'CRITICAL'),
        (r'SELECT.*\+.*FROM', 'SQL injection risk', 'HIGH')
    ]
    
    for root, _, files in os.walk(code_dir):
        for file in files:
            if file.endswith(('.py', '.js', '.java')):
                try:
                    with open(os.path.join(root, file), 'r', errors='ignore') as f:
                        content = f.read()
                    
                    for i, line in enumerate(content.split('\n'), 1):
                        for pattern, msg, severity in patterns:
                            if re.search(pattern, line, re.IGNORECASE):
                                issues.append({
                                    'file': file,
                                    'line': i,
                                    'issue': msg,
                                    'severity': severity,
                                    'type': 'security'
                                })
                except:
                    pass
    
    return issues

def validate_test_report(repo_url, test_data):
    """Minimal validation"""
    if not test_data:
        return "Unit test report required"
    
    repo_name = repo_url.split('/')[-1].replace('.git', '').lower()
    test_str = json.dumps(test_data).lower()
    
    if repo_name not in test_str:
        return f"Repository '{repo_name}' not found in test data"
    
    return None

def run_scan(job_id, repo_url):
    """Background scan task"""
    try:
        jobs[job_id]['status'] = 'running'
        
        # Clone repo
        temp_dir = tempfile.mkdtemp()
        subprocess.run(['git', 'clone', '--depth=1', repo_url, temp_dir], 
                      capture_output=True, check=True)
        
        # Scan code
        issues = scan_code(temp_dir)
        
        # Update job
        jobs[job_id].update({
            'status': 'completed',
            'issues': issues,
            'total_issues': len(issues),
            'completed_at': datetime.now().isoformat()
        })
        
        shutil.rmtree(temp_dir)
        
    except Exception as e:
        jobs[job_id].update({
            'status': 'failed',
            'error': str(e)
        })

@app.post('/api/scan')
def start_scan(repo_url: str = Form(...), unit_test_report: UploadFile = File(...)):
    """Start code scan"""
    job_id = str(uuid.uuid4())
    
    # Validate inputs
    if len(repo_url) < 10:
        raise HTTPException(400, "Invalid repository URL")
    
    if not unit_test_report.filename.endswith('.json'):
        raise HTTPException(400, "Unit test report must be JSON")
    
    # Parse test report
    try:
        content = unit_test_report.file.read()
        test_data = json.loads(content.decode('utf-8'))
        
        error = validate_test_report(repo_url, test_data)
        if error:
            raise HTTPException(400, error)
            
    except json.JSONDecodeError:
        raise HTTPException(400, "Invalid JSON format")
    
    # Create job
    jobs[job_id] = {
        'job_id': job_id,
        'repo_url': repo_url,
        'status': 'queued',
        'created_at': datetime.now().isoformat()
    }
    
    # Start scan
    threading.Thread(target=run_scan, args=(job_id, repo_url), daemon=True).start()
    
    return {'job_id': job_id, 'status': 'queued'}

@app.get('/api/scan/{job_id}')
def get_scan_status(job_id: str):
    """Get scan status"""
    if job_id not in jobs:
        raise HTTPException(404, 'Job not found')
    return jobs[job_id]

@app.get('/api/scan/{job_id}/report')
def get_scan_report(job_id: str):
    """Get scan report"""
    if job_id not in jobs:
        raise HTTPException(404, 'Job not found')
    
    job = jobs[job_id]
    if job['status'] != 'completed':
        raise HTTPException(400, 'Scan not completed')
    
    return job

@app.get('/api/health')
def health_check():
    """Health check"""
    return {'status': 'healthy', 'active_jobs': len(jobs)}

@app.get('/')
def serve_frontend():
    """Serve frontend"""
    return FileResponse('index.html')

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=8000)