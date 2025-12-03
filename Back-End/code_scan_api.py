from fastapi import FastAPI, HTTPException, File, UploadFile, Form, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uuid
import threading
from datetime import datetime
from scanner import CodeScanner
from database import ScanDatabase
from intelligent_validator import IntelligentValidator
import os
import json

# Optional environment loading
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except ImportError:
    pass

app = FastAPI(title="Code Scanning API", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database for persistent storage
db = ScanDatabase()

# In-memory storage for active scan jobs
scan_jobs = {}

class UnitTestReport(BaseModel):
    TOTAL_TESTS: int = None
    PASSED: int = None
    FAILED: int = None
    COVERAGE_PERCENT: float = None
    STATUS: str = None
    EXECUTION_TIME: str = None

def validate_unit_test_report(repo_url, unit_test_data):
    """Intelligent AI-powered validation using repository analysis"""
    if not unit_test_data:
        return "Unit test report is required. Please upload a JSON file containing test results for this repository."
    
    try:
        print(f"🤖 INTELLIGENT VALIDATION: Analyzing '{repo_url}'")
        
        # Use AI-powered intelligent validation
        validator = IntelligentValidator()
        is_valid, confidence, reason = validator.validate_repo_and_tests(repo_url, unit_test_data)
        
        print(f"AI Analysis: Valid={is_valid}, Confidence={confidence:.2f}")
        print(f"Reason: {reason}")
        
        # Require high confidence for acceptance
        if is_valid and confidence >= 0.7:
            print(f"✅ INTELLIGENT VALIDATION SUCCESS: {confidence:.1%} confidence")
            return None
        elif is_valid and confidence >= 0.5:
            # Medium confidence - run additional basic checks
            repo_name = repo_url.split('/')[-1].replace('.git', '').lower().strip()
            test_data_str = json.dumps(unit_test_data).lower()
            
            if repo_name in test_data_str:
                print(f"✅ VALIDATION SUCCESS: {confidence:.1%} AI confidence + name match")
                return None
            else:
                return f"VALIDATION FAILED: Medium AI confidence ({confidence:.1%}) but repository name mismatch. {reason}"
        else:
            return f"VALIDATION FAILED: {reason} (AI confidence: {confidence:.1%})"
        
    except Exception as e:
        print(f"Intelligent validation failed, falling back to basic validation: {e}")
        
        # Fallback to basic validation
        repo_name = repo_url.split('/')[-1].replace('.git', '').lower().strip()
        test_data_str = json.dumps(unit_test_data).lower()
        
        if repo_name in test_data_str:
            print("✅ BASIC VALIDATION SUCCESS: Repository name found")
            return None
        else:
            return f"VALIDATION FAILED: Repository '{repo_name}' not found in test data."

def extract_file_paths(test_data):
    """Extract file paths from test data"""
    paths = []
    
    def find_paths(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if 'file' in key.lower() or 'path' in key.lower():
                    if isinstance(value, str) and ('/' in value or '\\' in value):
                        paths.append(value)
                find_paths(value)
        elif isinstance(obj, list):
            for item in obj:
                find_paths(item)
        elif isinstance(obj, str):
            if ('/' in obj or '\\' in obj) and any(ext in obj for ext in ['.py', '.js', '.java']):
                paths.append(obj)
    
    find_paths(test_data)
    return paths

def extract_commit_info(test_data):
    """Extract git commit hash if present"""
    commit_fields = ['commit', 'commit_hash', 'git_hash', 'sha', 'revision']
    
    def find_commit(obj):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if key.lower() in commit_fields and isinstance(value, str) and len(value) >= 7:
                    return value
                result = find_commit(value)
                if result:
                    return result
        elif isinstance(obj, list):
            for item in obj:
                result = find_commit(item)
                if result:
                    return result
        return None
    
    return find_commit(test_data)

def analyze_test_structure(test_data, repo_name):
    """Analyze test file structure"""
    score = 0
    test_str = json.dumps(test_data).lower()
    
    # Test patterns
    patterns = [f'test_{repo_name}', f'{repo_name}_test', f'tests/{repo_name}']
    if any(pattern in test_str for pattern in patterns):
        score += 5
    
    # Framework indicators
    frameworks = ['pytest', 'unittest', 'jest', 'junit']
    if any(fw in test_str for fw in frameworks):
        score += 5
    
    return score

def validate_metadata(test_data):
    """Validate timestamps and metadata"""
    score = 0
    
    # Check for timestamps
    timestamp_fields = ['timestamp', 'date', 'created_at']
    test_str = json.dumps(test_data).lower()
    if any(field in test_str for field in timestamp_fields):
        score += 5
    
    # Check realistic test counts
    if isinstance(test_data, dict):
        total = test_data.get('total_tests') or test_data.get('total')
        if total and isinstance(total, int) and 1 <= total <= 10000:
            score += 5
    
    return score

def analyze_coverage_paths(test_data, repo_name):
    """Analyze coverage paths"""
    test_str = json.dumps(test_data).lower()
    indicators = ['coverage', 'src/', f'{repo_name}/']
    matches = sum(1 for indicator in indicators if indicator in test_str)
    return min(matches * 2, 5)

def run_scan(job_id, repo_url):
    """Background task to run code scanning"""
    scanner = CodeScanner()
    
    try:
        # Update status to running
        scan_jobs[job_id]['status'] = 'running'
        scan_jobs[job_id]['updated_at'] = datetime.now().isoformat()
        print(f"Starting scan for job {job_id} with repo {repo_url}")
        
        # Repository URL already validated in API endpoint
        print(f"Processing repository URL: {repo_url}")
            
        # Clone repository
        print(f"Cloning repository: {repo_url}")
        if not scanner.clone_repo(repo_url):
            scan_jobs[job_id]['status'] = 'failed'
            scan_jobs[job_id]['error'] = 'Failed to clone repository. Please check if the repository exists and is accessible.'
            print(f"Failed to clone repository for job {job_id}")
            return
        print(f"Repository cloned successfully for job {job_id}")
        
        # Run scans
        print(f"Running security scan for job {job_id}")
        security_issues = scanner.scan_security()
        print(f"Security scan complete: {len(security_issues)} issues found")
        
        print(f"Running quality scan for job {job_id}")
        quality_issues = scanner.scan_quality()
        print(f"Quality scan complete: {len(quality_issues)} issues found")
        
        # Combine results
        all_issues = security_issues + quality_issues
        print(f"Total issues found for job {job_id}: {len(all_issues)}")
        
        # Generate minimal project structure suggestions
        minimal_suggestions = scanner.generate_minimal_project_structure()
        
        # Update job with results
        scan_jobs[job_id].update({
            'status': 'completed',
            'issues': all_issues,
            'total_issues': len(all_issues),
            'security_issues': len(security_issues),
            'quality_issues': len(quality_issues),
            'minimal_code_suggestions': {
                'total_fixes': len([i for i in all_issues if i.get('minimal_fix')]),
                'project_structure': minimal_suggestions,
                'general_tips': [
                    'Remove unused imports and functions',
                    'Combine similar functions into one',
                    'Use built-in libraries instead of external ones',
                    'Minimize error handling to essential only',
                    'Remove debug prints and comments',
                    'Keep functions under 10 lines when possible'
                ]
            },
            'unit_test_summary': {
                'total_tests': scan_jobs[job_id].get('unit_test_report', {}).get('total_tests', scan_jobs[job_id].get('unit_test_report', {}).get('total', 'N/A')) if scan_jobs[job_id].get('unit_test_report') else 'N/A',
                'passed': scan_jobs[job_id].get('unit_test_report', {}).get('passed', 'N/A') if scan_jobs[job_id].get('unit_test_report') else 'N/A',
                'failed': scan_jobs[job_id].get('unit_test_report', {}).get('failed', 'N/A') if scan_jobs[job_id].get('unit_test_report') else 'N/A',
                'coverage': scan_jobs[job_id].get('unit_test_report', {}).get('coverage_percent', 'N/A') if scan_jobs[job_id].get('unit_test_report') else 'N/A',
                'status': scan_jobs[job_id].get('unit_test_report', {}).get('status', 'Validated') if scan_jobs[job_id].get('unit_test_report') else 'N/A'
            },
            'validation_status': 'Unit test report validated and matches repository',
            'completed_at': datetime.now().isoformat()
        })
        
        # Save to database
        try:
            db.save_scan(scan_jobs[job_id])
        except Exception as db_error:
            print(f"Database save error for job {job_id}: {db_error}")
        
    except Exception as e:
        print(f"Error in scan job {job_id}: {str(e)}")
        scan_jobs[job_id]['status'] = 'failed'
        scan_jobs[job_id]['error'] = str(e)
        scan_jobs[job_id]['updated_at'] = datetime.now().isoformat()
        
        # Save failed scan to database
        try:
            db.save_scan(scan_jobs[job_id])
        except Exception as db_error:
            print(f"Database save error for failed job {job_id}: {db_error}")
    
    finally:
        scanner.cleanup()

@app.post('/api/scan')
def start_scan(
    repo_url: str = Form(...),
    unit_test_report: UploadFile = File(..., description="Unit test report JSON file (Required)")
):
    """Start a new code scan"""
    job_id = str(uuid.uuid4())
    
    # Validate repository URL
    if not repo_url or not repo_url.strip():
        raise HTTPException(status_code=400, detail="Repository URL is required")
    
    repo_url = repo_url.strip()
    print(f"Processing scan request for: {repo_url}")
    
    # Accept any reasonable URL format
    if len(repo_url) < 10:
        raise HTTPException(status_code=400, detail="Repository URL too short")
    
    # MANDATORY: Unit test report validation
    test_report_data = None
    
    # Check if unit test report is provided
    if not unit_test_report or not unit_test_report.filename:
        raise HTTPException(
            status_code=400, 
            detail="Unit test report is required. Please upload a JSON file containing test results for this repository."
        )
    
    # Validate file format
    if not unit_test_report.filename.endswith('.json'):
        raise HTTPException(
            status_code=400,
            detail="Unit test report must be a JSON file. Please upload a .json file."
        )
    
    try:
        content = unit_test_report.file.read()
        test_report_data = json.loads(content.decode('utf-8'))
        
        # INTELLIGENT AI validation - analyzes actual repository content
        validation_error = validate_unit_test_report(repo_url, test_report_data)
        if validation_error:
            print(f"VALIDATION REJECTED: {validation_error}")
            raise HTTPException(status_code=400, detail=validation_error)
            
    except json.JSONDecodeError as e:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid JSON format in unit test report: {str(e)}. Please check the file format."
        )
    except UnicodeDecodeError as e:
        raise HTTPException(
            status_code=400, 
            detail=f"Cannot read unit test report file: {str(e)}. Please ensure it's a valid text file."
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Error processing unit test report: {str(e)}"
        )
    finally:
        if hasattr(unit_test_report.file, 'close'):
            unit_test_report.file.close()
    
    # Create job entry
    scan_jobs[job_id] = {
        'job_id': job_id,
        'repo_url': repo_url,
        'unit_test_report': test_report_data,
        'status': 'queued',
        'created_at': datetime.now().isoformat(),
        'updated_at': datetime.now().isoformat()
    }
    
    # Save initial job to database
    try:
        db.save_scan(scan_jobs[job_id])
    except Exception as db_error:
        print(f"Database save error for initial job {job_id}: {db_error}")
    
    print(f"Scan job created successfully: {job_id} for {repo_url}")
    
    # Start background scan
    thread = threading.Thread(target=run_scan, args=(job_id, repo_url))
    thread.daemon = True
    thread.start()
    
    response_data = {
        'job_id': job_id,
        'status': 'queued',
        'message': 'Scan started successfully with validated unit test report',
        'unit_test_report_validated': True,
        'repository_url': repo_url
    }
    print(f"Returning response: {response_data}")
    return response_data

@app.get('/api/scan/{job_id}')
def get_scan_status(job_id: str):
    """Get scan status"""
    job_id = job_id.strip()
    
    # Check in-memory first, then database
    job = scan_jobs.get(job_id) or db.get_scan(job_id)
    if not job:
        raise HTTPException(status_code=404, detail='Job not found')
    response = {
        'job_id': job_id,
        'status': job['status'],
        'created_at': job['created_at'],
        'updated_at': job['updated_at']
    }
    
    if job['status'] == 'completed':
        response.update({
            'total_issues': job.get('total_issues', 0),
            'security_issues': job.get('security_issues', 0),
            'quality_issues': job.get('quality_issues', 0),
            'completed_at': job.get('completed_at')
        })
    elif job['status'] == 'failed':
        response['error'] = job.get('error')
    
    return response

@app.get('/api/scan/{job_id}/report')
def get_scan_report(job_id: str):
    """Get detailed scan report"""
    job_id = job_id.strip()
    
    # Check in-memory first, then database
    job = scan_jobs.get(job_id) or db.get_scan(job_id)
    if not job:
        raise HTTPException(status_code=404, detail='Job not found')
    
    if job['status'] != 'completed':
        raise HTTPException(status_code=400, detail='Scan not completed yet')
    
    return {
        'job_id': job_id,
        'repo_url': job['repo_url'],
        'status': job['status'],
        'total_issues': job.get('total_issues', 0),
        'security_issues': job.get('security_issues', 0),
        'quality_issues': job.get('quality_issues', 0),
        'issues': job.get('issues', []),
        'minimal_code_suggestions': job.get('minimal_code_suggestions', {}),
        'unit_test_summary': job.get('unit_test_summary', {}),
        'unit_test_report': job.get('unit_test_report'),
        'completed_at': job.get('completed_at')
    }

@app.get('/api/scans')
def list_scans():
    """List all scans from database"""
    scans = db.get_all_scans()
    return {'scans': scans}

@app.get('/api/health')
def health_check():
    """Health check endpoint"""
    return {
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'active_scans': len([j for j in scan_jobs.values() if j['status'] == 'running'])
    }

# WORKING DOWNLOAD ENDPOINTS
@app.get('/api/download/{job_id}/json')
def download_json(job_id: str):
    """Download JSON report"""
    job = scan_jobs.get(job_id) or db.get_scan(job_id)
    if not job:
        raise HTTPException(status_code=404, detail='Job not found')
    if job['status'] != 'completed':
        raise HTTPException(status_code=400, detail='Scan not completed yet')
    
    report = {
        "job_id": job_id,
        "repo_url": job.get('repo_url', ''),
        "total_issues": job.get('total_issues', 0),
        "security_issues": job.get('security_issues', 0),
        "quality_issues": job.get('quality_issues', 0),
        "issues": job.get('issues', []),
        "minimal_code_suggestions": job.get('minimal_code_suggestions', {}),
        "unit_test_summary": job.get('unit_test_summary', {}),
        "unit_test_report": job.get('unit_test_report'),
        "completed_at": job.get('completed_at', '')
    }
    
    return Response(
        content=json.dumps(report, indent=2),
        media_type='application/json',
        headers={"Content-Disposition": f"attachment; filename=report_{job_id[:8]}.json"}
    )

@app.get('/api/download/{job_id}/pdf')
def download_pdf(job_id: str):
    """Download PDF report (as text)"""
    job = scan_jobs.get(job_id) or db.get_scan(job_id)
    if not job:
        raise HTTPException(status_code=404, detail='Job not found')
    if job['status'] != 'completed':
        raise HTTPException(status_code=400, detail='Scan not completed yet')
    
    # Add unit test summary to report
    unit_test_info = ""
    if job.get('unit_test_report'):
        unit_test_summary = job.get('unit_test_summary', {})
        unit_test_info = f"""
UNIT TEST SUMMARY
-----------------
Total Tests: {unit_test_summary.get('total_tests', 'N/A')}
Passed: {unit_test_summary.get('passed', 'N/A')}
Failed: {unit_test_summary.get('failed', 'N/A')}
Coverage: {unit_test_summary.get('coverage', 'N/A')}%
Status: {unit_test_summary.get('status', 'N/A')}
"""
    
    # Add minimal code suggestions to report
    minimal_suggestions = job.get('minimal_code_suggestions', {})
    minimal_info = ""
    if minimal_suggestions:
        minimal_info = f"""

MINIMAL CODE SUGGESTIONS
------------------------
Total Fixes Available: {minimal_suggestions.get('total_fixes', 0)}

General Tips:
{chr(10).join(f'• {tip}' for tip in minimal_suggestions.get('general_tips', []))}

Project Structure:
• Essential Files: {len(minimal_suggestions.get('project_structure', {}).get('minimal_files', []))}
• Removable Files: {len(minimal_suggestions.get('project_structure', {}).get('removable_files', []))}
"""
    
    content = f"""SCAN REPORT
===========

Repository: {job.get('repo_url', '')}
Job ID: {job_id}
Completed: {job.get('completed_at', '')}

SUMMARY
-------
Total Issues: {job.get('total_issues', 0)}
Security Issues: {job.get('security_issues', 0)}
Quality Issues: {job.get('quality_issues', 0)}{unit_test_info}{minimal_info}

DETAILED ISSUES
---------------
"""
    
    for i, issue in enumerate(job.get('issues', []), 1):
        content += f"{i}. {issue.get('type', '').upper()}: {issue.get('issue', '')}\n"
        content += f"   File: {issue.get('file', '')} (Line {issue.get('line', '')})\n"
        content += f"   Severity: {issue.get('severity', '')}\n"
        
        # Add minimal fix suggestion
        minimal_fix = issue.get('minimal_fix')
        if minimal_fix:
            content += f"   Minimal Fix: {minimal_fix.get('suggestion', '')}\n"
            content += f"   Code: {minimal_fix.get('minimal_code', '').replace(chr(10), ' | ')}\n"
        
        content += "\n"
    
    return Response(
        content=content,
        media_type='text/plain',
        headers={"Content-Disposition": f"attachment; filename=report_{job_id[:8]}.txt"}
    )

# History and management endpoints
@app.get('/api/history/{repo_url:path}')
def get_repo_history(repo_url: str):
    """Get scan history for specific repository"""
    history = db.get_scan_history(repo_url)
    return {'repo_url': repo_url, 'history': history}

@app.delete('/api/scan/{job_id}')
def delete_scan(job_id: str):
    """Delete scan from database"""
    success = db.delete_scan(job_id)
    if not success:
        raise HTTPException(status_code=404, detail='Scan not found')
    
    # Also remove from memory if exists
    if job_id in scan_jobs:
        del scan_jobs[job_id]
    
    return {'message': 'Scan deleted successfully'}

@app.get('/api/stats')
def get_scan_stats():
    """Get scanning statistics"""
    all_scans = db.get_all_scans(1000)
    
    stats = {
        'total_scans': len(all_scans),
        'completed_scans': len([s for s in all_scans if s['status'] == 'completed']),
        'failed_scans': len([s for s in all_scans if s['status'] == 'failed']),
        'total_issues_found': sum(s.get('total_issues', 0) for s in all_scans),
        'avg_issues_per_scan': 0
    }
    
    if stats['completed_scans'] > 0:
        stats['avg_issues_per_scan'] = round(stats['total_issues_found'] / stats['completed_scans'], 2)
    
    return stats

@app.get('/sample_unit_test.json')
def get_sample_unit_test():
    """Serve sample unit test report for testing"""
    return FileResponse('sample_unit_test.json')

@app.post('/api/minimal-suggestions')
def get_minimal_suggestions(request: dict):
    """Generate minimal code suggestions for other agents"""
    code = request.get('code', '')
    language = request.get('language', 'python')
    issue_type = request.get('issue_type', 'general')
    
    scanner = CodeScanner()
    
    # Generate suggestions based on issue type
    if issue_type == 'security':
        suggestion = {
            'type': 'security',
            'suggestion': 'Use environment variables for secrets',
            'minimal_code': 'api_key = os.getenv("API_KEY")',
            'explanation': 'Never hardcode sensitive data'
        }
    elif issue_type == 'performance':
        suggestion = {
            'type': 'performance', 
            'suggestion': 'Use list comprehension',
            'minimal_code': 'result = [x for x in items if condition]',
            'explanation': 'More efficient than loops'
        }
    else:
        suggestion = {
            'type': 'general',
            'suggestion': 'Follow minimal coding principles',
            'minimal_code': '# Write only essential code\n# Remove unnecessary complexity',
            'explanation': 'Keep code simple and focused'
        }
    
    return {'suggestions': [suggestion]}

@app.post('/api/elite-analysis')
def elite_security_analysis(request: dict):
    """Elite security analysis using senior engineer AI"""
    repo_files = request.get('repo_files', '')
    test_report = request.get('test_report', '{}')
    
    validator = IntelligentValidator()
    if not validator.enabled:
        raise HTTPException(status_code=503, detail='Elite AI analysis unavailable')
    
    result = validator.analyze_with_elite_ai(repo_files, test_report)
    if result:
        return result
    else:
        raise HTTPException(status_code=500, detail='Elite analysis failed')

# Serve static files from Front-End directory
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'Front-End')
app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

@app.get("/")
def serve_frontend():
    """Serve the main frontend page"""
    return FileResponse(os.path.join(frontend_dir, 'index.html'))

@app.get("/styles.css")
def serve_css():
    """Serve CSS file"""
    return FileResponse(os.path.join(frontend_dir, 'styles.css'))

@app.get("/script.js")
def serve_js():
    """Serve JavaScript file"""
    return FileResponse(os.path.join(frontend_dir, 'script.js'))

@app.get("/favicon.ico")
def serve_favicon():
    """Serve favicon to prevent 404 errors"""
    from fastapi.responses import Response
    return Response(status_code=204)

if __name__ == '__main__':
    import uvicorn
    port = int(os.getenv('PORT', 8000))
    uvicorn.run(app, host='0.0.0.0', port=port)