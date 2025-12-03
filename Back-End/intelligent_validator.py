#!/usr/bin/env python3
"""
Intelligent validation using Groq API to verify if GitHub repo and unit test report match
"""
import os
import json
import requests
import tempfile
from git import Repo
from dotenv import load_dotenv

load_dotenv()

ELITE_SENIOR_SECURITY_ANALYSIS_PROMPT = """
You are a Principal Security Engineer & Code Quality Architect with 20+ years at Google, Microsoft, and Trail of Bits.
You are performing a final pre-production security + quality gate on a student/company repository.

Your task is EXTREMELY strict: NEVER be nice. NEVER give false positives. NEVER accept fake/green tests.
You are the last line of defense before deployment.

INPUT:
- Repository files (full content provided below)
- Unit test report (pytest JSON + coverage data)

OUTPUT FORMAT (MUST BE VALID JSON, NO MARKDOWN, NO EXPLANATION OUTSIDE JSON):

{{
  "overall_verdict": "APPROVED" | "NEEDS_FIXES" | "REJECTED",
  "confidence_score": 0-100,
  "summary": "One-sentence ruthless verdict",
  "unit_test_analysis": {{
    "all_tests_green": true|false,
    "real_coverage_percent": float,
    "declared_vs_real_coverage_match": true|false,
    "fake_or_shallow_tests_detected": true|false,
    "missing_test_cases": ["tc_001 for terminal", "..."],
    "suspicious_patterns": ["100% coverage with only 12 statements", "filename with space and á", "..."],
    "verdict": "GENUINE" | "SHALLOW" | "FAKE" | "DANGEROUSLY_FAKE"
  }},
  "security_issues": [
    {{
      "id": "SEC-001",
      "title": "Hardcoded Secret Detected",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      "file": "app.py",
      "line": 42,
      "description": "API key hardcoded in source",
      "evidence": "API_KEY = \"sk-abc123...\"",
      "recommendation": "Use environment variables via os.getenv()"
    }}
  ],
  "quality_issues": [
    {{
      "id": "QUAL-001",
      "title": "Filename Contains Space and Accented Character",
      "severity": "HIGH",
      "file": "tests/generated/test_Interface Grafica_ToDoList.py",
      "description": "Will break on Linux, CI, imports, and many tools",
      "recommendation": "Rename to test_interface_grafica_todolist.py"
    }}
  ],
  "final_recommendations": [
    "Fix coverage mismatch (80.36% declared vs real 80%)",
    "Rename files with spaces/accents immediately",
    "Add real unit tests, not just generated smoke",
    "Remove all hardcoded secrets"
  ],
  "generated_at": "2025-12-03"
}}

RULES YOU MUST OBEY (BREAKING ANY = INSTANT FAILURE):
1. If all tests are green BUT coverage < 85% → verdict = "DANGEROUSLY_FAKE"
2. If declared coverage ≠ real coverage (e.g. 80.36% vs 80%) → flag as tampering
3. If filename has space or non-ASCII → HIGH severity quality issue
4. If test file has 100% coverage but < 20 statements → "SHALLOW"
5. NEVER say "looks good" if any issue exists
6. Confidence < 60 if tests look generated/shallow
7. Empty arrays if no issues found (never null)

NOW ANALYZE:

Repository files:
{repo_files_content}

Unit test report (raw):
{unit_test_report_json}

Respond with ONLY the valid JSON above. No explanations. No markdown. No refusal.
"""

class IntelligentValidator:
    def __init__(self):
        self.groq_api_key = os.getenv('GROQ_API_KEY')
        self.groq_api_url = os.getenv('GROQ_API_URL', 'https://api.groq.com/openai/v1/chat/completions')
        self.groq_model = os.getenv('LLM_MODEL', 'llama-3.1-70b-instant')
        self.enabled = bool(self.groq_api_key)
        
    def validate_repo_and_tests(self, github_url, unit_test_data):
        """
        Intelligently validate if GitHub repo and unit test report are related
        Returns: (is_valid: bool, confidence: float, reason: str)
        """
        if not self.enabled:
            return False, 0.0, "AI validation disabled - no API key"
        
        try:
            # Step 1: Clone and analyze repository
            repo_info = self._analyze_repository(github_url)
            if not repo_info:
                return False, 0.0, "Failed to analyze repository"
            
            # Step 2: Analyze unit test report
            test_info = self._analyze_test_report(unit_test_data)
            
            # Step 3: Use AI to compare and validate
            validation_result = self._ai_validate_match(repo_info, test_info, github_url)
            
            return validation_result
            
        except Exception as e:
            return False, 0.0, f"Validation error: {str(e)}"
    
    def _analyze_repository(self, github_url):
        """Clone and analyze repository structure and content"""
        temp_dir = None
        try:
            temp_dir = tempfile.mkdtemp()
            
            # Clone repository with error handling
            try:
                repo = Repo.clone_from(github_url, temp_dir, depth=1)
            except Exception as clone_error:
                print(f"Failed to clone repository {github_url}: {clone_error}")
                return None
            
            # Analyze repository
            repo_info = {
                'name': github_url.split('/')[-1].replace('.git', ''),
                'files': [],
                'structure': {},
                'languages': [],
                'test_files': [],
                'main_files': []
            }
            
            # Walk through repository files
            try:
                for root, dirs, files in os.walk(temp_dir):
                    # Skip .git directory
                    if '.git' in root:
                        continue
                        
                    for file in files:
                        if file.startswith('.'):
                            continue
                            
                        file_path = os.path.join(root, file)
                        rel_path = os.path.relpath(file_path, temp_dir)
                        
                        # Categorize files
                        if any(ext in file for ext in ['.py', '.js', '.java', '.ts', '.cpp', '.c']):
                            repo_info['files'].append(rel_path)
                            
                            # Detect language
                            if file.endswith('.py') and 'python' not in repo_info['languages']:
                                repo_info['languages'].append('python')
                            elif file.endswith(('.js', '.ts')) and 'javascript' not in repo_info['languages']:
                                repo_info['languages'].append('javascript')
                            elif file.endswith('.java') and 'java' not in repo_info['languages']:
                                repo_info['languages'].append('java')
                            
                            # Identify test files
                            if 'test' in file.lower() or 'spec' in file.lower():
                                repo_info['test_files'].append(rel_path)
                            
                            # Identify main files
                            if file.lower() in ['main.py', 'app.py', 'index.js', 'main.java']:
                                repo_info['main_files'].append(rel_path)
                            
                            # Read file content (configurable limit)
                            try:
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    content = f.read(int(os.getenv('FILE_READ_LIMIT', '500')))
                                    repo_info['structure'][rel_path] = content
                            except Exception as read_error:
                                print(f"Failed to read file {rel_path}: {read_error}")
                                continue
                
                # Ensure we have some data
                if not repo_info['files']:
                    print("No code files found in repository")
                    return None
                    
                return repo_info
                
            except Exception as walk_error:
                print(f"Failed to walk repository directory: {walk_error}")
                return None
            
        except Exception as e:
            print(f"Repository analysis failed: {e}")
            return None
        finally:
            if temp_dir:
                import shutil
                try:
                    shutil.rmtree(temp_dir)
                except Exception as cleanup_error:
                    print(f"Failed to cleanup temp directory: {cleanup_error}")
                    pass
    
    def _analyze_test_report(self, unit_test_data):
        """Analyze unit test report structure and content"""
        test_info = {
            'repository_name': unit_test_data.get('repository', ''),
            'test_files': [],
            'tested_modules': [],
            'framework': '',
            'languages': [],
            'coverage_files': []
        }
        
        # Extract test files and modules
        def extract_info(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    if 'file' in key.lower() and isinstance(value, str):
                        if any(ext in value for ext in ['.py', '.js', '.java']):
                            test_info['test_files'].append(value)
                    
                    if 'coverage' in key.lower() and isinstance(value, dict):
                        for file_name in value.keys():
                            if isinstance(file_name, str):
                                test_info['coverage_files'].append(file_name)
                    
                    extract_info(value, f"{path}.{key}")
            elif isinstance(obj, list):
                for item in obj:
                    extract_info(item, path)
        
        extract_info(unit_test_data)
        
        # Detect framework and language
        test_str = json.dumps(unit_test_data).lower()
        if 'pytest' in test_str:
            test_info['framework'] = 'pytest'
            if 'python' not in test_info['languages']:
                test_info['languages'].append('python')
        elif 'jest' in test_str:
            test_info['framework'] = 'jest'
            if 'javascript' not in test_info['languages']:
                test_info['languages'].append('javascript')
        elif 'junit' in test_str:
            test_info['framework'] = 'junit'
            if 'java' not in test_info['languages']:
                test_info['languages'].append('java')
        
        return test_info
    
    def analyze_with_elite_ai(self, repo_files_content, unit_test_report_json):
        """Elite AI analysis using senior security engineer prompt"""
        try:
            prompt = ELITE_SENIOR_SECURITY_ANALYSIS_PROMPT.format(
                repo_files_content=repo_files_content,
                unit_test_report_json=unit_test_report_json
            )
            
            headers = {
                "Authorization": f"Bearer {self.groq_api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": self.groq_model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 4096,
                "temperature": 0.0
            }
            
            response = requests.post(
                self.groq_api_url,
                json=payload,
                headers=headers,
                timeout=30
            )
            
            if response.status_code == 200:
                result = response.json()
                ai_response = result['choices'][0]['message']['content']
                
                # Clean and parse JSON
                cleaned_response = ai_response.strip().strip('```json').strip('```')
                return json.loads(cleaned_response)
            
            return None
            
        except Exception as e:
            print(f"Elite AI analysis failed: {e}")
            return None
    
    def _ai_validate_match(self, repo_info, test_info, github_url):
        """Use elite AI analysis for comprehensive validation"""
        try:
            # Prepare repository content
            repo_content = f"Repository: {github_url}\n"
            repo_content += f"Files: {repo_info['files']}\n"
            repo_content += f"Structure: {repo_info['structure']}\n"
            
            # Get elite analysis
            elite_result = self.analyze_with_elite_ai(repo_content, json.dumps(test_info))
            
            if elite_result:
                verdict = elite_result.get('overall_verdict', 'REJECTED')
                confidence = elite_result.get('confidence_score', 0) / 100.0
                summary = elite_result.get('summary', 'Elite analysis completed')
                
                is_valid = verdict in ['APPROVED', 'NEEDS_FIXES']
                return is_valid, confidence, summary
            
            return False, 0.0, "Elite AI analysis unavailable"
            
        except Exception as e:
            return False, 0.0, f"Elite validation failed: {str(e)}"

def test_intelligent_validation():
    """Test the intelligent validation system"""
    validator = IntelligentValidator()
    
    # Test data
    test_report = {
        "repository": "CodeScannerAgent",
        "test_summary": {"total_tests": 25, "passed": 22},
        "test_results": [
            {"test_file": "tests/test_scanner.py", "status": "PASSED"},
            {"test_file": "tests/test_api.py", "status": "FAILED"}
        ],
        "coverage_report": {
            "scanner.py": 92.5,
            "code_scan_api.py": 88.2
        }
    }
    
    print("🤖 INTELLIGENT VALIDATION TEST")
    print("=" * 50)
    
    # Test with matching repo
    print("\n1. Testing with matching repository:")
    is_valid, confidence, reason = validator.validate_repo_and_tests(
        "https://github.com/user/CodeScannerAgent.git", 
        test_report
    )
    print(f"Valid: {is_valid}")
    print(f"Confidence: {confidence:.2f}")
    print(f"Reason: {reason}")
    
    # Test with non-matching repo
    print("\n2. Testing with different repository:")
    wrong_report = test_report.copy()
    wrong_report['repository'] = 'DifferentProject'
    
    is_valid, confidence, reason = validator.validate_repo_and_tests(
        "https://github.com/user/CodeScannerAgent.git",
        wrong_report
    )
    print(f"Valid: {is_valid}")
    print(f"Confidence: {confidence:.2f}")
    print(f"Reason: {reason}")

if __name__ == "__main__":
    test_intelligent_validation()