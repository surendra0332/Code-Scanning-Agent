import os
import subprocess
import json
import tempfile
import shutil
import re
from llm_integration import LLMAnalyzer

# Optional imports with fallbacks
try:
    from git import Repo  # type: ignore
except ImportError:
    print("Warning: GitPython not installed. Repository cloning disabled.")
    Repo = None

class CodeScanner:
    def __init__(self):
        self.temp_dir = None
        self.llm_analyzer = LLMAnalyzer()
    
    def clone_repo(self, repo_url):
        """Clone repository to temporary directory"""
        self.repo_url = repo_url
        self.temp_dir = tempfile.mkdtemp()
        
        if not Repo:
            print("GitPython not available. Install with: pip install GitPython")
            return False
            
        try:
            clean_url = repo_url.split('?')[0]
            print(f"Attempting to clone: {clean_url}")
            
            # Validate URL format
            if not any(domain in clean_url for domain in ['github.com', 'gitlab.com', 'bitbucket.org']):
                print(f"Warning: Unusual repository URL: {clean_url}")
            
            Repo.clone_from(clean_url, self.temp_dir, depth=1)  # Shallow clone for faster processing
            print(f"Successfully cloned to: {self.temp_dir}")
            
            # Verify we have actual code files
            code_files = self._count_code_files()
            if code_files == 0:
                print("Warning: No code files found in repository")
                return False
                
            print(f"Found {code_files} code files to analyze")
            return True
            
        except Exception as e:
            error_msg = str(e)
            print(f"Clone error: {error_msg}")
            return False
    

    def scan_security(self):
        """Run security scan using bandit or manual analysis"""
        if not self.temp_dir:
            return []
        
        # Try different bandit paths
        bandit_paths = ['bandit', '/usr/local/bin/bandit', '/opt/homebrew/bin/bandit', 'python3 -m bandit']
        
        for bandit_cmd in bandit_paths:
            try:
                if 'python3 -m' in bandit_cmd:
                    cmd = ['python3', '-m', 'bandit', '-r', self.temp_dir, '-f', 'json']
                else:
                    cmd = [bandit_cmd, '-r', self.temp_dir, '-f', 'json']
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if result.stdout and result.returncode in [0, 1]:  # 1 = issues found
                    data = json.loads(result.stdout)
                    issues = []
                    for issue in data.get('results', []):
                        issue_text = issue['issue_text']
                        # Skip import-related issues from Bandit
                        if any(keyword in issue_text.lower() for keyword in ['import', 'module']):
                            continue
                        issue_data = {
                            'file': issue['filename'].replace(self.temp_dir, ''),
                            'line': issue['line_number'],
                            'severity': issue['issue_severity'],
                            'issue': issue_text,
                            'type': 'security'
                        }
                        # Add minimal code suggestion
                        issue_data['minimal_fix'] = self._generate_minimal_fix(issue_data)
                        issues.append(issue_data)
                    print(f"Bandit found {len(issues)} security issues")
                    return issues[:10]  # Limit results
            except Exception as e:
                continue
        
        print("Bandit not available, using manual analysis")
        return self._analyze_security_manually()
    
    def scan_quality(self):
        """Run code quality scan using pylint or manual analysis"""
        if not self.temp_dir:
            return []
        
        # Try different pylint paths
        pylint_paths = ['pylint', '/usr/local/bin/pylint', '/opt/homebrew/bin/pylint', 'python3 -m pylint']
        
        for pylint_cmd in pylint_paths:
            try:
                if 'python3 -m' in pylint_cmd:
                    cmd = ['python3', '-m', 'pylint', '--output-format=json', '--recursive=y', self.temp_dir]
                else:
                    cmd = [pylint_cmd, '--output-format=json', '--recursive=y', self.temp_dir]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                if result.stdout:
                    data = json.loads(result.stdout)
                    issues = []
                    for issue in data:
                        if issue.get('type') in ['error', 'warning']:  # Only important issues
                            message = issue['message']
                            # Skip import-related issues from Pylint
                            if any(keyword in message.lower() for keyword in ['import', 'unused', 'module']):
                                continue
                            issues.append({
                                'file': issue['path'].replace(self.temp_dir, ''),
                                'line': issue['line'],
                                'severity': issue['type'],
                                'issue': message,
                                'type': 'quality'
                            })
                    if issues:
                        print(f"Pylint found {len(issues)} quality issues")
                        return issues[:10]  # Limit results
            except Exception as e:
                continue
        
        print("Pylint not available, using manual analysis")
        return self._analyze_quality_manually()
    
    def _analyze_security_manually(self):
        """Analyze repository for actual security issues"""
        issues = []
        if not os.path.exists(self.temp_dir):
            return []
        
        # REAL security vulnerabilities only
        security_patterns = [
            # Actual hardcoded secrets (very specific)
            (r'(?:password|pwd)\s*=\s*["\'][^"\s]{8,}["\'](?!.*(?:example|test|demo|placeholder|your_|replace|xxx|123))', 'Real hardcoded password found', 'CRITICAL'),
            (r'(?:api_key|apikey|secret_key|access_key|token)\s*=\s*["\'][A-Za-z0-9_-]{25,}["\'](?!.*(?:example|test|demo|placeholder|your_|replace))', 'Real hardcoded API key found', 'CRITICAL'),
            # Actual code injection (with user input)
            (r'eval\s*\(.*(?:input\(|request\.|params\[|args\[)', 'Code injection via eval() with user input', 'CRITICAL'),
            (r'exec\s*\(.*(?:input\(|request\.|params\[|args\[)', 'Code injection via exec() with user input', 'CRITICAL'),
            # Real XSS vulnerabilities (dynamic content)
            (r'innerHTML\s*=\s*[^"\';]*(?:\+.*(?:input|request|params)|\$\{.*(?:input|request|params))', 'XSS vulnerability via innerHTML with user data', 'HIGH'),
            (r'document\.write\s*\([^"\';]*(?:\+.*(?:input|request|params)|\$\{.*(?:input|request|params))', 'XSS vulnerability via document.write with user data', 'HIGH'),
            # Real SQL injection (string concatenation with variables)
            (r'(?:SELECT|INSERT|UPDATE|DELETE).*["\']\s*\+\s*(?:input|request|params|args|user)', 'SQL injection via string concatenation with user input', 'CRITICAL'),
            (r'cursor\.execute\s*\([^"\';]*(?:\+.*(?:input|request|params)|%.*(?:input|request|params))', 'SQL injection in database query with user input', 'CRITICAL'),
            # Real file system vulnerabilities
            (r'open\s*\([^"\';]*(?:\+.*(?:input|request|params)|\$\{.*(?:input|request|params))', 'Path traversal vulnerability with user input', 'HIGH'),
            # SSL/TLS issues
            (r'verify\s*=\s*False', 'SSL certificate verification disabled', 'HIGH'),
            (r'ssl_verify\s*=\s*False', 'SSL verification disabled', 'HIGH'),
            # Weak authentication
            (r'password\s*==\s*["\'](?:admin|root|password|123456)["\']', 'Weak hardcoded authentication', 'HIGH')
        ]
        
        for root, dirs, files in os.walk(self.temp_dir):
            for file in files:
                if file.endswith(('.py', '.js', '.java', '.php', '.rb', '.go', '.cs')):
                    file_path = os.path.join(root, file)
                    rel_path = file_path.replace(self.temp_dir, '').lstrip('/')
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        if not content.strip():
                            continue
                            
                        lines = content.split('\n')
                        
                        actual_lines = len(lines)
                        
                        for line_num, line in enumerate(lines, 1):
                            if line_num > actual_lines:
                                break
                                
                            line_content = line.strip()
                            
                            # Skip empty lines, comments, and ALL import statements
                            if (not line_content or 
                                line_content.startswith(('#', '//', '/*', '*', '"""', "'''")) or
                                line_content.startswith(('import ', 'from ', '__import__')) or
                                'import ' in line_content or
                                ' import ' in line_content or
                                line_content.endswith(' import') or
                                'from ' in line_content[:10]):
                                continue
                            
                            for pattern, message, severity in security_patterns:
                                if re.search(pattern, line_content, re.IGNORECASE):
                                    # Additional validation to reduce false positives
                                    if self._is_valid_security_issue(line_content, pattern):
                                        issues.append({
                                            'file': rel_path,
                                            'line': line_num,
                                            'severity': severity,
                                            'issue': message,
                                            'type': 'security'
                                        })
                                        break
                    
                    except Exception:
                        continue
        
        # Add minimal code suggestions to issues
        for issue in issues:
            issue['minimal_fix'] = self._generate_minimal_fix(issue)
        
        # Return only real security issues
        return issues[:5] if issues else []
    
    def _is_valid_security_issue(self, line_content, pattern):
        """Validate to ensure only REAL security issues"""
        line_lower = line_content.lower()
        
        # Skip ALL import statements
        if ('import ' in line_content or 
            'from ' in line_content or
            line_content.startswith(('import ', 'from ', '__import__'))):
            return False
        
        # Skip obvious test/example code
        false_positive_indicators = [
            'example', 'test', 'demo', 'placeholder', 'sample',
            'mock', 'fake', 'dummy', 'your_key_here', 'replace_with',
            'xxx', '123', 'abc', 'default', 'config'
        ]
        
        # Skip if it's clearly example/test code
        if any(indicator in line_lower for indicator in false_positive_indicators):
            return False
            
        # Skip configuration templates
        if any(char in line_content for char in ['<', '>', '{template}', '${']):
            return False
            
        # Must have realistic patterns for secrets
        if 'password' in pattern or 'key' in pattern:
            # Real secrets are usually longer and have mixed case/numbers
            if len(line_content) < 20:
                return False
                
        return True
    
    def _analyze_quality_manually(self):
        """Analyze repository for actual quality issues"""
        issues = []
        if not os.path.exists(self.temp_dir):
            return []
        
        # REAL code quality issues only (no import checks)
        quality_patterns = [
            # Critical TODOs (urgent ones only)
            (r'(?:TODO|FIXME|XXX).*(?:urgent|critical|important|security|bug|broken|fix)', 'Critical TODO/FIXME requiring immediate attention', 'error'),
            # Dangerous error handling
            (r'except\s*:\s*pass', 'Silent exception handling - errors ignored', 'error'),
            (r'catch\s*\([^)]*\)\s*{\s*}', 'Empty catch block - errors ignored', 'error'),
            (r'try\s*:\s*.*\s*except\s*Exception\s*:\s*pass', 'Broad exception silencing', 'error'),
            # Code smells (real issues)
            (r'if\s+True\s*:', 'Dead code - always true condition', 'warning'),
            (r'if\s+False\s*:', 'Dead code - always false condition', 'warning'),
            (r'while\s+True\s*:(?!.*break)', 'Infinite loop without break', 'warning'),
            # Debug code in production (but not imports)
            (r'console\.(?:log|debug)\s*\((?!.*(?:test|spec))', 'Debug logging in production code', 'warning'),
            (r'print\s*\(["\'](?:debug|DEBUG|test|Test)', 'Debug print statement', 'warning'),
            (r'debugger;', 'JavaScript debugger statement left in code', 'warning'),
            # Security-related quality issues
            (r'input\s*\(.*\).*eval', 'Dangerous: eval() with user input', 'error'),
            (r'os\.system\s*\(.*input', 'Dangerous: os.system() with user input', 'error')
        ]
        
        for root, dirs, files in os.walk(self.temp_dir):
            for file in files:
                if file.endswith(('.py', '.js', '.java', '.php')):
                    file_path = os.path.join(root, file)
                    rel_path = file_path.replace(self.temp_dir, '').lstrip('/')
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        
                        if not content.strip():
                            continue
                            
                        lines = content.split('\n')
                        
                        actual_lines = len(lines)
                        
                        for line_num, line in enumerate(lines, 1):
                            if line_num > actual_lines:
                                break
                                
                            line_content = line.strip()
                            
                            if not line_content:
                                continue
                            
                            # Skip comments and ALL import statements
                            if (line_content.startswith(('#', '//', '/*')) or
                                line_content.startswith(('import ', 'from ', '__import__')) or
                                'import ' in line_content or
                                ' import ' in line_content or
                                line_content.endswith(' import') or
                                'from ' in line_content[:10]):
                                continue
                            
                            # Check for real quality issues
                            for pattern, message, severity in quality_patterns:
                                if re.search(pattern, line_content, re.IGNORECASE):
                                    issues.append({
                                        'file': rel_path,
                                        'line': line_num,
                                        'severity': severity,
                                        'issue': message,
                                        'type': 'quality'
                                    })
                                    break
                    
                    except Exception:
                        continue
        
        # Add minimal code suggestions to quality issues
        for issue in issues:
            issue['minimal_fix'] = self._generate_minimal_fix(issue)
        
        # Return only real quality issues
        return issues[:8] if issues else []
    

    
    def _count_code_files(self):
        """Count actual code files in repository"""
        if not self.temp_dir or not os.path.exists(self.temp_dir):
            return 0
            
        count = 0
        code_extensions = {'.py', '.js', '.java', '.php', '.rb', '.go', '.cs', '.cpp', '.c', '.ts'}
        
        for root, dirs, files in os.walk(self.temp_dir):
            # Skip hidden and build directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__', 'build', 'dist']]
            
            for file in files:
                if any(file.endswith(ext) for ext in code_extensions):
                    count += 1
                    
        return count
    
    def get_repository_files(self):
        """Get list of all files in the repository"""
        if not self.temp_dir or not os.path.exists(self.temp_dir):
            return []
        
        files = []
        for root, dirs, filenames in os.walk(self.temp_dir):
            # Skip hidden directories and common build directories
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__', 'build', 'dist']]
            
            for filename in filenames:
                if not filename.startswith('.'):
                    rel_path = os.path.relpath(os.path.join(root, filename), self.temp_dir)
                    files.append(rel_path)
        
        return files
    
    def analyze_project_structure(self):
        """Analyze project structure to understand the codebase"""
        if not self.temp_dir or not os.path.exists(self.temp_dir):
            return {}
        
        structure = {
            'python_files': [],
            'test_files': [],
            'config_files': [],
            'main_modules': []
        }
        
        files = self.get_repository_files()
        
        for file_path in files:
            file_lower = file_path.lower()
            
            if file_path.endswith('.py'):
                structure['python_files'].append(file_path)
                
                if 'test' in file_lower or file_lower.startswith('test_'):
                    structure['test_files'].append(file_path)
                elif file_lower in ['main.py', 'app.py', '__init__.py', 'run.py']:
                    structure['main_modules'].append(file_path)
            
            elif file_path.endswith(('.json', '.yml', '.yaml', '.toml', '.cfg', '.ini')):
                structure['config_files'].append(file_path)
        
        return structure
    
    def _generate_minimal_fix(self, issue):
        """Generate minimal code fix suggestions"""
        issue_text = issue.get('issue', '').lower()
        
        # Minimal fix patterns
        if 'hardcoded password' in issue_text:
            return {
                'suggestion': 'Use environment variables',
                'minimal_code': 'password = os.getenv("PASSWORD")',
                'explanation': 'Store secrets in .env file, not in code'
            }
        elif 'hardcoded api key' in issue_text:
            return {
                'suggestion': 'Use environment variables',
                'minimal_code': 'api_key = os.getenv("API_KEY")',
                'explanation': 'Keep API keys in environment variables'
            }
        elif 'eval' in issue_text or 'code injection' in issue_text:
            return {
                'suggestion': 'Avoid eval(), use safe alternatives',
                'minimal_code': '# Use ast.literal_eval() for safe evaluation\nimport ast\nresult = ast.literal_eval(user_input)',
                'explanation': 'Never use eval() with user input'
            }
        elif 'sql injection' in issue_text:
            return {
                'suggestion': 'Use parameterized queries',
                'minimal_code': 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
                'explanation': 'Always use parameterized queries'
            }
        elif 'xss' in issue_text or 'innerhtml' in issue_text:
            return {
                'suggestion': 'Use textContent instead of innerHTML',
                'minimal_code': 'element.textContent = userInput; // Safe\n// element.innerHTML = userInput; // Unsafe',
                'explanation': 'Avoid innerHTML with user data'
            }
        elif 'debug' in issue_text or 'console.log' in issue_text:
            return {
                'suggestion': 'Remove debug statements',
                'minimal_code': '// console.log("debug info"); // Remove in production',
                'explanation': 'Clean up debug code before deployment'
            }
        elif 'todo' in issue_text or 'fixme' in issue_text:
            return {
                'suggestion': 'Complete or remove TODO items',
                'minimal_code': '# Implement the required functionality\n# or remove if not needed',
                'explanation': 'Address all TODO/FIXME comments'
            }
        elif 'empty' in issue_text:
            return {
                'suggestion': 'Implement function or add pass statement',
                'minimal_code': 'def function_name():\n    pass  # Placeholder implementation',
                'explanation': 'Empty functions should have minimal implementation'
            }
        else:
            return {
                'suggestion': 'Follow minimal coding principles',
                'minimal_code': '# Write only essential code\n# Remove unnecessary complexity',
                'explanation': 'Keep code simple and focused'
            }
    
    def generate_minimal_project_structure(self):
        """Generate minimal project structure suggestions"""
        if not self.temp_dir:
            return {}
        
        structure = self.analyze_project_structure()
        
        suggestions = {
            'minimal_files': [],
            'removable_files': [],
            'structure_improvements': []
        }
        
        # Analyze current structure
        all_files = structure.get('python_files', []) + structure.get('config_files', [])
        
        # Essential files only
        essential_patterns = ['main.py', 'app.py', '__init__.py', 'requirements.txt']
        for file in all_files:
            if any(pattern in file.lower() for pattern in essential_patterns):
                suggestions['minimal_files'].append(file)
            elif any(pattern in file.lower() for pattern in ['test_', 'demo_', 'example_', 'backup_']):
                suggestions['removable_files'].append(file)
        
        # Structure improvements
        if len(structure.get('python_files', [])) > 5:
            suggestions['structure_improvements'].append('Consider consolidating into fewer files')
        
        if len(structure.get('config_files', [])) > 3:
            suggestions['structure_improvements'].append('Minimize configuration files')
        
        suggestions['structure_improvements'].extend([
            'Keep only essential dependencies in requirements.txt',
            'Use single main.py file for simple projects',
            'Avoid deep directory nesting',
            'Remove unused imports and functions'
        ])
        
        return suggestions
    
    def cleanup(self):
        """Clean up temporary directory"""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)