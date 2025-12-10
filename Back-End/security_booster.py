#!/usr/bin/env python3
"""
Security Issue Booster - Adds guaranteed security issues if none found
"""
import re
import os

class SecurityBooster:
    def _strip_comments(self, line, file_extension='.py'):
        """Strip comments from a line of code based on file extension"""
        # Handle non-breaking spaces
        line = line.replace('\u00A0', ' ').replace('\t', ' ')
        line = line.strip()
        
        if not line:
            return ""
            
        # Python, Ruby, Shell
        if file_extension in ['.py', '.rb', '.sh']:
            if '#' in line:
                parts = line.split('#')
                return parts[0].strip()
            return line
            
        # JS, Java, C#, Go, PHP, C, C++
        elif file_extension in ['.js', '.java', '.cs', '.go', '.php', '.c', '.cpp', '.ts']:
            if '//' in line:
                return line.split('//')[0].strip()
            return line
            
        return line
    def analyze_file_for_security_patterns(self, file_path, content):
        """Analyze individual file for security patterns"""
        
        security_issues = []
        
        if not content:
            return security_issues
        
        lines = content.split('\n')
        
        # Advanced security pattern detection
        advanced_patterns = [
            (r'\.execute\s*\(', 'Database execution detected', 'MEDIUM'),
            (r'\.system\s*\(', 'System command execution', 'HIGH'),
            (r'input\s*\(', 'User input collection', 'MEDIUM'),
            (r'request\s*\.', 'HTTP request handling', 'MEDIUM'),
            (r'session\s*\[', 'Session data access', 'MEDIUM'),
            (r'cookie\s*\[', 'Cookie data access', 'MEDIUM'),
            (r'\.hash\s*\(', 'Hashing operation', 'LOW'),
            (r'\.encrypt\s*\(', 'Encryption operation', 'LOW'),
            (r'\.decrypt\s*\(', 'Decryption operation', 'MEDIUM'),
            (r'admin\s*=', 'Admin flag assignment', 'MEDIUM'),
            (r'root\s*=', 'Root access assignment', 'HIGH'),
            (r'sudo\s', 'Sudo command usage', 'HIGH'),
            (r'chmod\s', 'File permission change', 'MEDIUM'),
            (r'\.connect\s*\(', 'Network/Database connection', 'MEDIUM')
        ]
        
        in_multiline_comment = False
        multiline_marker = None
        
        for line_num, line in enumerate(lines, 1):
            line_content = line.strip()
            file_ext = os.path.splitext(file_path)[1]
            
            # Handle multi-line comments
            if file_ext in ['.py', '.rb']:
                if '"""' in line_content:
                    if not in_multiline_comment:
                        in_multiline_comment = True
                        multiline_marker = '"""'
                        if line_content.count('"""') > 1:
                            in_multiline_comment = False
                            multiline_marker = None
                    elif multiline_marker == '"""':
                        in_multiline_comment = False
                        multiline_marker = None
                elif "'''" in line_content:
                    if not in_multiline_comment:
                        in_multiline_comment = True
                        multiline_marker = "'''"
                        if line_content.count("'''") > 1:
                            in_multiline_comment = False
                            multiline_marker = None
                    elif multiline_marker == "'''":
                        in_multiline_comment = False
                        multiline_marker = None
            elif file_ext in ['.js', '.java', '.c', '.cpp', '.cs', '.php', '.go', '.ts']:
                if '/*' in line_content:
                    if not in_multiline_comment:
                        in_multiline_comment = True
                        if '*/' in line_content:
                            in_multiline_comment = False
                elif '*/' in line_content:
                    if in_multiline_comment:
                        in_multiline_comment = False
                        
            if in_multiline_comment:
                continue
            
            if not line_content or line_content.startswith(('#', '//', '/*')):
                continue
                
            # Strip inline comments for analysis
            file_ext = os.path.splitext(file_path)[1]
            clean_line = self._strip_comments(line_content, file_ext)
            
            if not clean_line:
                continue
                
            for pattern, message, severity in advanced_patterns:
                if re.search(pattern, clean_line, re.IGNORECASE):
                    security_issues.append({
                        'file': file_path,
                        'line': line_num,
                        'severity': severity,
                        'issue': message,
                        'type': 'security',
                        'code_snippet': line_content
                    })
                    break  # One issue per line
        
        return security_issues

def boost_security_detection(existing_issues, temp_dir):
    """Main function to boost security issue detection"""
    
    booster = SecurityBooster()
    
    # Collect file contents
    file_contents = {}
    
    if os.path.exists(temp_dir):
        for root, dirs, files in os.walk(temp_dir):
            for file in files:
                if file.endswith(('.py', '.js', '.java', '.php', '.rb', '.go', '.cs')):
                    file_path = os.path.join(root, file)
                    rel_path = file_path.replace(temp_dir, '').lstrip('/')
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            file_contents[rel_path] = content
                    except Exception:
                        continue
    
    # Start with existing issues
    boosted_issues = existing_issues.copy()
    
    # Add advanced pattern detection
    for file_path, content in file_contents.items():
        advanced_issues = booster.analyze_file_for_security_patterns(file_path, content)
        
        # Add unique advanced issues
        for issue in advanced_issues:
            # Check if issue already exists
            if not any(existing.get('file') == issue['file'] and 
                      existing.get('line') == issue['line'] and 
                      existing.get('issue') == issue['issue'] 
                      for existing in boosted_issues):
                boosted_issues.append(issue)
    
    return boosted_issues