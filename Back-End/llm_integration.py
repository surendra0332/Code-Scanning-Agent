import os
import requests
import json
from dotenv import load_dotenv

load_dotenv()

class LLMAnalyzer:
    def __init__(self):
        self.enabled = False
        self.api_key = os.getenv('GROQ_API_KEY')
        self.api_url = os.getenv('GROQ_API_URL', 'https://api.groq.com/openai/v1/chat/completions')
        self.model = os.getenv('LLM_MODEL', 'llama-3.1-8b-instant')
        self.max_tokens = int(os.getenv('LLM_MAX_TOKENS', '1000'))
        self.temperature = float(os.getenv('LLM_TEMPERATURE', '0.1'))
        self.timeout = int(os.getenv('LLM_TIMEOUT', '15'))
        
        if (os.getenv('LLM_ENABLED', 'false').lower() == 'true' and 
            self.api_key and self.api_key != 'your_groq_api_key_here'):
            self.enabled = True
            print("LLM integration enabled with Groq API")
        else:
            print("LLM integration disabled - no API key configured")
    
    def analyze_code_files(self, file_contents, repo_url):
        """Use LLM to analyze actual code files for issues"""
        if not self.enabled or not file_contents:
            return []
        
        try:
            # Create code analysis prompt
            code_summary = f"Repository: {repo_url}\n\nCode files to analyze:\n"
            for file_path, content in file_contents.items():
                # Limit content size for API (configurable)
                content_limit = int(os.getenv('FILE_READ_LIMIT', '1000'))
                truncated_content = content[:content_limit] + '...' if len(content) > content_limit else content
                code_summary += f"\n=== {file_path} ===\n{truncated_content}\n"
            
            prompt = f"""Analyze this code repository for security vulnerabilities and code quality issues.

{code_summary}

Find real issues like:
- Security: SQL injection, XSS, hardcoded secrets, insecure protocols
- Quality: Long functions, missing error handling, code smells, performance issues

Return ONLY real issues in this JSON format:
{{
  "issues": [
    {{
      "file": "filename",
      "line": 1,
      "type": "security" or "quality",
      "severity": "HIGH/MEDIUM/LOW",
      "issue": "description"
    }}
  ]
}}

If no real issues found, return: {{"issues": []}}"""
            
            # Use Groq REST API with configurable values
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": self.model,
                "messages": [{
                    "role": "user",
                    "content": prompt
                }],
                "max_tokens": self.max_tokens,
                "temperature": self.temperature
            }
            
            response = requests.post(self.api_url, json=payload, headers=headers, timeout=self.timeout)
            
            if response.status_code == 200:
                result = response.json()
                analysis_text = result.get('choices', [{}])[0].get('message', {}).get('content', '')
                
                # Try to parse JSON response
                try:
                    # Extract JSON from response
                    json_start = analysis_text.find('{')
                    json_end = analysis_text.rfind('}') + 1
                    if json_start >= 0 and json_end > json_start:
                        json_str = analysis_text[json_start:json_end]
                        parsed = json.loads(json_str)
                        return parsed.get('issues', [])
                except:
                    pass
                
                # Fallback: parse text response
                return self._parse_text_issues(analysis_text)
            else:
                print(f"Groq API error: {response.status_code} - {response.text}")
                return []
                
        except Exception as e:
            print(f"LLM analysis failed: {e}")
            return []
    
    def _parse_text_issues(self, text):
        """Parse issues from text response"""
        issues = []
        lines = text.split('\n')
        
        for line in lines:
            if any(keyword in line.lower() for keyword in ['security', 'vulnerability', 'issue', 'problem']):
                # Extract basic issue info
                if 'security' in line.lower():
                    issue_type = 'security'
                    severity = 'HIGH'
                else:
                    issue_type = 'quality'
                    severity = 'MEDIUM'
                
                issues.append({
                    'file': 'detected_file',
                    'line': 1,
                    'type': issue_type,
                    'severity': severity,
                    'issue': line.strip()[:100]
                })
        
        return issues[:5]  # Limit to 5 issues
    
