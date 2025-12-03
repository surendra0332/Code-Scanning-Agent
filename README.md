# Code Scanner Agent

Intelligent code scanning system with AI-powered validation that analyzes repositories for security vulnerabilities and code quality issues.

## ✨ Features

- 🤖 **AI-Powered Validation** - Groq LLM integration for intelligent repository analysis
- 🛡️ **Security Scanning** - Detects vulnerabilities, hardcoded secrets, injection flaws
- 📊 **Quality Analysis** - Code quality, complexity, and best practices checking
- 🔍 **Smart Validation** - Multi-method verification of unit test reports
- 🌐 **Web Interface** - Clean, responsive UI for easy scanning
- 📱 **REST API** - Complete API for programmatic access

## 🚀 Quick Start

1. **Install dependencies:**
```bash
pip install -r requirements.txt
```

2. **Configure environment:**
```bash
# Edit .env with your Groq API key
GROQ_API_KEY=your_groq_api_key_here
```

3. **Run application:**
```bash
python run_app.py
```

4. **Access application:**
- 🌐 Web UI: http://localhost:8000
- 📚 API Docs: http://localhost:8000/docs

## 📁 Project Structure

```
CodeScannerAgent/
├── code_scan_api.py          # Main FastAPI application
├── scanner.py                # Security & quality scanning engine
├── intelligent_validator.py  # AI-powered validation system
├── llm_integration.py        # Groq LLM integration
├── database.py               # SQLite database operations
├── index.html               # Web interface
├── script.js                # Frontend JavaScript
├── styles.css               # UI styling
├── run_app.py               # Application launcher
├── requirements.txt         # Python dependencies
├── .env                     # Environment configuration
└── README.md               # This file
```

## 🔧 API Endpoints

### Start Intelligent Scan
```http
POST /api/scan
Content-Type: multipart/form-data

repo_url: https://github.com/username/repository.git
unit_test_report: [JSON file upload - Required]
```

### Get Scan Status
```http
GET /api/scan/{job_id}
```

### Download Reports
```http
GET /api/download/{job_id}/json
GET /api/download/{job_id}/pdf
```

### Health Check
```http
GET /api/health
```

## 💡 Usage

### Web Interface
1. Open http://localhost:8000
2. Enter GitHub repository URL
3. Upload matching unit test report (JSON)
4. AI validates repository-test correlation
5. View comprehensive scan results

### API Usage
```bash
# Start scan with validation
curl -X POST http://localhost:8000/api/scan \
  -F "repo_url=https://github.com/user/repo.git" \
  -F "unit_test_report=@test_report.json"

# Check status
curl http://localhost:8000/api/scan/{job_id}

# Download JSON report
curl http://localhost:8000/api/download/{job_id}/json
```

## 🤖 AI Validation System

The intelligent validator uses Groq's Llama model to analyze:
- Repository structure and files
- Unit test report authenticity
- Code-test correlation
- Framework and language alignment

**Confidence Levels:**
- 🟢 High (70%+): Auto-approved
- 🟡 Medium (50-70%): Additional checks
- 🔴 Low (<50%): Rejected with reason

## 🛡️ Security Features

- **Multi-layer validation** prevents fake test reports
- **Repository cloning** for actual code analysis
- **Pattern-based detection** for common vulnerabilities
- **AI enhancement** reduces false positives

## 📊 Scan Results

- **Security Issues**: Vulnerabilities with severity levels
- **Quality Issues**: Code smells and improvements
- **Unit Test Summary**: Test coverage and results
- **Downloadable Reports**: JSON and text formats

---

**Built with FastAPI, SQLite, and Groq AI** 🚀