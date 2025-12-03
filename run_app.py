#!/usr/bin/env python3
"""
Main application runner for Code Scanner Agent
"""
import os
import sys
import uvicorn

# Add Back-End directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'Back-End'))

from code_scan_api import app

def main():
    """Run the FastAPI application"""
    try:
        port = int(os.getenv('PORT', 8005))
        host = os.getenv('HOST', '0.0.0.0')
        
        print(f"Starting Code Scanner Agent on {host}:{port}")
        print(f"Web UI: http://localhost:{port}")
        print(f"API Docs: http://localhost:{port}/docs")
        
        uvicorn.run(
            app, 
            host=host, 
            port=port,
            reload=os.getenv('DEBUG', 'false').lower() == 'true'
        )
    except KeyboardInterrupt:
        print("\nShutting down gracefully...")
    except Exception as e:
        print(f"Error starting application: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()