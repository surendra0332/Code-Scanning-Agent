#!/usr/bin/env python3
"""
Code Scanner Agent - Main Application Runner
Intelligent security and quality code analysis with test validation
"""
import os
import sys

# Add Back-End directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'Back-End'))

if __name__ == '__main__':
    try:
        import uvicorn
        from code_scan_api import app
        
        import subprocess
        import time

        # Configuration from environment
        port = int(os.getenv('PORT', 8000))
        host = os.getenv('HOST', '0.0.0.0')
        debug = os.getenv('DEBUG', 'false').lower() == 'true'
        
        def kill_port(port_num):
            """Kill process running on specified port"""
            try:
                # Find process ID
                cmd = f"lsof -i :{port_num} -t"
                pids = subprocess.check_output(cmd, shell=True).decode().strip().split('\n')
                
                for pid in pids:
                    if pid:
                        print(f"⚠️  Port {port_num} is in use by PID {pid}. Killing it...")
                        subprocess.run(f"kill -9 {pid}", shell=True, check=True)
                
                if pids:
                    time.sleep(1)  # Wait for release
                    print(f"✓ Port {port_num} released.")
            except subprocess.CalledProcessError:
                pass  # No process found, which is good
            except Exception as e:
                print(f"Warning: Could not auto-kill port {port_num}: {e}")

        # Ensure port is free
        kill_port(port)

        # Startup messages
        print(f"Starting Code Scanner Agent on {host}:{port}")
        print(f"Web UI: http://localhost:{port}")
        print(f"API Docs: http://localhost:{port}/docs")
        
        if debug:
            print("Debug mode: ON (auto-reload enabled)")
        
        # Start server
        # Set PYTHONPATH for the reloader process to find the module
        if debug:
            backend_path = os.path.join(os.path.dirname(__file__), 'Back-End')
            current_pythonpath = os.environ.get('PYTHONPATH', '')
            os.environ['PYTHONPATH'] = f"{backend_path}{os.pathsep}{current_pythonpath}"
        
        # Start server
        uvicorn.run(
            "code_scan_api:app", 
            host=host, 
            port=port,
            reload=debug,  # Auto-reload on code changes in debug mode
            reload_dirs=[os.path.join(os.path.dirname(__file__), 'Back-End')] if debug else None
        )
        
    except KeyboardInterrupt:
        print("\n✓ Shutting down gracefully...")
        sys.exit(0)
        
    except Exception as e:
        print(f"✗ Error starting application: {e}")
        sys.exit(1)