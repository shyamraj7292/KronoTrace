import os
import threading
import uvicorn
import subprocess
import time
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from api import router

app = FastAPI(title="KronoTrace API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

static_dir = os.path.join(os.path.dirname(__file__), "static")
if not os.path.exists(static_dir):
    os.makedirs(static_dir)

app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")

def run_server():
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")

def launch_app_window():
    time.sleep(1) # wait for server to start
    url = "http://127.0.0.1:8000/index.html"
    try:
        # Try Edge first (pre-installed on Windows)
        subprocess.Popen(["msedge", f"--app={url}"])
    except FileNotFoundError:
        try:
            # Fallback to Chrome
            subprocess.Popen(["chrome", f"--app={url}"])
        except FileNotFoundError:
            # Fallback to default browser
            import webbrowser
            webbrowser.open(url)

if __name__ == "__main__":
    t = threading.Thread(target=run_server)
    t.daemon = True
    t.start()
    
    launch_app_window()
    
    # Keep the main thread alive so the server continues running
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
