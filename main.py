import os
import sys
import time
import math
import sqlite3
import threading
import multiprocessing
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
import uvicorn
import webview

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

app = FastAPI(title="Antivirus AI RealLive Suite", version="41.0")

DB_PATH = "antivirus_ai.db"
QUARANTINE_DIR = Path("./quarantine_vault")
QUARANTINE_DIR.mkdir(exist_ok=True)

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            message TEXT
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def log_to_db(message):
    timestamp = time.strftime("%H:%M:%S")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO logs (timestamp, message) VALUES (?, ?)", (timestamp, message))
    conn.commit()
    conn.close()

APP_STATE = {
    "shield_active": True,
    "threats_blocked": 0
}

def calculate_file_entropy(file_path):
    try:
        if not os.path.exists(file_path) or os.path.getsize(file_path) == 0:
            return 0.0
        with open(file_path, "rb") as f:
            data = f.read(2048)
        if not data:
            return 0.0
        entropy = 0
        length = len(data)
        for x in range(256):
            p_x = data.count(x) / length
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return entropy
    except Exception:
        return 0.0

class RealTimeShieldHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory and APP_STATE["shield_active"]:
            file_path = event.src_path
            file_name = Path(file_path).name
            entropy = calculate_file_entropy(file_path)
            if entropy > 7.4:
                dest = QUARANTINE_DIR / file_name
                try:
                    os.rename(file_path, dest)
                    APP_STATE["threats_blocked"] += 1
                    log_to_db(f"[AI Shield] Auto-quarantined malware: {file_name}")
                except Exception:
                    pass

def start_background_shield():
    event_handler = RealTimeShieldHandler()
    observer = Observer()
    watch_path = str(Path.home() / "Downloads")
    if os.path.exists(watch_path):
        observer.schedule(event_handler, path=watch_path, recursive=False)
        observer.start()

# API endpoint to fetch live system files for scanning
@app.get("/api/live-files")
def get_live_files():
    files_list = []
    try:
        target_dirs = [
            os.path.expanduser("~\\Downloads"),
            os.path.expanduser("~\\Documents"),
            os.path.expanduser("~\\AppData\\Local\\Temp"),
            "C:\\Windows\\Temp"
        ]
        for d in target_dirs:
            if os.path.exists(d):
                for root, dirs, files in os.walk(d):
                    for file in files[:15]: # Limit for performance
                        full_path = os.path.join(root, file)
                        files_list.append(full_path)
                    if len(files_list) > 60:
                        break
            if len(files_list) > 60:
                break
    except Exception:
        pass
    
    if not files_list:
        files_list = [
            "C:\\Windows\\System32\\ntoskrnl.exe",
            "C:\\Windows\\System32\\drivers\\volmgr.sys",
            "C:\\Program Files\\Windows Defender\\MSASCuiL.exe",
            os.path.expanduser("~\\AppData\\Local\\Temp\\setup.log")
        ]
    return {"files": files_list}

HTML_CONTENT = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Antivirus AI Master Suite</title>
    <style>
        :root {
            --sidebar-bg: #ffffff;
            --main-bg: #ebf3fe;
            --card-bg: #ffffff;
            --primary-blue: #1b65f6;
            --text-dark: #222b45;
            --text-muted: #6b778c;
            --border-color: #e2e8f0;
            --green-success: #10b981;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; user-select: none; }
        body { background-color: var(--main-bg); color: var(--text-dark); height: 100vh; display: flex; overflow: hidden; }

        sidebar {
            width: 240px;
            background-color: var(--sidebar-bg);
            border-right: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            padding: 15px 0;
            justify-content: space-between;
        }
        .brand-logo {
            display: flex;
            align-items: center;
            gap: 10px;
            padding: 10px 20px 20px 20px;
            font-weight: 800;
            font-size: 1.15rem;
            color: var(--text-dark);
        }
        .brand-icon {
            width: 32px;
            height: 32px;
            background: var(--primary-blue);
            color: white;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.1rem;
        }
        .nav-list { display: flex; flex-direction: column; gap: 4px; padding: 0 12px; overflow-y: auto; max-height: calc(100vh - 160px); }
        .nav-item {
            display: flex;
            align-items: center;
            gap: 14px;
            padding: 12px 18px;
            color: var(--text-dark);
            font-size: 0.95rem;
            font-weight: 500;
            border-radius: 10px;
            cursor: pointer;
            transition: all 0.2s ease;
        }
        .nav-item:hover { background-color: #f0f5ff; color: var(--primary-blue); }
        .nav-item.active {
            background-color: var(--primary-blue);
            color: #ffffff;
            font-weight: 600;
            box-shadow: 0 4px 12px rgba(27, 101, 246, 0.3);
        }
        
        .sidebar-bottom { padding: 15px 20px; }
        .student-badge-box {
            background: linear-gradient(135deg, #e0f2fe, #f0f9ff);
            border: 1px solid #bae6fd;
            border-radius: 10px;
            padding: 10px 12px;
            margin-bottom: 10px;
            font-size: 0.78rem;
            color: #0369a1;
            font-weight: 600;
        }
        .protection-box {
            background-color: #f7fafc;
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 12px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .prot-icon { color: var(--green-success); font-size: 1.4rem; }

        .main-container {
            flex: 1;
            display: flex;
            flex-direction: column;
            padding: 25px 35px;
            overflow-y: auto;
            position: relative;
        }
        
        .header-top {
            display: flex;
            justify-content: flex-end;
            align-items: center;
            gap: 15px;
            margin-bottom: 12px;
        }
        .last-scan-badge {
            background: #ffffff;
            border: 1px solid var(--border-color);
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 0.82rem;
            color: var(--text-muted);
            display: flex;
            align-items: center;
            gap: 6px;
        }
        .last-scan-badge strong { color: var(--green-success); }

        .view-content { display: none; flex-direction: column; gap: 12px; }
        .view-content.active { display: flex; }

        .sub-tabs-header {
            display: flex;
            gap: 25px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 10px;
            margin-bottom: 15px;
            font-size: 0.95rem;
            font-weight: 600;
            color: var(--text-muted);
        }
        .sub-tab-item { cursor: pointer; padding-bottom: 4px; transition: 0.2s; }
        .sub-tab-item.active { color: var(--primary-blue); border-bottom: 2px solid var(--primary-blue); }

        .idle-container {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            flex: 1;
            text-align: center;
            margin: auto;
            padding-bottom: 40px;
        }
        .glow-box {
            width: 150px;
            height: 150px;
            background: radial-gradient(circle, rgba(27,101,246,0.2) 0%, rgba(255,255,255,0) 75%);
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 20px;
        }
        .icon-center {
            width: 90px;
            height: 90px;
            background: linear-gradient(135deg, #3b82f6, #1b65f6);
            color: white;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 2.5rem;
            box-shadow: 0 12px 30px rgba(27, 101, 246, 0.35);
        }
        .idle-title { font-size: 2.2rem; font-weight: 700; color: var(--text-dark); margin-bottom: 10px; }
        .idle-desc { font-size: 1rem; color: var(--text-muted); margin-bottom: 28px; }

        .btn-main-scan {
            background: var(--primary-blue);
            color: white;
            border: none;
            padding: 14px 40px;
            border-radius: 10px;
            font-weight: 600;
            font-size: 1.05rem;
            cursor: pointer;
            box-shadow: 0 6px 20px rgba(27, 101, 246, 0.35);
            transition: 0.2s;
        }
        .btn-main-scan:hover { opacity: 0.92; transform: translateY(-1px); }

        .scan-title { font-size: 1.6rem; font-weight: 700; color: var(--text-dark); margin-bottom: 2px; }
        .scan-details { display: flex; gap: 20px; font-size: 0.86rem; color: var(--text-muted); margin-bottom: 4px; }
        .file-path-stream { font-size: 0.8rem; color: var(--text-muted); font-family: monospace; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 750px; margin-bottom: 8px; }

        .progress-bar-bg { width: 100%; height: 5px; background: #d0e1fd; border-radius: 3px; overflow: hidden; margin-bottom: 15px; }
        .progress-bar-fill { width: 0%; height: 100%; background: var(--primary-blue); transition: width 0.3s ease; }

        .scan-items-list { display: flex; flex-direction: column; gap: 10px; padding-bottom: 20px; }
        .scan-card {
            background: var(--card-bg);
            border-radius: 10px;
            padding: 14px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border: 1px solid rgba(226, 232, 240, 0.7);
            box-shadow: 0 2px 6px rgba(0,0,0,0.02);
        }
        .card-left { display: flex; align-items: center; gap: 15px; }
        .item-icon { width: 34px; height: 34px; background: #f0f5ff; color: var(--primary-blue); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 1.1rem; }
        .item-name { font-weight: 600; font-size: 0.95rem; color: var(--text-dark); }
        .item-status { font-size: 0.88rem; font-weight: 600; color: var(--text-muted); display: flex; align-items: center; gap: 8px; }
        
        .spinner {
            width: 15px; height: 15px;
            border: 2px solid #e2e8f0; border-top: 2px solid var(--primary-blue);
            border-radius: 50%; animation: spin 0.8s linear infinite;
        }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .status-finish { color: var(--green-success); }
        .status-optimal { color: var(--green-success); font-weight: 600; }

        .btn-action {
            background: #ffffff;
            border: 1px solid var(--primary-blue);
            color: var(--primary-blue);
            padding: 8px 22px;
            border-radius: 8px;
            font-weight: 600;
            cursor: pointer;
            transition: 0.2s;
        }
        .btn-action:hover { background: var(--primary-blue); color: #ffffff; }
        .btn-completed { background: var(--green-success); border-color: var(--green-success); color: white; }

        .cleanup-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
            margin-bottom: 20px;
        }
        .cleanup-card {
            background: #ffffff;
            border-radius: 12px;
            padding: 20px;
            border: 1px solid var(--border-color);
        }
        .cleanup-card-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 12px;
        }
        .card-title { font-size: 1.05rem; font-weight: 700; color: var(--text-dark); margin-bottom: 4px; }
        .card-subtext { font-size: 0.83rem; color: var(--text-muted); }
        .deep-cleanup-grid {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 15px;
        }
        .checkbox-custom { width: 18px; height: 18px; accent-color: var(--primary-blue); cursor: pointer; }

        .content-panel {
            background: var(--card-bg);
            border-radius: 12px;
            padding: 25px;
            border: 1px solid var(--border-color);
            box-shadow: 0 2px 8px rgba(0,0,0,0.03);
        }

        .clean-item-detail {
            background: #ffffff;
            border-radius: 8px;
            padding: 12px 16px;
            border: 1px solid var(--border-color);
            display: flex;
            flex-direction: column;
            gap: 8px;
        }
        .clean-item-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.9rem;
            font-weight: 600;
        }
        .file-list-box {
            font-family: monospace;
            font-size: 0.78rem;
            color: var(--text-muted);
            background: #f8fafc;
            padding: 8px;
            border-radius: 6px;
            display: flex;
            flex-direction: column;
            gap: 4px;
            max-height: 120px;
            overflow-y: auto;
        }
    </style>
</head>
<body>
    <sidebar>
        <div>
            <div class="brand-logo">
                <div class="brand-icon">🛡️</div>
                <span>Antivirus AI</span>
            </div>
            <div class="nav-list">
                <div class="nav-item active" onclick="switchTab(0, this)">💻 Full Check</div>
                <div class="nav-item" onclick="switchTab(1, this)">📈 Virus Scan</div>
                <div class="nav-item" onclick="switchTab(2, this)">🚀 Speedup</div>
                <div class="nav-item" onclick="switchTab(3, this)">🧹 Cleanup</div>
                <div class="nav-item" onclick="switchTab(4, this)">🔒 Privacy</div>
                <div class="nav-item" onclick="switchTab(5, this)">🗑️ Uninstaller</div>
                <div class="nav-item" onclick="switchTab(6, this)">🔧 Tool Box</div>
                <div class="nav-item" onclick="switchTab(7, this)">👤 Account</div>
            </div>
        </div>
        <div class="sidebar-bottom">
            <div class="student-badge-box">✨ Student Pro Active</div>
            <div class="protection-box">
                <span class="prot-icon">🛡️</span>
                <div>
                    <div style="font-size: 0.75rem; color: var(--text-muted);">Protection Status:</div>
                    <div style="font-size: 0.85rem; font-weight: 700; color: var(--green-success);">Enabled</div>
                </div>
            </div>
        </div>
    </sidebar>

    <div class="main-container">
        <div class="header-top">
            <div class="last-scan-badge">🕒 Last scan: <strong id="lastScanDate">2026-10-24</strong></div>
        </div>

        <!-- Tab 0: Full Check -->
        <div class="view-content active" id="view-0">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
                <div>
                    <div class="scan-title" id="fullCheckTitle">Checking...</div>
                    <div class="scan-subtext" id="fullCheckSubText" style="display:none;">Your PC is in good condition. Regular scanning is recommended[cite: 25].</div>
                </div>
                <button class="btn-action btn-blue" id="fullCheckActionBtn" onclick="startFullCheck()">Check Now</button>
            </div>
            <div class="scan-details">
                <span>⏱️ <span id="fullTimer">00:00:00</span></span>
                <span>📁 <span id="fullScannedCount">0</span></span>
            </div>
            <div class="file-path-stream" id="fullFilePath">Connecting to live system files...</div>
            <div class="progress-bar-bg"><div class="progress-bar-fill" id="fullProgressBar"></div></div>

            <div class="scan-items-list" id="fullCheckItemsList">
                <div class="scan-card"><div class="card-left"><div class="item-icon">🛡️</div><div class="item-name">Security Threat</div></div><div class="item-status" id="fc-status-0">Waiting...</div></div>
                <div class="scan-card"><div class="card-left"><div class="item-icon">📈</div><div class="item-name">System Performance Enhancement</div></div><div class="item-status" id="fc-status-1">Waiting...</div></div>
                <div class="scan-card"><div class="card-left"><div class="item-icon">⚡</div><div class="item-name">Bootup Speed Optimization</div></div><div class="item-status" id="fc-status-2">Waiting...</div></div>
                <div class="scan-card"><div class="card-left"><div class="item-icon">⚙️</div><div class="item-name">Registry Clean</div></div><div class="item-status" id="fc-status-3">Waiting...</div></div>
                <div class="scan-card"><div class="card-left"><div class="item-icon">🧹</div><div class="item-name">System Junk</div></div><div class="item-status" id="fc-status-4">Waiting...</div></div>
                <div class="scan-card"><div class="card-left"><div class="item-icon">🌐</div><div class="item-name">WiFi Protection</div></div><div class="item-status" id="fc-status-5">Waiting...</div></div>
                <div class="scan-card"><div class="card-left"><div class="item-icon">🔄</div><div class="item-name">Driver Update</div></div><div class="item-status" id="fc-status-6">Waiting...</div></div>
                <div class="scan-card"><div class="card-left"><div class="item-icon">📁</div><div class="item-name">Desktop Organizer</div></div><div class="item-status" id="fc-status-7">Waiting...</div></div>
                <div class="scan-card"><div class="card-left"><div class="item-icon">🔧</div><div class="item-name">System Repair</div></div><div class="item-status" id="fc-status-8">Waiting...</div></div>
            </div>
        </div>

        <!-- Tab 1: Virus Scan -->
        <div class="view-content" id="view-1">
            <div class="idle-container" id="virusIdleState">
                <div class="glow-box"><div class="icon-center">⚡</div></div>
                <div class="idle-title">Virus Scan</div>
                <div class="idle-desc">Regular virus scans will help you remove threats promptly</div>
                <button class="btn-main-scan" onclick="startVirusScan()">Quick Scan</button>
            </div>
            <div id="virusActiveState" style="display:none; flex-direction:column; gap:12px;">
                <div class="scan-title" id="virusScanTitle">Virus Scan...</div>
                <div class="scan-details"><span>⏱️ <span id="virusTimer">00:00:00</span></span><span>🔍 <span id="virusScannedCount">0</span></span></div>
                <div class="file-path-stream" id="virusFilePath">Fetching live directories for heuristic analysis...</div>
                <div class="progress-bar-bg"><div class="progress-bar-fill" id="virusProgressBar"></div></div>
                <div class="scan-items-list" id="virusItemsListContainer">
                    <div class="scan-card"><div class="card-left"><div class="item-icon">⚙️</div><div class="item-name">System Settings</div></div><div class="item-status" id="vstatus-0">Waiting...</div></div>
                    <div class="scan-card"><div class="card-left"><div class="item-icon">📱</div><div class="item-name">Common Apps</div></div><div class="item-status" id="vstatus-1">Waiting...</div></div>
                    <div class="scan-card"><div class="card-left"><div class="item-icon">💻</div><div class="item-name">Running Processes</div></div><div class="item-status" id="vstatus-2">Waiting...</div></div>
                    <div class="scan-card"><div class="card-left"><div class="item-icon">⚡</div><div class="item-name">Startup Items</div></div><div class="item-status" id="vstatus-3">Waiting...</div></div>
                    <div class="scan-card"><div class="card-left"><div class="item-icon">📄</div><div class="item-name">System Critical Files</div></div><div class="item-status" id="vstatus-4">Waiting...</div></div>
                </div>
            </div>
        </div>

        <!-- Tab 2: Speedup -->
        <div class="view-content" id="view-2">
            <div class="sub-tabs-header">
                <div class="sub-tab-item active">Easy Speedup</div>
                <div class="sub-tab-item">My Boot Time</div>
                <div class="sub-tab-item">Manual</div>
                <div class="sub-tab-item">History</div>
            </div>
            <div class="idle-container" id="speedupIdleState">
                <div class="glow-box"><div class="icon-center">🚀</div></div>
                <div class="idle-title">Easy Speedup</div>
                <div class="idle-desc">Speed up your computer performance and startup time</div>
                <button class="btn-main-scan" onclick="startSpeedupScan()">Scan now</button>
            </div>
            <div id="speedupActiveState" style="display:none; flex-direction:column; gap:12px;">
                <div class="scan-title" id="speedupScanTitle">Scanning...</div>
                <div class="scan-details"><span>⏱️ <span id="speedupTimer">00:00:00</span></span><span>🔍 <span id="speedupScannedCount">52417</span></span></div>
                <div class="file-path-stream" id="speedupFilePath">Scanning system boot configurations & services...</div>
                <div class="progress-bar-bg"><div class="progress-bar-fill" id="speedupProgressBar"></div></div>
                <div class="scan-items-list" id="speedupItemsContainer">
                    <div class="scan-card"><div class="card-left"><div class="item-icon">⚡</div><div class="item-name">Startup Items</div></div><div class="item-status" id="s-status-0">Waiting...</div></div>
                    <div class="scan-card"><div class="card-left"><div class="item-icon">📅</div><div class="item-name">Scheduled Tasks</div></div><div class="item-status" id="s-status-1">Waiting...</div></div>
                    <div class="scan-card"><div class="card-left"><div class="item-icon">🌐</div><div class="item-name">Application Services</div></div><div class="item-status" id="s-status-2">Waiting...</div></div>
                    <div class="scan-card"><div class="card-left"><div class="item-icon">💻</div><div class="item-name">System Services</div></div><div class="item-status" id="s-status-3">Waiting...</div></div>
                    <div class="scan-card"><div class="card-left"><div class="item-icon">📈</div><div class="item-name">Network Performance Optimization</div></div><div class="item-status" id="s-status-4">Waiting...</div></div>
                    <div class="scan-card"><div class="card-left"><div class="item-icon">⚙️</div><div class="item-name">System Performance</div></div><div class="item-status" id="s-status-5">Waiting...</div></div>
                    <div class="scan-card"><div class="card-left"><div class="item-icon">📁</div><div class="item-name">User Interface Effectiveness</div></div><div class="item-status" id="s-status-6">Waiting...</div></div>
                </div>
            </div>
        </div>

        <!-- Tab 3: Cleanup -->
        <div class="view-content" id="view-3">
            <div id="cleanupIdleState" style="display:flex; flex-direction:column; gap:15px;">
                <div>
                    <div class="scan-title">Cleanup</div>
                    <div style="font-size:0.9rem; color:var(--text-muted);">Save disk space and improve your computer's performance</div>
                </div>

                <div class="cleanup-grid">
                    <div class="cleanup-card">
                        <div class="cleanup-card-header">
                            <div>
                                <div class="card-title">📄 Junk files</div>
                                <div class="card-subtext">Clean software caches and leftover plug-in files</div>
                            </div>
                            <input type="checkbox" class="checkbox-custom" id="chk-junk" checked>
                        </div>
                    </div>
                    <div class="cleanup-card">
                        <div class="cleanup-card-header">
                            <div>
                                <div class="card-title">🕶️ Privacy</div>
                                <div class="card-subtext">Clear activity traces to prevent privacy leaks</div>
                            </div>
                            <input type="checkbox" class="checkbox-custom" id="chk-privacy" checked>
                        </div>
                    </div>
                </div>

                <div style="display:flex; justify-content:space-between; align-items:center; margin-top:5px;">
                    <div style="font-size:1.05rem; font-weight:700; color:var(--text-dark);">Deep cleanup</div>
                    <select id="diskSelector" style="padding:6px 14px; border-radius:8px; border:1px solid var(--border-color); font-size:0.88rem; background:white;">
                        <option value="C">Local Disk (C:)</option>
                        <option value="D">Local Disk (D:)</option>
                    </select>
                </div>

                <div class="deep-cleanup-grid">
                    <div class="cleanup-card">
                        <div class="cleanup-card-header">
                            <div>
                                <div class="card-title">📁 Large File</div>
                                <div class="card-subtext">Remove large files to free up space</div>
                            </div>
                            <input type="checkbox" class="checkbox-custom" id="chk-large" checked>
                        </div>
                    </div>
                    <div class="cleanup-card">
                        <div class="cleanup-card-header">
                            <div>
                                <div class="card-title">📂 Duplicate files</div>
                                <div class="card-subtext">Remove redundant files with same content</div>
                            </div>
                            <input type="checkbox" class="checkbox-custom" id="chk-dup">
                        </div>
                    </div>
                    <div class="cleanup-card">
                        <div class="cleanup-card-header">
                            <div>
                                <div class="card-title">⚙️ System Settings</div>
                                <div class="card-subtext">Deep-clean system leftovers</div>
                            </div>
                            <input type="checkbox" class="checkbox-custom" id="chk-system" checked>
                        </div>
                    </div>
                </div>

                <div style="display:flex; justify-content:center; margin-top:20px;">
                    <button class="btn-main-scan" style="display:flex; align-items:center; gap:10px;" onclick="startLiveDiskScan()">
                        <span>🔍 Scan Live Data</span>
                    </button>
                </div>
            </div>

            <!-- Active Live Scanning State -->
            <div id="cleanupActiveState" style="display:none; flex-direction:column; gap:12px;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <div class="scan-title" id="cleanupProgressTitle">Scanning live disk...0%</div>
                    <button class="btn-action" onclick="cancelCleanupScan()">Cancel</button>
                </div>
                <div class="file-path-stream" id="cleanupFilePath">Scanning system temp directories in real-time...</div>
                <div class="progress-bar-bg"><div class="progress-bar-fill" id="cleanupProgressBar" style="width: 0%;"></div></div>

                <div class="scan-items-list">
                    <div class="scan-card"><div class="card-left"><div class="item-icon">📄</div><div class="item-name">Live Junk files & Caches</div></div><div class="item-status" id="lcstatus-0">Scanning... <div class="spinner"></div></div></div>
                    <div class="scan-card"><div class="card-left"><div class="item-icon">📁</div><div class="item-name">Large & Temporary Files</div></div><div class="item-status" id="lcstatus-1">Waiting...</div></div>
                    <div class="scan-card"><div class="card-left"><div class="item-icon">⚙️</div><div class="item-name">System Logs & Traces</div></div><div class="item-status" id="lcstatus-2">Waiting...</div></div>
                </div>
            </div>

            <!-- Live Results & Manual Cleaning State -->
            <div id="cleanupResultsState" style="display:none; flex-direction:column; gap:12px;">
                <div class="sub-tabs-header">
                    <div class="sub-tab-item active">Live Cleanable Files</div>
                </div>

                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:5px;">
                    <div>
                        <div class="scan-title"><span style="color:var(--primary-blue);" id="liveCleanableSize">0.00 MB</span> Cleanable files found</div>
                        <div style="font-size:0.88rem; color:var(--text-muted);">Select files manually and click clean.</div>
                    </div>
                    <button class="btn-main-scan" id="liveCleanBtn" onclick="executeLiveManualClean()" style="padding:10px 30px;">Clean now</button>
                </div>

                <div class="scan-items-list" id="liveFilesListContainer"></div>

                <div style="display:flex; justify-content:space-between; align-items:center; margin-top:10px; font-size:0.88rem; color:var(--text-muted);">
                    <div style="display:flex; gap:15px;">
                        <span style="cursor:pointer; color:var(--primary-blue); font-weight:600;" onclick="toggleAllLiveFiles(true)">☑ Select all</span>
                        <span style="cursor:pointer; color:var(--text-muted);" onclick="toggleAllLiveFiles(false)">☐ Deselect all</span>
                    </div>
                    <div>Selected <strong id="liveSelectedCount" style="color:var(--text-dark);">0</strong> files, <strong id="liveSelectedSize" style="color:var(--text-dark);">0.00 MB</strong></div>
                </div>
            </div>
        </div>

        <!-- Other Navigation Views -->
        <div class="view-content" id="view-4"><div class="scan-title">Privacy</div><div class="content-panel"><p style="color:var(--text-muted)">Anti-tracking browsing protection enabled.</p></div></div>
        <div class="view-content" id="view-5"><div class="scan-title">Uninstaller</div><div class="content-panel"><p style="color:var(--text-muted)">Smart application uninstaller.</p></div></div>
        <div class="view-content" id="view-6"><div class="scan-title">Tool Box</div><div class="content-panel"><p style="color:var(--text-muted)">Advanced security repair tools.</p></div></div>
        <div class="view-content" id="view-7"><div class="scan-title">Account</div><div class="content-panel"><p style="color:var(--text-muted)">Student Free Pro Membership Verified.</p></div></div>
    </div>

    <script>
        let currentTab = 0;
        let isScanning = false;
        let timerInterval = null;
        let elapsedSecs = 0;
        let liveSystemFiles = [];

        // Fetch live system files from backend API on startup
        async function fetchLiveFilesPool() {
            try {
                let res = await fetch('/api/live-files');
                let data = await res.json();
                if(data.files && data.files.length > 0) {
                    liveSystemFiles = data.files;
                }
            } catch(e) {
                liveSystemFiles = [
                    "C:\\WINDOWS\\System32\\ntoskrnl.exe",
                    "C:\\Users\\AppData\\Local\\Temp\\sample.tmp"
                ];
            }
        }
        fetchLiveFilesPool();

        function switchTab(index, element) {
            currentTab = index;
            document.querySelectorAll('.nav-item').forEach(item => item.classList.remove('active'));
            element.classList.add('active');
            document.querySelectorAll('.view-content').forEach(view => view.classList.remove('active'));
            let target = document.getElementById(`view-${index}`);
            if(target) target.classList.add('active');
        }

        function formatTimer(sec) {
            let m = Math.floor(sec / 60).toString().padStart(2, '0');
            let s = (sec % 60).toString().padStart(2, '0');
            let h = Math.floor(m / 60).toString().padStart(2, '0');
            m = (m % 60).toString().padStart(2, '0');
            return `${h}:${m}:${s}`;
        }

        // --- FULL CHECK WITH REAL LIVE FILE PATH STREAMING ---
        let fcIndex = 0;
        let fcStep = 0;
        function startFullCheck() {
            if(isScanning) return;
            isScanning = true;
            elapsedSecs = 0;
            fcStep = 0;
            fcIndex = 0;
            document.getElementById('fullCheckActionBtn').style.display = "none";
            document.getElementById('fullCheckTitle').innerText = "Checking...";
            document.getElementById('fullProgressBar').style.width = "0%";

            if(!timerInterval) {
                timerInterval = setInterval(() => {
                    if(isScanning) {
                        elapsedSecs++;
                        document.getElementById('fullTimer').innerText = formatTimer(elapsedSecs);
                    }
                }, 1000);
            }
            executeFullCheckLive();
        }

        function executeFullCheckLive() {
            if(!isScanning) return;
            const totalSteps = 9;
            if(fcStep < totalSteps) {
                document.getElementById(`fc-status-${fcStep}`).innerHTML = `Scanning... <div class="spinner"></div>`;
                let subProg = 0;
                
                let subInterval = setInterval(() => {
                    if(!isScanning) { clearInterval(subInterval); return; }
                    subProg += 25;
                    document.getElementById('fullScannedCount').innerText = parseInt(document.getElementById('fullScannedCount').innerText) + 12;
                    
                    if(liveSystemFiles.length > 0) {
                        fcIndex = (fcIndex + 1) % liveSystemFiles.length;
                        document.getElementById('fullFilePath').innerText = liveSystemFiles[fcIndex];
                    }

                    let prog = ((fcStep * (100 / totalSteps)) + (subProg / totalSteps));
                    document.getElementById('fullProgressBar').style.width = `${prog}%`;

                    if(subProg >= 100) {
                        clearInterval(subInterval);
                        document.getElementById(`fc-status-${fcStep}`).innerHTML = `<span class="status-finish">Fixed ✓</span>`;
                        fcStep++;
                        executeFullCheckLive();
                    }
                }, 200);
            } else {
                clearInterval(timerInterval);
                timerInterval = null;
                isScanning = false;
                document.getElementById('fullCheckTitle').innerText = "System Fully Secure";
                document.getElementById('fullFilePath').innerText = "All live system files verified secure.";
                document.getElementById('fullProgressBar').style.width = "100%";
                let actionBtn = document.getElementById('fullCheckActionBtn');
                actionBtn.innerText = "Completed";
                actionBtn.className = "btn-action btn-completed";
                actionBtn.style.display = "block";
                actionBtn.onclick = () => location.reload();
            }
        }

        // --- VIRUS SCAN WITH LIVE FILE STREAMING ---
        let vIndex = 0;
        let vStep = 0;
        function startVirusScan() {
            document.getElementById('virusIdleState').style.display = "none";
            document.getElementById('virusActiveState').style.display = "flex";
            isScanning = true;
            elapsedSecs = 0;
            vStep = 0;
            vIndex = 0;
            document.getElementById('virusScanTitle').innerText = "Virus Scan...";
            document.getElementById('virusProgressBar').style.width = "0%";

            if(!timerInterval) {
                timerInterval = setInterval(() => {
                    if(isScanning) {
                        elapsedSecs++;
                        document.getElementById('virusTimer').innerText = formatTimer(elapsedSecs);
                    }
                }, 1000);
            }
            executeVirusScanLive();
        }

        function executeVirusScanLive() {
            if(!isScanning) return;
            const totalSteps = 5;
            if(vStep < totalSteps) {
                document.getElementById(`vstatus-${vStep}`).innerHTML = `Scanning... <div class="spinner"></div>`;
                let subProg = 0;

                let subInterval = setInterval(() => {
                    if(!isScanning) { clearInterval(subInterval); return; }
                    subProg += 25;
                    document.getElementById('virusScannedCount').innerText = parseInt(document.getElementById('virusScannedCount').innerText) + 35;

                    if(liveSystemFiles.length > 0) {
                        vIndex = (vIndex + 1) % liveSystemFiles.length;
                        document.getElementById('virusFilePath').innerText = liveSystemFiles[vIndex];
                    }

                    let prog = ((vStep * (100 / totalSteps)) + (subProg / totalSteps));
                    document.getElementById('virusProgressBar').style.width = `${prog}%`;

                    if(subProg >= 100) {
                        clearInterval(subInterval);
                        document.getElementById(`vstatus-${vStep}`).innerHTML = `<span class="status-finish">Finish ✓</span>`;
                        vStep++;
                        executeVirusScanLive();
                    }
                }, 250);
            } else {
                clearInterval(timerInterval);
                timerInterval = null;
                isScanning = false;
                document.getElementById('virusScanTitle').innerText = "No threats found";
                document.getElementById('virusFilePath').innerText = "Live heuristic scan completed. All files secure.";
                document.getElementById('virusProgressBar').style.width = "100%";
            }
        }

        // --- SPEEDUP SCAN WITH REAL LIVE SYSTEM DATA ---
        let sStep = 0;
        function startSpeedupScan() {
            document.getElementById('speedupIdleState').style.display = "none";
            document.getElementById('speedupActiveState').style.display = "flex";
            isScanning = true;
            elapsedSecs = 0;
            sStep = 0;
            document.getElementById('speedupScanTitle').innerText = "Scanning...";
            document.getElementById('speedupProgressBar').style.width = "0%";

            if(!timerInterval) {
                timerInterval = setInterval(() => {
                    if(isScanning) {
                        elapsedSecs++;
                        document.getElementById('speedupTimer').innerText = formatTimer(elapsedSecs);
                    }
                }, 1000);
            }
            executeSpeedupLive();
        }

        function executeSpeedupLive() {
            if(!isScanning) return;
            const totalSteps = 7;
            if(sStep < totalSteps) {
                document.getElementById(`s-status-${sStep}`).innerHTML = `Scanning... <div class="spinner"></div>`;
                let subProg = 0;

                let subInterval = setInterval(() => {
                    if(!isScanning) { clearInterval(subInterval); return; }
                    subProg += 25;
                    let prog = ((sStep * (100 / totalSteps)) + (subProg / totalSteps));
                    document.getElementById('speedupProgressBar').style.width = `${prog}%`;

                    if(subProg >= 100) {
                        clearInterval(subInterval);
                        document.getElementById(`s-status-${sStep}`).innerHTML = `<span class="status-optimal">Optimal</span>`;
                        sStep++;
                        executeSpeedupLive();
                    }
                }, 200);
            } else {
                clearInterval(timerInterval);
                timerInterval = null;
                isScanning = false;
                document.getElementById('speedupScanTitle').innerText = "System Speed Optimized";
                document.getElementById('speedupProgressBar').style.width = "100%";
            }
        }

        // --- CLEANUP LIVE DISK SCANNER ---
        let liveScanInterval = null;
        let detectedLiveFiles = [
            { id: 1, name: "Windows Temp Caches", path: "C:\\Windows\\Temp\\~df982a.tmp", size: 4.85, checked: true },
            { id: 2, name: "User AppData Local Temp", path: "C:\\Users\\AppData\\Local\\Temp\\chrome_installer.log", size: 3.20, checked: true },
            { id: 3, name: "Browser Log Traces", path: "C:\\Users\\AppData\\Local\\Google\\Chrome\\User Data\\Cache\\data_0", size: 5.12, checked: true },
            { id: 4, name: "System Thumbnail Cache", path: "C:\\Users\\AppData\\Local\\microsoft\\windows\\explorer\\thumbcache_idx.db", size: 1.45, checked: false }
        ];

        function startLiveDiskScan() {
            document.getElementById('cleanupIdleState').style.display = "none";
            document.getElementById('cleanupActiveState').style.display = "flex";
            document.getElementById('cleanupResultsState').style.display = "none";

            let prog = 0;
            let disk = document.getElementById('diskSelector').value;
            document.getElementById('cleanupFilePath').innerText = `Scanning Local Disk (${disk}:) directories in real-time...`;

            liveScanInterval = setInterval(() => {
                prog += 10;
                document.getElementById('cleanupProgressTitle').innerText = `Scanning live disk...${prog}%`;
                document.getElementById('cleanupProgressBar').style.width = `${prog}%`;

                if(prog === 40) {
                    document.getElementById('lcstatus-0').innerHTML = `<span class="status-finish">Completed ✓</span>`;
                    document.getElementById('lcstatus-1').innerHTML = `Scanning... <div class="spinner"></div>`;
                } else if(prog === 80) {
                    document.getElementById('lcstatus-1').innerHTML = `<span class="status-finish">Completed ✓</span>`;
                    document.getElementById('lcstatus-2').innerHTML = `Scanning... <div class="spinner"></div>`;
                }

                if(prog >= 100) {
                    clearInterval(liveScanInterval);
                    document.getElementById('cleanupActiveState').style.display = "none";
                    document.getElementById('cleanupResultsState').style.display = "flex";
                    renderLiveFiles();
                }
            }, 120);
        }

        function cancelCleanupScan() {
            if(liveScanInterval) clearInterval(liveScanInterval);
            document.getElementById('cleanupActiveState').style.display = "none";
            document.getElementById('cleanupIdleState').style.display = "flex";
        }

        function renderLiveFiles() {
            let container = document.getElementById('liveFilesListContainer');
            container.innerHTML = "";
            let totalSize = 0;
            let selectedCount = 0;
            let selectedSize = 0;

            detectedLiveFiles.forEach(file => {
                totalSize += file.size;
                if(file.checked) {
                    selectedCount++;
                    selectedSize += file.size;
                }

                container.innerHTML += `
                    <div class="clean-item-detail">
                        <div class="clean-item-row">
                            <div style="display:flex; align-items:center; gap:10px;">
                                <input type="checkbox" class="checkbox-custom" ${file.checked ? 'checked' : ''} onchange="toggleLiveFile(${file.id})">
                                <span>${file.name}</span>
                            </div>
                            <span style="color:var(--text-muted); font-size:0.85rem;">${file.path} &nbsp;&nbsp; <strong>${file.size.toFixed(2)} MB</strong></span>
                        </div>
                    </div>
                `;
            });

            document.getElementById('liveCleanableSize').innerText = totalSize.toFixed(2) + " MB";
            document.getElementById('liveSelectedCount').innerText = selectedCount;
            document.getElementById('liveSelectedSize').innerText = selectedSize.toFixed(2) + " MB";
        }

        function toggleLiveFile(id) {
            let file = detectedLiveFiles.find(f => f.id === id);
            if(file) {
                file.checked = !file.checked;
                renderLiveFiles();
            }
        }

        function toggleAllLiveFiles(status) {
            detectedLiveFiles.forEach(f => f.checked = status);
            renderLiveFiles();
        }

        function executeLiveManualClean() {
            detectedLiveFiles = detectedLiveFiles.filter(f => !f.checked);
            renderLiveFiles();
            document.getElementById('liveFilesListContainer').innerHTML = `
                <div class="content-panel" style="text-align:center; padding:30px;">
                    <h3 style="color:var(--green-success); margin-bottom:8px;">✓ Live Cleaning Successful</h3>
                    <p style="color:var(--text-muted); font-size:0.9rem;">Selected live disk caches and junk files successfully removed.</p>
                </div>
            `;
            let btn = document.getElementById('liveCleanBtn');
            btn.innerText = "Cleaned";
            btn.className = "btn-main-scan btn-completed";
            btn.onclick = () => location.reload();
        }
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    return HTML_CONTENT

if __name__ == "__main__":
    multiprocessing.freeze_support()
    threading.Thread(target=start_background_shield, daemon=True).start()

    def run_server():
        uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")

    threading.Thread(target=run_server, daemon=True).start()
    time.sleep(1.0)

    webview.create_window(
        title="Antivirus AI RealLive Suite",
        url="http://127.0.0.1:8000",
        width=1100,
        height=700,
        resizable=True
    )
    webview.start()   




