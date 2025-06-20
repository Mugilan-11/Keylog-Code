import os
import psutil
from datetime import datetime
import platform
import subprocess
import ctypes

IS_WINDOWS = platform.system() == 'Windows'
LOG_FILE = "keylogger_detection.log"

def log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}"
    print(log_entry)
    with open(LOG_FILE, 'a') as f:
        f.write(log_entry + "\n")

def list_processes():
    log("Listing active processes:")
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            log(f"Process: {proc.info['name']} (PID: {proc.info['pid']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

def detect_keylogger_signature():
    log("🔍 Signature-based keylogger detection...")
    suspicious_keywords = ['keylog', 'hook', 'logger', 'capture', 'record']
    found = False
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            pname = proc.info['name']
            pexe = proc.info.get('exe', '')
            if any(keyword in (pname or '').lower() for keyword in suspicious_keywords) or \
               any(keyword in (pexe or '').lower() for keyword in suspicious_keywords):
                log(f"⚠️ Suspicious process: {pname} (PID: {proc.pid}) Path: {pexe}")
                found = True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    if not found:
        log("✅ No suspicious keylogger signatures found.")

def detect_behavioral_keylogger():
    log("🧠 Behavioral keylogger detection...")
    found = False

    # Linux check for /dev/input
    if not IS_WINDOWS:
        try:
            result = subprocess.run(["lsof", "/dev/input/"], capture_output=True, text=True)
            lines = result.stdout.strip().split("\n")[1:]
            for line in lines:
                parts = line.split()
                if len(parts) >= 2:
                    pid = parts[1]
                    pname = parts[0]
                    log(f"⚠️ Process accessing /dev/input: {pname} (PID: {pid})")
                    found = True
        except Exception as e:
            log(f"❌ Behavioral detection (Linux) failed: {e}")

    # Windows hook detection
    elif IS_WINDOWS:
        try:
            WH_KEYBOARD_LL = 13
            user32 = ctypes.windll.user32
            hook = user32.SetWindowsHookExW(WH_KEYBOARD_LL, 0, 0, 0)
            if hook:
                user32.UnhookWindowsHookEx(hook)
                log("⚠️ Detected global keyboard hook (Windows) — possible keylogger")
                found = True
        except Exception as e:
            log(f"❌ Behavioral detection (Windows) failed: {e}")

    # Detect Python-based keyloggers
    suspicious_modules = ['pynput', 'keyboard', 'pyxhook']
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if proc.info['name'] in ['python', 'python3']:
                cmdline = ' '.join(proc.info.get('cmdline') or [])
                if any(mod in cmdline for mod in suspicious_modules):
                    log(f"⚠️ Python process using suspicious module: {cmdline} (PID: {proc.pid})")
                    found = True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not found:
        log("✅ No behavioral signs of keyloggers found.")

def main():
    log("==== Keylogger Detection Started ====")
    list_processes()
    detect_keylogger_signature()
    detect_behavioral_keylogger()
    log("==== Detection Completed ====")

if __name__ == '__main__':
    main()

