import os
import psutil
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog, ttk
from datetime import datetime
import threading
import platform
import subprocess
import ctypes

IS_WINDOWS = platform.system() == 'Windows'

# File to store logs
DETECTION_LOG_FILE = "keylogger_detection.log"

class KeyloggerDetectionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Keylogger Detection App")
        self.fullscreen = True
        self.ask_before_kill = True

        self.dark_mode = True
        self.root.configure(bg="#1e1e1e")
        if IS_WINDOWS:
            self.root.state('zoomed')
        else:
            self.root.attributes('-zoomed', True)

        # Mode Toggle
        self.mode_toggle = tk.Button(root, text="🌙 Dark Mode", command=self.toggle_mode,
                                     bg="#2c2f33", fg="white", font=("Segoe UI", 9))
        self.mode_toggle.place(relx=0.97, rely=0.01, anchor='ne')

        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=120, height=30,
                                                   bg="#2c2f33", fg="white", insertbackground="white",
                                                   font=("Consolas", 10))
        self.text_area.pack(pady=10, padx=20)

        button_frame = tk.Frame(root, bg="#1e1e1e")
        button_frame.pack(pady=10)

        self.monitor_btn = tk.Button(button_frame, text="🧩 Monitor Processes", command=self.run_in_thread(self.list_processes),
                                     bg="#2c2f33", fg="white", activebackground="#7289da",
                                     font=("Segoe UI", 10, "bold"), width=30, height=2)
        self.monitor_btn.grid(row=0, column=0, padx=10, pady=10)

        self.detect_btn = tk.Button(button_frame, text="🛡️ Detect Keylogger", command=self.run_in_thread(self.detect_keylogger),
                                     bg="#2c2f33", fg="white", activebackground="#7289da",
                                     font=("Segoe UI", 10, "bold"), width=30, height=2)
        self.detect_btn.grid(row=0, column=1, padx=10, pady=10)

        self.behavior_btn = tk.Button(button_frame, text="🔬 Detect Behavior", command=self.run_in_thread(self.detect_behavioral_keylogger),
                                     bg="#2c2f33", fg="white", activebackground="#7289da",
                                     font=("Segoe UI", 10, "bold"), width=30, height=2)
        self.behavior_btn.grid(row=0, column=2, padx=10, pady=10)

        self.export_var = tk.StringVar()
        self.export_dropdown = ttk.Combobox(button_frame, textvariable=self.export_var, width=29, font=("Segoe UI", 10))
        self.export_dropdown['values'] = ("Export as .txt", "Export as .csv", "Export as .pdf")
        self.export_dropdown.current(0)
        self.export_dropdown.grid(row=0, column=3, padx=10, pady=10)

        self.export_btn = tk.Button(button_frame, text="📄 Export Logs", command=self.export_logs,
                                     bg="#2c2f33", fg="white", activebackground="#7289da",
                                     font=("Segoe UI", 10, "bold"), width=30, height=2)
        self.export_btn.grid(row=0, column=4, padx=10, pady=10)

    def toggle_mode(self):
        self.dark_mode = not self.dark_mode
        bg = "#ffffff" if not self.dark_mode else "#1e1e1e"
        fg = "#000000" if not self.dark_mode else "white"
        tbg = "#e0e0e0" if not self.dark_mode else "#2c2f33"
        self.root.configure(bg=bg)
        self.text_area.configure(bg=tbg, fg=fg, insertbackground=fg)
        self.mode_toggle.configure(text="☀️ Light Mode" if not self.dark_mode else "🌙 Dark Mode",
                                   bg=tbg, fg=fg)

    def log(self, message):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        self.text_area.insert(tk.END, log_entry + "\n")
        self.text_area.see(tk.END)
        with open(DETECTION_LOG_FILE, 'a') as f:
            f.write(log_entry + "\n")

    def run_in_thread(self, func):
        def wrapper():
            threading.Thread(target=func).start()
        return wrapper

    def list_processes(self):
        self.log("Listing active processes:")
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                self.log(f"Process: {proc.info['name']} (PID: {proc.info['pid']})")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    def detect_keylogger(self):
        self.log("Detecting potential keyloggers...")
        suspicious_keywords = ['keylog', 'hook', 'logger', 'capture', 'record']
        found = False
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                pname = proc.info['name']
                pexe = proc.info.get('exe', '')
                if any(keyword in (pname or '').lower() for keyword in suspicious_keywords) or \
                   any(keyword in (pexe or '').lower() for keyword in suspicious_keywords):
                    found = True
                    self.log(f"⚠ Suspicious process: {pname} (PID: {proc.pid}) Path: {pexe}")
                    if self.ask_before_kill:
                        answer = messagebox.askyesno("Terminate Process?",
                            f"Suspicious process detected:\n\nName: {pname}\nPID: {proc.pid}\nPath: {pexe}\n\nDo you want to terminate it?")
                        if answer:
                            proc.terminate()
                            self.log(f"⛔ Terminated process: {pname} (PID {proc.pid})")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        if not found:
            self.log("✅ No keylogger found in system.")

    def export_logs(self):
        file_type = self.export_var.get()
        extension = ".txt" if "txt" in file_type else ".csv" if "csv" in file_type else ".pdf"
        filetypes = [("Text Files", "*.txt"), ("CSV Files", "*.csv"), ("PDF Files", "*.pdf")]
        path = filedialog.asksaveasfilename(defaultextension=extension, filetypes=filetypes)
        if not path:
            return
        try:
            with open(DETECTION_LOG_FILE, 'r') as f:
                data = f.read()
            if extension == ".pdf":
                from reportlab.lib.pagesizes import letter
                from reportlab.pdfgen import canvas
                c = canvas.Canvas(path, pagesize=letter)
                textobject = c.beginText(40, 750)
                for line in data.splitlines():
                    textobject.textLine(line)
                c.drawText(textobject)
                c.save()
            else:
                with open(path, 'w') as out:
                    out.write(data)
            self.log(f"Logs exported to {path}")
        except Exception as e:
            self.log(f"Export failed: {e}")

    def detect_behavioral_keylogger(self):
        self.log("🧠 Performing behavioral keylogger detection...")
        found = False

        if not IS_WINDOWS:
            try:
                result = subprocess.run(["lsof", "/dev/input/"], capture_output=True, text=True)
                lines = result.stdout.strip().split("\n")[1:]
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 2:
                        pid = parts[1]
                        pname = parts[0]
                        self.log(f"⚠ Process accessing /dev/input: {pname} (PID: {pid})")
                        found = True
            except Exception as e:
                self.log(f"Behavioral detection (Linux) failed: {e}")

        elif IS_WINDOWS:
            try:
                WH_KEYBOARD_LL = 13
                user32 = ctypes.windll.user32
                hook = user32.SetWindowsHookExW(WH_KEYBOARD_LL, 0, 0, 0)
                if hook:
                    user32.UnhookWindowsHookEx(hook)
                    self.log("⚠ Detected global keyboard hook (Windows) — possible keylogger")
                    found = True
            except Exception as e:
                self.log(f"Behavioral detection (Windows) failed: {e}")

        suspicious_python_modules = ['pynput', 'keyboard', 'pyxhook']
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if proc.info['name'] in ['python', 'python3']:
                    cmdline = ' '.join(proc.info.get('cmdline') or [])
                    if any(mod in cmdline for mod in suspicious_python_modules):
                        self.log(f"⚠ Python process using suspicious module: {cmdline} (PID: {proc.pid})")
                        found = True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if not found:
            self.log("✅ No behavioral signs of keyloggers found.")

if __name__ == '__main__':
    root = tk.Tk()
    app = KeyloggerDetectionApp(root)
    root.mainloop()
