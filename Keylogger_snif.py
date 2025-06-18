import os
import psutil
import ctypes
import threading
import logging
import socket
from datetime import datetime
import time
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
from cryptography.fernet import Fernet
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from reportlab.lib import colors
from PIL import Image, ImageTk
from tkinter import ttk
import platform

# File paths
DETECTION_LOG_FILE = "keylogger_detection.log"
LOGIN_HISTORY_FILE = "login_history.log"
KEY_FILE = "secret.key"
LOGO_FILE = "logo.png"
ICON_FILE = "logo.ico"

IS_WINDOWS = platform.system() == 'Windows'

# Generate or load encryption key
if not os.path.exists(KEY_FILE):
    with open(KEY_FILE, 'wb') as f:
        f.write(Fernet.generate_key())
with open(KEY_FILE, 'rb') as f:
    key = f.read()
fernet = Fernet(key)

def save_login():
    user = os.getlogin()
    ip = socket.gethostbyname(socket.gethostname())
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    data = f"User: {user}, IP: {ip}, Logged in at: {now}\n"
    encrypted = fernet.encrypt(data.encode())
    with open(LOGIN_HISTORY_FILE, 'ab') as f:
        f.write(encrypted + b'\n')
save_login()

def decrypt_login_history():
    if not os.path.exists(LOGIN_HISTORY_FILE):
        return ""
    with open(LOGIN_HISTORY_FILE, 'rb') as f:
        lines = f.readlines()
    output = ""
    for line in lines:
        try:
            decrypted = fernet.decrypt(line.strip()).decode()
            output += decrypted + "\n"
        except:
            continue
    return output

logging.basicConfig(filename=DETECTION_LOG_FILE, level=logging.INFO,
                    format="%(asctime)s - %(levelname)s - %(message)s")

if IS_WINDOWS:
    WH_KEYBOARD_LL = 13
    KERNEL32 = ctypes.windll.kernel32

class KeyloggerDetectionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Keylogger Detection App")

        if IS_WINDOWS:
            self.root.state('zoomed')
        else:
            self.root.attributes('-zoomed', True)

        self.fullscreen = True
        self.root.configure(bg="#1e1e1e")

        if os.path.exists(ICON_FILE) and IS_WINDOWS:
            self.root.iconbitmap(ICON_FILE)

        if os.path.exists(LOGO_FILE):
            logo_img = Image.open(LOGO_FILE)
            logo_img = logo_img.resize((150, 75), Image.ANTIALIAS)
            self.logo = ImageTk.PhotoImage(logo_img)
            tk.Label(root, image=self.logo, bg="#1e1e1e").pack(pady=10)

        self.text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=120, height=30,
                                                   bg="#2c2f33", fg="white", insertbackground="white",
                                                   font=("Consolas", 10))
        self.text_area.pack(pady=10, padx=20)

        button_frame = tk.Frame(root, bg="#1e1e1e")
        button_frame.pack(pady=10)

        self.buttons = [
            ("Detect Hooks", self.run_in_thread(self.detect_hooks), "🛡️", "Alt-d"),
            ("List Processes", self.run_in_thread(self.list_processes_and_dlls), "📋", "Alt-p"),
            ("HoneyID Simulation", self.run_in_thread(self.honeyid_simulation), "🐝", "Alt-h"),
            ("Analyze Behavior", self.run_in_thread(self.detect_suspicious_behavior), "🔍", "Alt-a"),
            ("Clear Display", self.clear_display, "🧹", "Alt-c"),
            ("Clear Log Files", self.clear_log_files, "🗑️", "Alt-l"),
            ("Export Logs (.txt)", self.export_logs, "📄", "Alt-t"),
            ("Export Logs (.pdf)", self.export_logs_to_pdf, "📑", "Alt-f"),
            ("Toggle Fullscreen", self.toggle_fullscreen, "🖥️", "Alt-s"),
        ]

        for i, (label, command, icon, shortcut) in enumerate(self.buttons):
            btn = tk.Button(button_frame,
                            text=f"{icon} {label}",
                            command=command,
                            bg="#2c2f33",
                            fg="white",
                            activebackground="#7289da",
                            activeforeground="white",
                            relief=tk.FLAT,
                            font=("Segoe UI", 10, "bold"),
                            width=25,
                            height=2)
            row, col = divmod(i, 3)
            btn.grid(row=row, column=col, padx=10, pady=8, sticky="nsew")
            self.root.bind_all(f"<{shortcut}>", lambda e, cmd=command: cmd())
            CreateToolTip(btn, label)

    def log(self, message):
        self.text_area.insert(tk.END, f"{message}\n")
        self.text_area.see(tk.END)
        logging.info(message)

    def warn(self, message):
        self.text_area.insert(tk.END, f"⚠ {message}\n")
        self.text_area.see(tk.END)
        logging.warning(message)

    def run_in_thread(self, func):
        def wrapper():
            threading.Thread(target=func).start()
        return wrapper

    def detect_hooks(self):
        if not IS_WINDOWS:
            self.warn("Hook detection is only supported on Windows.")
            return
        try:
            user32 = ctypes.windll.user32
            hook_id = user32.SetWindowsHookExW(WH_KEYBOARD_LL, None, KERNEL32.GetModuleHandleW(None), 0)
            if hook_id:
                self.warn(f"Suspicious hook detected. Hook ID: {hook_id}")
            else:
                self.log("No suspicious hooks detected.")
        except Exception as e:
            self.warn(f"Error in detect_hooks: {e}")

    def list_processes_and_dlls(self):
        suspicious_keywords = ["keylog", "hook", "logger", "capture", "record"]
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    pname = proc.info['name']
                    pid = proc.info['pid']
                    pexe = proc.info.get('exe', 'Unknown')

                    if any(keyword in (pname or "").lower() for keyword in suspicious_keywords) or \
                       any(keyword in (pexe or "").lower() for keyword in suspicious_keywords):
                        self.warn(f"⚠ Suspicious process detected: {pname}, PID={pid}, Path={pexe}")
                        answer = messagebox.askyesno("Terminate Process?",
                            f"Suspicious process detected:\n\nName: {pname}\nPID: {pid}\nPath: {pexe}\n\nDo you want to terminate it?")
                        if answer:
                            proc.terminate()
                            self.log(f"⛔ Terminated process: {pname} (PID {pid})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            self.warn(f"Error in process detection: {e}")

    def honeyid_simulation(self):
        try:
            for i in range(5):
                bogus_key = chr(65 + i)
                self.log(f"Generated bogus key event: {bogus_key}")
                time.sleep(1)
        except Exception as e:
            self.warn(f"Error in honeyid_simulation: {e}")

    def detect_suspicious_behavior(self):
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    suspicious = False
                    conn_info = ""
                    log_info = ""

                    for conn in proc.connections(kind='inet'):
                        if conn.status == psutil.CONN_ESTABLISHED:
                            conn_info += f"Active Connection: {conn.laddr}\n"
                            suspicious = True

                    for mmap in proc.memory_maps():
                        if 'log' in mmap.path.lower():
                            log_info += f"Log File: {mmap.path}\n"
                            suspicious = True

                    if suspicious:
                        self.warn(f"⚠ Suspicious activity in {proc.info['name']} (PID {proc.pid})")
                        answer = messagebox.askyesno("Terminate Suspicious Process?",
                            f"{proc.info['name']} (PID {proc.pid}) shows suspicious behavior.\n\n{conn_info}{log_info}\nDo you want to terminate it?")
                        if answer:
                            proc.terminate()
                            self.log(f"⛔ Terminated process: {proc.info['name']} (PID {proc.pid})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            self.warn(f"Error in behavior detection: {e}")

    def clear_display(self):
        self.text_area.delete(1.0, tk.END)

    def clear_log_files(self):
        open(DETECTION_LOG_FILE, 'w').close()
        open(LOGIN_HISTORY_FILE, 'wb').close()
        self.log("Log files cleared.")

    def export_logs(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if not path:
            return
        try:
            with open(DETECTION_LOG_FILE, 'r') as det_log:
                detection_data = det_log.read()
            login_data = decrypt_login_history()
            with open(path, 'w') as f:
                f.write("==== Keylogger Detection Log ====\n")
                f.write(detection_data + "\n")
                f.write("==== Login History Log ====\n")
                f.write(login_data)
            self.log(f"Logs exported to: {path}")
        except Exception as e:
            self.warn(f"Log export failed: {e}")

    def export_logs_to_pdf(self):
        try:
            export_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF Files", "*.pdf")])
            if not export_path:
                return

            with open(DETECTION_LOG_FILE, "r") as detection_log:
                detection_data = detection_log.read()
            login_data = decrypt_login_history()

            c = canvas.Canvas(export_path, pagesize=letter)
            width, height = letter
            margin = 40
            y_pos = height - margin

            if os.path.exists(LOGO_FILE):
                logo = ImageReader(LOGO_FILE)
                c.drawImage(logo, width / 2 - 50, y_pos - 60, width=100, height=50)
                y_pos -= 70

            c.setFont("Helvetica-Bold", 16)
            c.setFillColor(colors.darkblue)
            c.drawCentredString(width / 2, y_pos, "Keylogger Detection Report")
            y_pos -= 30

            c.setFont("Helvetica", 10)
            c.setFillColor(colors.gray)
            c.drawCentredString(width / 2, y_pos, f"Exported: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            y_pos -= 40

            def draw_block(title, content):
                nonlocal y_pos
                c.setFillColor(colors.whitesmoke)
                c.setFont("Helvetica-Bold", 12)
                c.drawString(margin, y_pos, title)
                y_pos -= 20
                c.setFont("Courier", 9)
                c.setFillColor(colors.black)
                for line in content.splitlines():
                    c.drawString(margin, y_pos, line)
                    y_pos -= 12
                    if y_pos < 50:
                        c.showPage()
                        y_pos = height - margin

            draw_block("Keylogger Detection Log", detection_data)
            draw_block("Login History Log", login_data)

            c.setFont("Helvetica-Oblique", 8)
            c.drawRightString(width - margin, 15, "Page 1")
            c.save()

            self.log(f"Logs exported as PDF: {export_path}")
        except Exception as e:
            self.warn(f"PDF Export failed: {e}")

    def toggle_fullscreen(self):
        self.fullscreen = not self.fullscreen
        self.root.attributes("-fullscreen", self.fullscreen)

class CreateToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        widget.bind("<Enter>", self.show_tip)
        widget.bind("<Leave>", self.hide_tip)

    def show_tip(self, event=None):
        if self.tip_window or not self.text:
            return
        x, y, _, cy = self.widget.bbox("insert")
        x = x + self.widget.winfo_rootx() + 40
        y = y + cy + self.widget.winfo_rooty() + 20
        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, background="#ffffe0",
                         relief=tk.SOLID, borderwidth=1,
                         font=("tahoma", "8", "normal"))
        label.pack(ipadx=6)

    def hide_tip(self, event=None):
        if self.tip_window:
            self.tip_window.destroy()
            self.tip_window = None

if __name__ == "__main__":
    root = tk.Tk()
    app = KeyloggerDetectionApp(root)
    root.mainloop()
