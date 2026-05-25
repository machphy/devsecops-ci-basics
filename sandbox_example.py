# sandbox_example.py
import subprocess

# Example: Run untrusted Python code in a sandbox using Firejail (Linux)
try:
    result = subprocess.run(
        ["firejail", "--net=none", "python3", "untrusted_script.py"],
        capture_output=True, text=True, timeout=10
    )
    print("Sandboxed output:", result.stdout)
except Exception as e:
    print("Sandbox error:", e)

# Note: Requires Firejail installed and an 'untrusted_script.py' file.
# For Docker-based sandboxing, see the shell example in the text file.
