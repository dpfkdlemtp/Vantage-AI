import pty
import os

pid, fd = pty.fork()
if pid == 0:
    # Child process
    os.execlp("ffuf", "ffuf", "-u", "http://127.0.0.1:8000/FUZZ", "-w", "wordlists/test.txt", "-t", "1")
else:
    # Parent process
    try:
        while True:
            output = os.read(fd, 1024)
            if output:
                print(f"PTY OUTPUT: {repr(output)}")
            else:
                break
    except OSError:
        pass
