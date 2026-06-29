import subprocess
import threading

def read_stream(stream):
    for line in stream:
        print(f"OUT: {line.strip()}")

proc = subprocess.Popen(
    ["nmap", "scanme.nmap.org"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    bufsize=1
)

t = threading.Thread(target=read_stream, args=(proc.stdout,))
t.start()
proc.wait()
t.join()
