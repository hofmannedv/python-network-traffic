
# original Python code by Raul Becerra
# simplified by Frank Hofmann

import subprocess

ETHERNET_ADAPTER = "wlan0"

process = subprocess.Popen(
    ['sudo', 'tcpdump', '-XX', '-i', ETHERNET_ADAPTER], 
    bufsize=-1, 
    stdout=subprocess.PIPE
)

for linne in iter(process.stdout.readline, ''):
    linne = linne.decode('utf-8')
    print(linne)
