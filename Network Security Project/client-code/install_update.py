import time
import socket
import os
import subprocess
import sys




def main():
    print("Starting installation...")

    # Simulate installation process
    for i in range(100):
        progress = (i + 1)
        sys.stdout.write("\rInstallation progress: [{0}] {1}%".format("#" * (progress // 10), progress))
        sys.stdout.flush()

        
            

    print("\nInstallation complete!")


if __name__ == "__main__":
    main()
