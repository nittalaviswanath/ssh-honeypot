import socket
import threading
import paramiko
import os
HOST_KEY = paramiko.RSAKey(filename="keys/server.key")
class SSHServer(paramiko.ServerInterface):

    def check_auth_password(self, username, password):
        print(f"[+] Login attempt")
        print(f"    Username : {username}")
        print(f"    Password : {password}")

        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):

        if kind == "session":
            return paramiko.OPEN_SUCCEEDED

        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
HOST = "0.0.0.0"

PORT = 2222

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server.bind((HOST, PORT))

server.listen(100)

print(f"[+] Honeypot listening on {HOST}:{PORT}")

while True:

    client, addr = server.accept()

    print(f"[+] New connection from {addr[0]}:{addr[1]}")

    client.close()
