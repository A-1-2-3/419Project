# SERVER
import _thread
from socket import socket, AF_INET, SOCK_STREAM
server = socket(AF_INET, SOCK_STREAM)
server.bind(('', 11000))

def listen_for_messages(conn, addr):
    print("Received connection from",addr)
    while True:
        try: data = conn.recv(1024)
        except: break
        if not data: break
        print("[",addr,"]: ",data.decode(),sep="")
    print("User has left.")
    conn.close()
    return

# def forward_message():

server.listen(3)
while True:
    conn, addr = server.accept()    
    _thread.start_new_thread(listen_for_messages, (conn, addr,))
server.close()

