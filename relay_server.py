##########################################################################
#                                                                        #
#                              Relay Server                              #
#                                                                        #
##########################################################################
from socket import socket, AF_INET, SOCK_STREAM
from threading import Thread, Lock
from argon2 import PasswordHasher # pip install argon2-cffi
from crypto import * # This is part of the assignment submission
import string
import time
import json

thread_lock = Lock()
password_hasher = PasswordHasher()

with open("server_address.json", 'r') as file:
    server_info = json.load(file)
server = socket(AF_INET, SOCK_STREAM)
server.bind(('', server_info["port"]))


# Dictionary of current connected users. 
# key is the username, all lowercase.
# value is "True" if user is logged in, and is a username if the user has requested a conversation partner.
global online_users
online_users = {}

# For storing messages that need to be relayed.
# key is a username string, all lowercase.
# value is a list, consisting of the message loads to be sent.
global message_queue
message_queue = {}


# Register a user.
def register(login_load):
    username = login_load["user"]

    allowed_chars = set(string.ascii_lowercase + string.ascii_uppercase + string.digits + '_')
    if not set(username) <= allowed_chars:
        return False, "Error: Username invalid; must consist of letters, number, and underscores. Please try again.\n"

    thread_lock.acquire()
    with open("login_info.json", 'r') as file:
        db = json.load(file)

    if username in db.keys():
        thread_lock.release()
        return False, "Error: Username already taken. Please try again.\n"

    # user_salt = password_salt_gen()
    # db[username] = {
    #     "pass": hash_password(login_load["pass"], user_salt),
    #     "salt": user_salt
    #     }
    db[username] = password_hasher.hash(login_load["pass"])
    with open("login_info.json", 'w') as file:
        json.dump(db, file) 

    thread_lock.release()
    return True, "Success: Account created. You may now proceed to login."

# Login a user.
def login(login_load):
    username = login_load["user"]
    thread_lock.acquire()
    with open("login_info.json", 'r') as file:
        db = json.load(file)

    if username not in db.keys():
        thread_lock.release()
        return False, "Error: Username not found. Please try again.\n"

    if username in online_users:
        thread_lock.release()
        return False, "Error: User "+username+" is already logged in.\n"

    # if hash_password(login_load["pass"], db[username]["salt"]) != db[username]["pass"]:
    #     thread_lock.release()
    #     return False, "Error: Incorrect password. Please try again.\n"
    try: password_hasher.verify(db[username], login_load["pass"]);
    except: thread_lock.release(); return False, "Error: Incorrect password. Please try again.\n"

    thread_lock.release()
    online_users[username] = True
    return True, "Successfully logged in."


# Remove a user from the pool of online users.
# def remove_user(user): if user in online_users: del online_users[user];


# Primary client handling function.
def handle_client(conn, addr):  
    this_user = ""
    # Key exchange with user
    try: client_chacha_key = create_secure_channel(conn, addr);
    except Exception as e: close_conn_from_handler(conn, this_user, e); exit();
    # Login the user
    try: this_user = handle_login_and_registration(conn, addr, client_chacha_key)
    except Exception as e: close_conn_from_handler(conn, this_user, e); exit();
    # Relaying messages
    try: begin_message_relay(conn, addr)
    except Exception as e: close_conn_from_handler(conn, this_user, e); exit();

    if this_user in online_users: del online_users[this_user];
    conn.close()

def close_conn_from_handler(conn, this_user, e):
    print("Error, closing connection to ",this_user,": ",e,sep='')
    if this_user in online_users: del online_users[this_user];
    conn.close()

# Use DH key exchange to create a shared secret key with client, for receiving login info
def create_secure_channel(conn, addr):
    my_exponent, my_half_key = create_my_DH_half()
    half_key_load = {
        "source": "Server",
        "dest": "UNREGISTERED",
        "half_key": my_half_key
    }

    user_half_key_load = json.loads(conn.recv(64000))
    conn.send(bytes(json.dumps(half_key_load), encoding='utf-8'))

    full_dh_key = mix_DH_keys(user_half_key_load["half_key"], my_exponent)

    dh_hash = hash_dh(full_dh_key)
    user_dh_hash = json.loads(conn.recv(64000))["dh_hash"]
    conn.send(bytes(json.dumps({"dh_hash": dh_hash}), encoding='utf-8'))

    if dh_hash != user_dh_hash:
        print("Error: Server and client DH key hash did not match. Aborting client connection.")
        conn.close()
        exit()
    else: print("Shared private login key established with", addr)

    return get_chacha_key_from_DH(full_dh_key)


# Handles the client registration and login.
def handle_login_and_registration(conn, addr, client_chacha_key):   
    print("Received connection from",addr)
    while True:
        login_load = json.loads(conn.recv(64000))
        login_load["user"] = login_load["user"].lower()

        if login_load["auth"] != auth_chacha(client_chacha_key, login_load["pass"], login_load["auth_salt"]):
            print("WARNING: Incoming message failed authentication check. Possible tampering or data loss.")
            login_response = {
                "success": False,
                "login_message": "Error - the message authentication check failed. Please resend your request."
            }
            conn.send(bytes(json.dumps(login_response), encoding='utf-8'))
            continue

        login_load["pass"] = bytearray(decrypt_chacha(login_load["pass"], client_chacha_key, login_load["nonce"])).decode('utf-8')

        if login_load["action"] == "login":
            print(addr,"is trying to login as",login_load["user"])
            login_success, login_message = login(login_load)
            login_response = {
                "success": login_success,
                "login_message": login_message
            }
            conn.send(bytes(json.dumps(login_response), encoding='utf-8'))
            if login_success == True:
                print(login_load["user"],"has successfully logged in.")
                return login_load["user"]

        elif login_load["action"] == "register":
            print(addr,"is trying to register as",login_load["user"])
            register_success, register_message = register(login_load)
            login_response = {
                "success": register_success,
                "register_message": register_message
            }
            conn.send(bytes(json.dumps(login_response), encoding='utf-8'))
            if register_success == True: print(addr,"has successfully registered as",login_load["user"]);


# User is successfully logged in. Ask who they want to speak with, and begin relaying messages.
def begin_message_relay(conn, addr):
    chat_info = json.loads(conn.recv(64000))
    client_username = str(chat_info["source"]).lower()
    dest_username = str(chat_info["dest"]).lower()
    message_queue[client_username] = []
    print(chat_info["source"],"has joined the user pool.")
    online_users[client_username] = dest_username

    # Wait for other user to join
    while True:
        if dest_username in online_users:
            if online_users[dest_username] == client_username: 
                print(chat_info["source"],"and",chat_info["dest"],"are both online, connecting...")
                initialization_load = {
                    "source": "Server",
                    "dest": chat_info["dest"],
                    "message": "The other user has connected; chat initialized.",
                    "success": True
                }
                conn.sendall(bytes(json.dumps(initialization_load), encoding='utf-8'))
                break

        # Check that the user is still online.
        # If they forcibly close the program, we don't want to be in an infinite loop
        conn.settimeout(1)
        try:
            conn.recv(64000)
        except Exception as e:
            if "timed out" in str(e) or "timeout" in str(e):
                pass
            else:
                print("Seems user",chat_info["source"],"has disconnected.")
                conn.close()
                return
        conn.settimeout(None)

    # Connection established. Begin acting as relay
    Thread(target = grab_messages_from_queue, args = (conn, client_username,)).start()

    # Diffie-Hellman Key Exchange
    print("Waiting to receive DH half-key from",chat_info["source"])
    dh_half_key_load = json.loads(conn.recv(64000))
    print("Received DH half-key from",chat_info["source"])
    add_message_to_queue(dh_half_key_load)

    # Sending/receiving text messages
    print("DH key exchange complete. Beginning chat relay.")
    while True:
        try: data = conn.recv(64000)
        except: break
        if not data: break
        add_message_to_queue(json.loads(data))

    # The other destination user has left. Let this source client know.
    if client_username in online_users: del online_users[client_username];
    farewell_message = {
        "source": "Server",
        "dest": chat_info["dest"],
        "message": "The other user has disconnected; chat nonfunctional."
    }
    add_message_to_queue(farewell_message)
    print(client_username,"has left. Closing connection.")
    time.sleep(3)
    conn.close()
    return


def grab_messages_from_queue(conn, username):
    while True:
        if len(message_queue[username]) != 0:
            message_load = message_queue[username].pop(0)
            if message_load["dest"].lower() in online_users:
                conn.sendall(bytes(json.dumps(message_load), encoding='utf-8'))
                print("Relayed load from",message_load["source"],"to",message_load["dest"])
        if conn.fileno() == -1: print("grab_message_from_queue thread closing"); return;


def add_message_to_queue(message_load):
    dest_user = message_load["dest"].lower()
    message_queue[dest_user].append(message_load)
    # if "message" in message_load: print("[",message_load["source"],"]: ",message_load["message"],sep="");
    return



print("Server is up and listening for connections on",server.getsockname())
server.listen(3)
while True:
    conn, addr = server.accept()    
    Thread(target = handle_client, args = (conn, addr,)).start()
server.close()

