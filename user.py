##########################################################################
#                                                                        #
#                              User Client                               #
#                                                                        #
##########################################################################
from socket import socket, AF_INET, SOCK_STREAM
from argparse import ArgumentParser
from threading import Thread
from getpass import getpass
from crypto import * # This is part of the assignment submission
import string
import time
import json
import os


# Setting up the socket with the address of the central server (through which messages are routed).
with open("server_address.json", 'r') as file:
    server_info = json.load(file)
RELAY_SERVER = (server_info["ip"], server_info["port"])
sock = socket(AF_INET, SOCK_STREAM)



# A function that takes in a message as a string, and sends it to the server.
def send_encrypted_message(message, intentional_bad_auth=False):
    # Encrypt message.
    nonce = nonce_gen()
    message = encrypt_chacha(message.encode('utf-8'), chacha_key, nonce)
    auth = auth_chacha(auth_key, message)

    if intentional_bad_auth == True: auth = "This is an intentionally bad auth for testing";

    message_load = {
        "source": my_username,
        "dest": destination_user,
        "message": message,
        "nonce": nonce,
        "auth": auth
    }
    sock.sendall(bytes(json.dumps(message_load), encoding='utf-8'))

# Runs on Receiving thread.
# Waits for incoming data, then gets and prints the message.
def user_receive_messages():
    while True:
        try:
            data = sock.recv(64000)
        except:
            print("Conversation closed.")
            sock.close()
            exit()
        message_load = json.loads(data)

        # Check if it's a message from the Server
        # The only message a server will send now is the farewell message, so the other user is gone, and we should close the connection.
        if message_load["source"] == "Server":
            print("[",message_load["source"],"]: ",message_load["message"],sep="")
            sock.close(); exit();
            continue

        # Verify the message's authentication.
        # If it fails, decrypt and print output to a text file.
        r_auth = auth_chacha(auth_key, message_load["message"])
        if r_auth != message_load["auth"]:
            print("WARNING: Incoming message failed authentication check. Possible tampering or data loss.")
            # with open("messages_that_failed_authentication.txt", 'a') as file:
            #     entry = "=======================================\nTimestamp: " + time.strftime("%B %d, %Y at %H:%M:%S") + "\n"
            #     entry += "From '" + message_load["source"] + "' to '" + message_load["dest"] + "'" + "\n"
            #     entry += "Decrypted: " + bytearray(decrypt_chacha(message_load["message"], chacha_key, message_load["nonce"])).decode('utf-8') + "\n"
            #     file.write(entry)
            continue

        decrypted_message = bytearray(decrypt_chacha(message_load["message"], chacha_key, message_load["nonce"])).decode('utf-8')
        print("[",destination_user,"]: ",decrypted_message,sep="")



# Runs on Sending thread.
# Allows the user to enter in a message.
def user_send_messages():
    os.system('cls')
    print("Type '!q' to quit, or '!help' for help.")
    while True:
        # Read user message.
        message = input("You: ")
        if sock.fileno() == -1:
            print("Connection has been closed.")
            exit()
        intentional_bad_auth = False
        if message == "": continue;
        if message[0] == '!':
            if message == "!q": sock.close(); exit();
            if message == "!help": print("- Type '!q' to quit\n- Type '!keys' to print your diffie-hellman and chacha key\n- Type '!bad_auth' before a message to test out sending a message with broken authentication")
            if message == "!keys": print("================\nDH Hash:    ",dh_key_hash,"\nChaCha Hash:",chacha_key_hash,"\n================"); continue;
            if message[:9] == "!bad_auth":
                message = message[9:]
                intentional_bad_auth = True

        send_encrypted_message(message, intentional_bad_auth)


# Function for the blessed interface option.
# Takes a list of strings, and cuts them down to fit within the terminal.
def trim_messages(m_list):
    output = []
    for m in m_list:
        while len(m) > term.width - 2:
            output.append(m[0 : term.width-2])
            m = m[term.width-2 : ]
        output.append(m)
    return output

# Function for the blessed interface option.
# Adds a message to the list of saved messages, and updates the screen.
# Input is a list of strings.
def update_message_list(inp):
    new_msg_list = trim_messages(inp)
    while len(message_list) + len(new_msg_list) >= term.height - 1:
        message_list.pop(0)
    for msg in new_msg_list:
        message_list.append(msg)
    with term.location(0,0):
        for msg in message_list:
            print(term.clear_bol, msg, term.clear_eol)

# Function for the blessed interface option.
# Runs on the Receiving thread.
# Waits for incoming data, then gets and prints the message.
def blessed_user_receive_messages():
    while True:
        try:
            data = sock.recv(64000)
        except:
            print(term.clear, "Conversation closed.")
            sock.close()
            exit()
        message_load = json.loads(data)

        # Check if it's a message from the Server
        # The only message a server will send now is the farewell message, so the other user is gone, and we should close the connection.
        if message_load["source"] == "Server":
            print(term.clear, "[",message_load["source"],"]: ",message_load["message"],sep="")
            sock.close(); exit();
            continue

        # Verify the message's authentication.
        # If it fails, decrypt and print output to a text file.
        r_auth = auth_chacha(auth_key, message_load["message"])
        if r_auth != message_load["auth"]:
            m = "WARNING: Incoming message failed authentication check. Possible tampering or data loss."           
            # with open("messages_that_failed_authentication.txt", 'a') as file:
            #     entry = "=======================================\nTimestamp: " + time.strftime("%B %d, %Y at %H:%M:%S") + "\n"
            #     entry += "From '" + message_load["source"] + "' to '" + message_load["dest"] + "'" + "\n"
            #     entry += "Decrypted: " + bytearray(decrypt_chacha(message_load["message"], chacha_key, message_load["nonce"])).decode('utf-8') + "\n"
            #     file.write(entry)
            update_message_list([m])
            continue

        decrypted_message = bytearray(decrypt_chacha(message_load["message"], chacha_key, message_load["nonce"])).decode('utf-8')
        m = "[" + destination_user + "]: " + decrypted_message

        update_message_list([m])

# Function for the blessed interface option.
# Updates/prints the text entry zone at the bottom of the screen.
def print_text_entry_box(message):
    marker = ">>>"
    # separator = "=================================="
    separator = ""
    with term.location(0, term.height - 2): print(term.clear_bol,    separator,    term.clear_eol, end="")
    with term.location(0, term.height - 1): print(term.clear_bol, marker, message, term.clear_eol, end="")

# Function for the blessed interface option.
# Runs on the Sending thread.
# Allows the user to type a message, charcter by character, at the bottom of the screen.
def blessed_user_send_messages():
    with term.hidden_cursor():
        user_prefix = "[" + my_username + "]: "
        msg = ""
        print_text_entry_box(msg)
        with term.cbreak():
            val = u''
            while True:
                if sock.fileno() == -1:
                    print(term.clear, "Connection has been closed.")
                    exit()
                val = term.inkey()
                if val.is_sequence:
                    if val.code ==  343: # ENTER
                        if msg == "" or str.isspace(msg): pass; # Empty message
                        elif msg[0] == '!': 
                            if msg == '!q': print(term.clear); sock.close(); exit();
                            elif msg == "!help":
                                update_message_list(["- Type '!q' to quit", "- Type '!keys' to print your diffie-hellman and chacha key", "- Type '!bad_auth' before a message to test out sending a message with broken authentication"])
                            elif msg == "!keys":
                                update_message_list(["================", "DH Hash:     "+dh_key_hash, "ChaCha Hash: "+chacha_key_hash, "================"])
                            elif msg[:10] == "!bad_auth ":
                                if msg[10:] == "" or str.isspace(msg[10:]): pass;
                                else:
                                    update_message_list([user_prefix + msg[10:]])
                                    msg = msg[10:]
                                    send_encrypted_message(msg, True)
                        else: 
                            update_message_list([user_prefix + msg])
                            send_encrypted_message(msg)
                        msg = ""
                        print_text_entry_box(msg)
                    elif val.code == 263: # BACKSPACE
                        if len(msg) > 0:
                            msg = msg[0:len(msg)-1]
                            print_text_entry_box(msg)
                elif len(msg) + 6 >= term.width: pass; # Hit the length of the terminal; just cap message length here  for 
                elif val:
                    msg += val
                    print_text_entry_box(msg)

#######################################################################################################################################                    
#######################################################################################################################################                    
#######################################################################################################################################                    

# The process for performing a DH key exchange with the destination user (through the central server/trusted third party).
# The shared DH key will create the symmetric key (ChaCha cipher), to be used for sending/receiving messages.
def dh_handshake():
    my_exponent, my_half_key = create_my_DH_half()
    half_key_load = {
        "source": my_username,
        "dest": destination_user,
        "half_key": my_half_key
    }
    sock.send(bytes(json.dumps(half_key_load), encoding='utf-8'))

    print("Waiting for other user's half-key")
    other_key_load = json.loads(sock.recv(64000))
    print("Received other key")

    full_dh_key = mix_DH_keys(other_key_load["half_key"], my_exponent)

    return get_chacha_key_from_DH(full_dh_key), get_hmac_key_from_dh(full_dh_key), hash_dh(full_dh_key)

# The process for performing a DH key exchange with the central server/trusted third party.
# The shared DH key will create a symmetric key (ChaCha cipher), to be used for sending the user's password to the server.
def server_dh_handshake():
    my_exponent, my_half_key = create_my_DH_half()
    half_key_load = {
        "source": "UNREGISTERED",
        "dest": "Server",
        "half_key": my_half_key
    }

    sock.send(bytes(json.dumps(half_key_load), encoding='utf-8'))
    other_key_load = json.loads(sock.recv(64000))

    full_dh_key = mix_DH_keys(other_key_load["half_key"], my_exponent)

    dh_hash = hash_dh(full_dh_key)
    sock.send(bytes(json.dumps({"dh_hash": dh_hash}), encoding='utf-8'))
    if dh_hash != json.loads(sock.recv(64000))["dh_hash"]:
        print("Error: Server and client DH key hash did not match. Aborting program.")
        sock.close()
        exit()
    else: print("Secure communications established with server.")

    return get_chacha_key_from_DH(full_dh_key), get_hmac_key_from_dh(full_dh_key), dh_hash

# For logging in; encrypts a password and returns a dictionary ready to be sent to the server.
def get_encrypted_credentials(action, user, password):
    password = hash_string(password)
    nonce = nonce_gen()
    password = encrypt_chacha(password.encode('utf-8'), server_chacha_key, nonce)
    auth = auth_chacha(server_auth_key, password)

    load = {
        "action": action,
        "user": user,
        "pass": password,
        "nonce": nonce,
        "auth": auth
    }
    return load

# For registering a new account with the server.
def register():
    allowed_chars = set(string.ascii_lowercase + string.ascii_uppercase + string.digits + '_')
    while True:
        desired_user = input("What username would you like?\nuser: ")
        if not set(desired_user) <= allowed_chars:
            print("The username may only contain letters, numbers, and underscores.")
            continue
        print("What password do you want?")
        desired_pass = getpass("pass: ")
        if len(desired_pass) == 0:
            print("Error: Password must contain at least 1 character")
            continue
        print("Please enter the password again:")
        desired_pass_check = getpass("pass: ")
        if desired_pass != desired_pass_check:
            print("Error: Passwords do not match.")
            continue
        login_load = get_encrypted_credentials("register", desired_user, desired_pass)
        sock.send(bytes(json.dumps(login_load), encoding='utf-8'))

        login_response = json.loads(sock.recv(64000))
        print("\n",login_response["register_message"], sep='')
        if login_response["success"] == True:
            return 


# For logging in with the server.
def login():
    while True:
        print("Please enter your login information.")
        login_user = input("user: ")
        login_pass = getpass("pass: ")
        login_load = get_encrypted_credentials("login", login_user, login_pass)
        sock.send(bytes(json.dumps(login_load), encoding='utf-8'))

        login_response = json.loads(sock.recv(64000))
        print(login_response["login_message"])
        if login_response["success"] == True:
            return login_user

# After a user is logged in, this function takes place until the user is connected with their desired partner.
def connect_users():
    destination_user = input("\nWho do you want to talk with?\n")
    while True:
        if destination_user.lower() != my_username.lower(): break
        else: destination_user = input("Error: Cannot connect to yourself. Please enter the username of the person you want to talk to:\n")

    chat_request_load = {
        "source": my_username,
        "dest": destination_user,
        "sockinfo": sock.getsockname()
    }
    sock.send(bytes(json.dumps(chat_request_load),encoding='utf-8'))
    print("Sent info and request to chat with",destination_user,"to central server. Awaiting response...")

    data = sock.recv(64000)
    initialization_load = json.loads(data)
    if initialization_load["success"] != True: print("Error: Unexpected error from server, failed to connect to other user!")
    print("[",initialization_load["source"]," -> ",initialization_load["dest"],"]: ",initialization_load["message"],sep="")
    return destination_user




#######################################################################################################################################                    
#######################################################################################################################################                    
#######################################################################################################################################                    





# If the argument is added, we will use the simple interface (without the 'blessed' library)
parser = ArgumentParser()
parser.add_argument('-s', '-simple', '--s', '--simple', action="store_false", dest="use_blessed_interface", default=True)
args = parser.parse_args()




# Attempt to connect to central server
while True:
    try: sock.connect(RELAY_SERVER); print(); break;
    except: 
        print("Unable to connect to central server, retrying in 3 seconds...", end='\r')
        time.sleep(1)
        print("Unable to connect to central server, retrying in 2 seconds...", end='\r')
        time.sleep(1)
        print("Unable to connect to central server, retrying in 1 seconds...", end='\r')
        time.sleep(1)
        print("Unable to connect to central server, trying again............", end='\r')


# Perform key exchange to derive shared symmetic key between client/server for login/registration
server_chacha_key, server_auth_key, server_dh_key_hash = server_dh_handshake()


# Login the user, registering an account first if requested
login_action = input("Welcome! Are you logging in (L) or registering (R)? ")
while True:
    if login_action.upper() == "R" or login_action.upper() == "REGISTER":
        register()
        my_username = login()
        break
    elif login_action.upper() == "L" or login_action.upper() == "LOGIN":
        my_username = login()
        break
    else: login_action = input("Error - input not recognized. Please type 'R' for registration or 'L' for login. ")


# Ask user who they want to talk with, and connect them
destination_user = connect_users()

# We assume that the two users have no preshared secret, and perform a Diffie-Hellman key exchange
# Server is trusted third party, assumption of no person-in-the-middle attack
print("Beginning DH handshake.")
chacha_key, auth_key, dh_key_hash = dh_handshake()
print("Successfully calculated DH key, as well as the chacha key.")
chacha_key_hash = hash_chacha(chacha_key)







if args.use_blessed_interface == False:
    try:
        Thread(target = user_receive_messages).start() # Receiving thread
        Thread(target = user_send_messages).start()    # Sending thread
    except (KeyboardInterrupt, SystemExit):
        sock.close()
        sys.exit()

else:
    from blessed import Terminal  # pip install blessed
    term = Terminal()
    print(term.clear)
    message_list = ["Type '!q' to quit or '!help' for help."]
    print(message_list[0])    
    try:
        Thread(target=blessed_user_receive_messages).start() # Receiving thread
        Thread(target=blessed_user_send_messages).start()    # Sending thread
    except (KeyboardInterrupt, SystemExit):
        print(term.clear())
        sock.close()
        sys.exit()
