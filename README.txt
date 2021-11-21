/==============\
| Requirements |
\==============/
Python3 is required, as well as the library "argon2-cffi". The library "blessed" is also highly recommended.
    pip install argon2-cffi blessed

Running the server program ("relay_server.py") requires the following files in the same directory:
    crypto.py
    server_address.json
    login_info.json

Running the client/user program ("user.py") requires the following files in the same directory:
    crypto.py
    server_address.json

The program is designed and intended for Windows 10 machines.

/=======\
| Usage |
\=======/
To start the server, set the server ip/port in "server_address.json", and then simply run 
    python3 server.py

To start a user instance, first ensure that "server_address.json" has the server's ip/port. Then run 
    python3 user.py
If you did not install the "blessed" library, you must use an additional argument:
    python3 user.py --simple


As the user, you will first be asked if you are registering or logging in. Type "R" or "L" respectively, and press enter. Follow the instructions to register and/or log in.

Next, you will be asked who you want to speak to. Input the username of your desired conversation partner.
Wait for the other user to come online, and the ephemeral chat sesion will begin.

While in a chat, you can type !help to view available commands:
    "!keys" will print a hash of your chacha key, as well as the shared DH key. Users may verify through some separate channel (or, uh, face-to-face) that they possess the same key.
    "!q" will quit the app.
    "!bad_auth" is for testing purposes, and makes the integrity check fail when the other user receives that message.



/========\
| Design |
\========/
Clients first form a connection with the central server.

Clients perform a classic Diffie-Hellman key exchange with the server, and obtain a key for a symmetric cipher (ChaCha) to be used to encrypt their passwords when logging in.

Clients log in, registering a new account first if necessary.

Once logged in, clients specify who they wish to open a chat wish. 

When the client's parter is online (and also chooses to speak with the client), then they perform a Diffie-Hellman key exchange and obtain a key for a symmetric cipher (ChaCha), to be used to encrypt the contents of their messages.

All messages are sent through the server to be forwarded to the final destination.




















