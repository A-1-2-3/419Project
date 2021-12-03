This is an application for creating an end-to-end encrypted chat. Chats are between two people, and both users must be online to chat with one another. All messages are relayed through a central server.

/==============\
| Requirements |
\==============/
Python3 is required, as well as the libraries "argon2-cffi" (for the server) and "blessed" (for the client).
    > pip install argon2-cffi blessed

Running the server program ("relay_server.py") requires the following files in the same directory:
    - crypto.py
    - server_address.json
    - login_info.json

Running the client/user program ("user.py") requires the following files in the same directory:
    - crypto.py
    - server_address.json

The program is designed and intended for Windows 10 machines.

/=======\
| Usage |
\=======/
To start the server, set the server ip/port in "server_address.json", and then simply run 
    > python3 server.py

To start a user instance, first ensure that "server_address.json" has the server's correct ip/port. Then run 
    > python3 user.py
By default, chats will use the "blessed" library to improve the UI; if you want to disable this, add the argument
    > python3 user.py --simple


As the user, you will first be asked if you are registering or logging in. Type "R" or "L" to make your choice, and press enter. Follow the instructions to make an account and/or log in.

Next, you will be asked who you want to speak to. Input the username of your desired conversation partner.
Wait for the other user to come online, and if your desired conversation partner also wishes to speak to you, the ephemeral chat sesion will automatically begin.

While in a chat, type a message and press enter to send.
You can type !help to view available commands:
    "!keys" will print a hash of your chacha key, as well as the shared DH key. Users may verify through some separate channel (or, uh, face-to-face) that they possess the same key.
    "!q" will quit the app.
    "!bad_auth" is for testing purposes. If it prefixes a message, it makes the integrity check fail when the other user receives that message.



/========\
| Design |
\========/
The general design of the program is as follows:
1. Clients first form a connection with the central server, which is a trusted third party.

2. Clients perform a classic Diffie-Hellman key exchange with the server, and obtain a key for a symmetric cipher (ChaCha) that is shared with the server. This will be used to encrypt their passwords when logging in. 

3. Clients log in, registering a new account first if they choose.

4. Once logged in, clients specify who they wish to open a chat with. 

5. When the client's parter is online (and also chooses to speak with the client), then they perform a Diffie-Hellman key exchange through the server and obtain a key for a symmetric cipher (ChaCha), to be used to encrypt the contents of their messages.

6. All messages are sent through the server to be forwarded to the final destination.


/================\
| Internet usage |
\================/
If you wish to connect with users over the Internet (rather than over a local network), you'll have to set the "ip" in "server_address.json" to be the external IP of the machine running the server, and "port" to be an (open/available) port on the server machine. You may need to port-forward and/or modify firewall settings.
Please note that some routers do not support hairpinning (https://en.wikipedia.org/wiki/Hairpinning); if not, clients cannot connect over the Internet when the server is hosted on the same local network as the client. If testing from a single local network, a VPN can be used to help get around this.



















