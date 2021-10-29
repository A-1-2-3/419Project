# CLIENT
from threading import Thread
import time
import random
import math
from socket import socket, AF_INET, SOCK_STREAM
# s = socket(AF_INET, SOCK_STREAM)
# s.bind(('10.0.0.173', 41900)) 
server = ('10.0.0.173', 11000)

outsock = socket(AF_INET, SOCK_STREAM)
outsock.bind(('10.0.0.173', 0)) 

# def listen_for_messages():
#     while True:
#         s.listen(1)
#         conn, addr = s.accept()
#         while True:
#             data = conn.recv(1024)
#             if not data: break
#             print("\r[",addr,"]: ",data.decode(),"\n",sep="")
#         conn.close()


def send_message():
    while True:
        try: 
            outsock.connect(server)
            break
        except: 
            print("Unable to connect, retrying in 5 seconds...")
            time.sleep(5)
    print("Type '!q' to leave the program.")
    while True:
        # Send string
        string = input("You: ")
        if string == "!q": 
            exit()
        outsock.sendall(string.encode())

# listen_for_messages()
send_message()
# Thread(target = listen_for_messages).start()
# Thread(target = send_message).start()




# A primality test, based on probability
# Input:  n is the number to test, "tests" is amount of tests to perform
# Returns True if n is composite
# Returns False if n is probably prime
def millerRabin(n,tests):
    # Test that n is not even
    if n%2==0: return True

    # In case tests exceeds the number of integers a such that 1<a<n.
    if tests>(n-2): tests=n-2

    # Generate k and q.
    temp = n-1
    k = 0
    q = temp
    endloop = False
    while endloop==False:
        if temp%2==0:
            k+=1
            q = q//2
            temp = temp//2
        else:
            endloop=True

    # Test some a's.
    a_tested = []
    for everytest in range(0,tests):        
        while True:
            a = random.randint(2,n-1)
            if a not in a_tested:
                a_tested.append(a)
                break
        
        if math.gcd(a,n)>1: return True

        testfailed = False
        if pow(a,q,n)==1: testfailed = True
        for i in range(0,k):
            if pow(a,((pow(2,i))*q),n)==(n-1): testfailed = True
        if testfailed == False: return True

    return False

# status = millerRabin(10000000000000000000000000000000000000121,100)
# if status: print("Composite")
# if not status: print("Probably Prime")
