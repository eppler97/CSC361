import re
import sys
from socket import *
from ssl import *


def main():
    """ Create flags, and cookie list """
    h2 = False
    pw_protected = False
    cookies = []

    # c1 is used to detect connection to SSL
    # c2 is used to detect connection to HTTP/1.1
    # If neither are true, we will not output any data
    c1 = True
    c2 = True
    # Get user input, identify path and host from the args
    if len(sys.argv) != 2:
        print("Please run the program with the following format:")
        print("python SmartClient.py www.uvic.ca")
        exit(1)

    args = sys.argv[1].split('/')
    host = args[0]
    path = ''
    port = 443

    if len(args) > 1:
        path = "/" + args[1]
    else:
        path = "/"

    ######### SSL CONNECTION ##########################################################
    # Setup message and secure socket
    message = "GET " + path + " HTTP/1.1\r\n\r\n"
    context = create_default_context()
    context.set_alpn_protocols(["h2"])
    s = socket(AF_INET, SOCK_STREAM)
    ss = context.wrap_socket(s, server_hostname=host)
    ss.settimeout(10)

    # Try connecting using SSL to detect http2 support
    try:
        print("--- SSL CONNECTION ---")
        ss.connect((host, port))
        if ss.selected_alpn_protocol() == 'h2':
            h2 = True

        # Send a message using TLS, if we get a 401 error code, it's PW protected
        print("--- Sending message ---")
        print(("GET " + path + " HTTP/1.1\r\nHost:" + host + '\n'))
        ss.sendall(("GET " + path + " HTTP/1.1\r\nHost:" + host + "\r\n\r\n").encode())

        # Print out the response, and get error code
        print("--- Message sent, awaiting response ---\n")
        temp = ss.recv(10000)
        data = temp
        while temp:
            temp = ss.recv(10000)
            data += temp
        print_header_body(data.decode())
        if data.decode():
            errcode = get_err_code(data.decode())
        else:
            errcode = 0

        # If we get 401, the address is password protected
        if errcode == '401':
            pw_protected = True

        # Add cookies to list, if any
        cookies.extend(get_cookies(data.decode()))

        ss.close()
        print("--- SSL socket closed ---\n")

    except Exception as e:
        print("Exception: " + str(e))
        print("Unable to connect using SSL.\n")
        c1 = False  # c1 flag indicates no connection was made here

    ######### HTTP/1.1 CONNECTION ##########################################################
    port = 80
    try:
        print("--- HTTP/1.1 CONNECTION ---")
        sock = socket(AF_INET, SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))
        print("--- Sending message ---")
        print(message)
        sock.send(message.encode())
        print("--- Message sent, awaiting response ---")

        temp = sock.recv(10000)
        data = temp

        print_header_body(data.decode())

        # Extend cookie list
        cookies.extend(get_cookies(data.decode()))

        sock.close()

    except Exception as e:
        print(e)
        print("Unable to connect using HTTP/1.1\n")
        c2 = False  # c2 flag indicates no connection was made here

    ######### OUTPUT ##########################################################
    if h2:
        h2support = 'yes'
    else:
        h2support = 'no'
    if pw_protected:
        pwsupport = 'yes'
    else:
        pwsupport = 'no'
    print('--- FINAL RESULTS ---')
    if c1 or c2:
        print('website: ' + host)
        print('1. Supports http2: ' + h2support)
        print('2. List of cookies:')
        for cookie in cookies:
            print(cookie)
        print('3. Password-protected: ' + pwsupport)
    else:
        print("No successful connections made.")


def get_err_code(data):
    pattern = re.compile(r'(\d{3})\s')
    try:
        return re.search(pattern, data).group(0).rstrip(' ')
    except Exception as e:
        return 0


def print_header_body(data):
    data_segmented = data.split("\r\n\r\n")
    print("--- Response Header ---")
    print(data_segmented[0] + '\n')
    if len(data_segmented) > 1:
        print("--- Response Body ---")
        print(data_segmented[1] + '\n')


def get_cookies(data):
    # Takes in a (str) data and parses for cookies, returning a list
    pattern = re.compile(r'Set-Cookie:.*')
    return re.findall(pattern, data)


if __name__ == '__main__':
    main()
