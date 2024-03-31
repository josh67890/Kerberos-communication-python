import socket, size, codes, crypty, struct, os

VERSION = 24

client_details_file = "me.info"
servers_details_file = "srv.info"
message_server_file = 'msg.info'

def get_client_details_from_meinfo_file():
    details = {}
    registered = False
    try:
        details_file = open(client_details_file, 'r')

        details['name'] = details_file.readline().strip()
        details['uuid'] = details_file.readline().strip()
        details_file.close()
        if not details['name'] and details['uuid']:
            raise Exception()
        registered = True

    except Exception:
        print("seems like your'e not registered yet.\nplease enter your client name here")
        client_name = input().strip()[:size.name-1]
        # f = open(client_details_file, 'w')       UNNECESSARY - will be written to file in register procedure 
        # f.write(client_name+'\n')
        # f.close()
        details['name'] = client_name
    

    return details, registered


def get_server_and_kdc_details():
    servers_details = {'server':{}, 'kdc':{}}
    try:
        servers_file = open(servers_details_file, 'r')

        line = servers_file.readline().strip()
        ind = line.find(':')
        addr, port = line[:ind], int(line[ind+1:])
        if not addr and port:
            raise Exception()
        servers_details['kdc'] = {'address':addr, 'port':port}

        line = servers_file.readline().strip()
        ind = line.find(':')
        addr, port = line[:ind], int(line[ind+1:])
        if not addr and port:
            raise Exception()
        servers_details["server"] = {'address':addr, 'port':port}
        
    except Exception:
        print(f"error while trying to read from {servers_details_file}")

    finally:
        servers_file.close()
    
    return servers_details

#unnecessary?
# def determine_action_from_user():
#     action = input("please type what action to take (type 'register' or 'message')\n").strip()
#     while action not in ('message', 'register'):
#         action = input("invalid input. please try again ('register' or 'message' only, please)\n").strip()
#     return action


def construct_register_request(client):
    password = input('please enter your password here - it can be up to 254 chars long').strip()[:size.password-1] # enforces max length of 254+null terminator 
    b_password = password.encode('utf-8').ljust(size.password,b'\0') # null termination
    b_name = client['name'].encode('utf-8').ljust(size.name, b'\0') 
    payload = b_name+b_password
    header = construct_client_header('0'*32, VERSION, codes.cl_reg, len(payload))
    return header+payload


def register_client(client, socket):
    # register with kdc, and obtain uuid
    request = construct_register_request(client)
    padded_request = request.ljust(size.pack, b'\0')

    socket.sendall(padded_request)

    # write uuid to client_details_file  
    response = socket.recv(size.pack)
    unpacked_response = proccess_response_from_kdc(response, register = True)

    # add uuid to client_details dict
    client['uuid'] = unpacked_response

    #write details to me.info
    with open(client_details_file, 'w') as file:
        file.write(client['name']+'\n'+client['uuid'])
    
def get_server_id():  
    with open(message_server_file, 'r') as f:
        id = ''
        for i in range(3):
            id = f.readline().strip()
    if not id:
        raise Exception(f'no data for server id. check file "{message_server_file}"')
    return id



def construct_client_header(client_id, version, code, payload_size):
    b_client_id = bytes.fromhex(client_id)
    rest = struct.pack('<BHI', version, code, payload_size)
    return b_client_id+rest


def construct_message_for_server(message, aes):
    msg_iv = os.urandom(16)
    encrypted_message = crypty.encrypt(message.encode('utf-8'), aes, msg_iv)
    b_size = struct.pack("<I", len(encrypted_message))
    return b_size+msg_iv+encrypted_message

def proccess_msg_response_from_message_server(response): #is only a code number - unsigned short 
    decoded = struct.unpack('<H', response[:size.code_no])[0]
    if decoded == codes.msg_ack:
        print(f"code {decoded}.\nmessage arrived correctly at server's side")
    else:
        print(f"error occured during transmission of message to server.\nerror code {decoded}")

def construct_authenticator(client_details, aes_key, version):
    import time
    auth_iv = os.urandom(16)
    b_version = struct.pack('B', version)
    b_client_id = bytes.fromhex(client_details['uuid'])
    b_server_id = bytes.fromhex(get_server_id())
    b_creat_time = struct.pack('<d', time.time())
    enc_ver, enc_cl_id = crypty.encrypt(b_version, aes_key, auth_iv),  crypty.encrypt(b_client_id, aes_key, auth_iv)
    enc_serv_id, enc_time = crypty.encrypt(b_server_id, aes_key, auth_iv), crypty.encrypt(b_creat_time, aes_key, auth_iv)
    payload = auth_iv+enc_ver+enc_cl_id+enc_serv_id+enc_time
    return payload

def construct_request_for_key_from_kdc(client, nonce):
    server_id = get_server_id()
    b_serv_id = bytes.fromhex(server_id)
    payload  = b_serv_id+nonce
    header = construct_client_header(client['uuid'], VERSION, codes.sym_key_req, len(payload))
    return header+payload


def proccess_response_from_kdc(response, nonce = None, register = False):
    unpadded = response.rstrip(b'\0')
    header = unpadded[:size.kdc_header]
    version, code, pld_size = struct.unpack('<BHI', header)
    payload = unpadded[size.kdc_header:]
    if register:
        return payload.hex()
    while True:
        password = input("please enter your password now.\nnote that this is the only time you will need your password this session\n").strip()
        long_key = crypty.hash_password(password).encode('utf-8')

        iv = payload[:size.iv]
        offset1 = size.iv+size.enc_nonce
        encrypted_nonce = payload[size.iv:offset1]
        encrypted_aes = payload[offset1:size.key_payload]
        ticket = payload[size.key_payload:]
        try:
            decrypted_nonce = crypty.decrypt(iv,encrypted_nonce,long_key)    
            decrypted_aes = crypty.decrypt(iv, encrypted_aes, long_key)
            break
        except Exception:
            print('unable to properly authenticate - please try again')
            
    if decrypted_nonce == nonce:
        return decrypted_aes, ticket
    else:
        print("unable to properly decrypt aes key - nonce not matched")
        return None, None



def procces_key_ack_from_server(response):
    decoded = struct.unpack('<H', response[:size.code_no])[0]
    if decoded == codes.key_ack:
        return True
    elif decoded != codes.err:
        print('error decoding code response from message server')
    return False

# obsolete?
# def do_somthing_with_response(message_from_server, response_code):
#     pass

#client_actions = {'message':construct_message_for_server, 'register':register_client}

def obtain_session(client, registered, server, kdc, nonce):
    kdc_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    kdc_socket.connect((kdc['address'], kdc['port']))
    if not registered:
        register_client(client, kdc_socket) 
    
    packed_request_for_key = construct_request_for_key_from_kdc(client, nonce)
    padded_request = packed_request_for_key.ljust(size.pack, b'\0')
    kdc_socket.sendall(padded_request)
    response = kdc_socket.recv(size.pack)
    aes, ticket = proccess_response_from_kdc(response, nonce)
    kdc_socket.close()
    if not (aes and ticket):
        print('error while parsing credentials from auth server')
    return aes, ticket


def initialize_client():
    
    client_details, registered = get_client_details_from_meinfo_file()
    servers = get_server_and_kdc_details()
    server_details = servers['server']
    kdc_details = servers['kdc']
    if not (client_details and server_details and kdc_details):
        print(f"unable to obtain details of client or server - check files {client_details_file} and {servers_details_file}")
        return

    nonce = os.urandom(size.nonce)
    aes_key, ticket = obtain_session(client_details, registered, server_details, kdc_details, nonce)
    if not (aes_key and ticket):
        return
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((server_details['address'], server_details['port']))

    authenticator = construct_authenticator(client_details, aes_key,VERSION)
    payload = authenticator+ticket
    header = construct_client_header(client_details['uuid'], VERSION, codes.sym_key_to_serv, len(payload))
    msg_to_server = header+payload
    padded_msg = msg_to_server.ljust(size.pack, b'\0')

    client_socket.sendall(padded_msg)
    response = client_socket.recv(size.pack)
    recieved = procces_key_ack_from_server(response)

    
    while recieved: # will only work if ticket recieved properly by message server

        message = input(f"enter your message for server here - please note the max length of each message is {size.pack} bytes:\n")[:size.pack]
        msg = construct_message_for_server(message, aes_key)
        header = construct_client_header(client_details['uuid'], VERSION, codes.msg_to_serv, len(msg))
        packed_message = header+msg
        padded_message = packed_message.ljust(size.pack, b'\0')
        client_socket.sendall(padded_message)

        if message.lower() == 'exit':
            break

        response = client_socket.recv(size.pack)
        proccess_msg_response_from_message_server(response)
        
    
    client_socket.close()



        
if __name__ == '__main__':
    initialize_client()









