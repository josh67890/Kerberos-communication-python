import threading, socket,  struct, msg_server, size, codes, crypty, funcs

VERSION = 24
PACKSIZE = 2048

port_details_file = "port.info"
message_server_details_file = "msg.info"
clients_data_file = "clients_data.info"

def get_port_number_for_kdc():
    try:
        port_file = open(port_details_file, 'r')
        port = int(port_file.readline())
        port_file.close()
    except Exception:
        port = 1256
        print("WARNING: no data available for kdc port number.\nopened on default port no. 1256")
    return port

#unused - simply imported the same function from msg_server.py and used it
# def get_details_for_server():
#     pass


def get_details_for_all_clients():
    details = {}
    try:
        with open(clients_data_file, 'r') as clients_file:
            for line in clients_file:
                client = [l.strip() for l in line.split(':')]
                details[client[0]] = {'name':client[1], 'psw':client[2], 'last_seen':client[3]} # each client is mapped to uuid key
                for k in details[client[0]].values():
                    if not k:
                        print('AAA')
                        raise Exception(f'unable to parse {clients_data_file} file')
                if len(client) != 4:
                    print('BBB')
                    raise Exception(f'unable to parse {clients_data_file} file')
    except Exception:
        print(f"error occured while parsing client file")
        return
    
    return details


def register_client(request, clients_data, server):
    import datetime
    
    if request['uuid'] in clients_data: # remember - the uuids are the keys in the clients_data dict
        uuid = request['uuid']
        response = get_error_response(request)
        code = codes.cl_reg_fail
    else:
        uuid = construct_uuid_response()
        response = bytes.fromhex(uuid)
        clients_data[uuid] = {'name': request['name'], 'psw':crypty.hash_password(request['psw']) , 'last_seen':None}
        code = codes.cl_reg_succ
    clients_data[uuid]['last_seen'] = datetime.datetime.now().strftime("%Y-%m-%d %H-%M-%S")  # will always register correctly the timestamp of last_seen
    header = construct_kdc_header(VERSION, code, len(response))
    return header+response

# OBSOLETE?
# def construct_reg_response(response, code):
#     header = construct_kdc_header(VERSION, code, len(response))
#     return header+response



def get_aes_key(request, clients_data, server):
    client_key = clients_data['psw'].encode('utf-8')
    import os
    session_key, iv = os.urandom(32), os.urandom(16)
    encr_key = crypty.encrypt(session_key, client_key, iv)
    encr_nonce = crypty.encrypt(request['nonce'], client_key, iv)
    return iv+encr_nonce+encr_key, session_key


def construct_ticket(request, clients, server, session_key):
    import time, os
    b_version = struct.pack('B', VERSION)
    # b_client_id = bytes.fromhex(request['uuid'])
    # b_server_id = bytes.fromhex(request['server_id'])
    b_client_id = bytes.fromhex(request['uuid'])
    b_server_id = bytes.fromhex(server['uuid'])
    b_creation_time = struct.pack('<d', time.time())
    ticket_iv = os.urandom(16)
    encr_session_key = crypty.encrypt(session_key, server['key'], ticket_iv)
    b_expiration = struct.pack('<d', time.time()+60*20) #adds 20 minutes untill expiration
    encr_exp = crypty.encrypt(b_expiration, server['key'], ticket_iv)
    return b_version+b_client_id+b_server_id+b_creation_time+ticket_iv+encr_session_key+encr_exp

def create_aes_and_ticket(request, clients, server):
    clients_data = clients[request['uuid']]
    aes, session_key = get_aes_key(request, clients_data, server)
    ticket = construct_ticket(request, clients_data, server, session_key)
    payload = aes+ticket
    code = codes.sym_key_from_kdc
    header = construct_kdc_header(VERSION, code, len(payload))
    return header+payload

#obsolete?
# def construct_credentials_response(aes, ticket, code):
#     pass


def construct_kdc_header(version, code, payload_size):
    b_version = struct.pack('B', VERSION)
    b_code = struct.pack('<H', code)
    b_payload_size = struct.pack('<I', payload_size)
    return b_version+b_code+b_payload_size

kdc_functions = {'register':register_client, 'aes_and_ticket':create_aes_and_ticket}

def kdc_process_request_from_client(request): #unpacks header and payload-based on the code in header
    header = request[:size.client_header]
    payload = request[size.client_header:].rstrip(b'\0')
    unpacked = {}
    client_id, version, code, payload_size = funcs.deconstruct_message(header, 'header', 'client')
    unpacked['uuid'] = client_id
    if code == codes.cl_reg:
        unpacked['name'], unpacked['psw'] = funcs.deconstruct_message(payload, 'register_client')
        unpacked['action'] = 'register_client'
    elif code == codes.sym_key_req:
        unpacked['server_id'], unpacked['nonce'] = funcs.deconstruct_message(payload, 'key_req')
        unpacked['action'] = 'create_aes_and_ticket'
    for val in unpacked.values():
        if not val:
            return
    return unpacked


def get_error_response(request):
    msg =  f"client id {request['uuid']}  is already registered with kdc"
    return msg.encode('utf-8')

def construct_uuid_response(): # returns a 32 character hex string representing the 16 byte uuid
    import uuid
    id = uuid.uuid4()
    return id.hex

def backup_clients_info_to_file(client_details):
    import time
    while True:
        client_backup = open(clients_data_file, 'w')
        for uuid in client_details:
            cl = client_details[uuid]
            line = uuid+':'+cl['name']+':'+cl['psw']+':'+cl['last_seen']+'\n'
            client_backup.write(line)
        client_backup.close()
        
        time.sleep(5) # wakeup every 60 seconds to perform a backup

def kdc_client_handler(client_socket, clients_data, server):
    while True:
        request_from_client = client_socket.recv(size.pack)
        if not request_from_client: # client closed socket - connection terminated
            break
        unpacked_request = kdc_process_request_from_client(request_from_client) # returns dict with all the details, including field 'action'
        if not unpacked_request:
            print(f'error while parsing request from client')
            packed_response_for_client = construct_kdc_header(VERSION, codes.err, size.kdc_header).ljust(size.pack, b'\0')
        else:
            packed_response_for_client =  unpacked_request['action'](unpacked_request, clients_data, server) # appropiate function is called. returns the key/ticket or uuid, respectively
            padded_response = packed_response_for_client.ljust(size.pack, b'\0')
        client_socket.sendall(padded_response)
    client_socket.close()



def initialize_kdc():

    port_num = get_port_number_for_kdc()
    server = msg_server.get_details_from_msginfo_file()
    clients = get_details_for_all_clients()
    if not (clients and server):
        return
    backup_thread = threading.Thread(target=backup_clients_info_to_file, args=(clients,), daemon=True)
    backup_thread.start()

    kdc_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    kdc_socket.bind(('127.0.0.1', port_num))
    kdc_socket.listen()

    print(f"kdc server listening on 127.0.0.01:{port_num}")

    while True:
        client_socket, client_address = kdc_socket.accept()
        print(f"connection recived from {client_address}")

        threading.Thread(target=kdc_client_handler, args=(client_socket,clients, server), daemon=True).start()

  
if __name__ == "__main__":
    initialize_kdc()
