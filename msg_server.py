import socket, threading, struct, time, size, codes, funcs

server_details_file = "msg.info"

def client_handler(client_socket, server):  #continues to proccess requests from client until client disconnects

    #must recieve key/ticket from client before secure messaging - verify what to to if not recieved key first!!
    session_key = None
    expiration_time = 0 #defaults to epoch time
    while True:
        request_from_client = client_socket.recv(size.pack)

        if not request_from_client: #client disconnected - VERIFY THIS DOES WHAT IS EXPECTED!!!
            break
            
        msg_code, request = msg_srv_proccess_request_from_client(request_from_client, server, session_key)
        if msg_code == codes.msg_ack:
            if expiration_time > time.time():
                print(f"message recieved securely from client:\n{request}\nmessage code: {msg_code}")
            else:
                print(f'unable to securely recieve message - session key expired at {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(expiration_time))}')
                msg_code = codes.err
        elif msg_code == codes.key_ack:
            session_key, expiration_time = request       # saves session key for further use - decoding future messages
        response = struct.pack('<H', msg_code).ljust(size.pack)
        client_socket.sendall(response)
    
    client_socket.close()


def initialize_server():
    server_details = get_details_from_msginfo_file() #details saved in dict
    if not server_details: # error ocurred while obtaining server details
        return
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((server_details['host'], server_details['port']))
    server_socket.listen()

    print(f"server listening on {server_details['host']}:{server_details['port']}")

    while True: #waits for client connection requests
        client_socket, client_address = server_socket.accept()
        print(f"connection recived from {client_address}")

        threading.Thread(target = client_handler, args = (client_socket, server_details)).start() # dispatches each client connection to seperate handler thread



def get_details_from_msginfo_file():
    details = {}
    try:
        detail_file = open(server_details_file, 'r')

        line = detail_file.readline()
        index = line.find(':')
        details['host'] = line[:index].strip()
        details['port'] = int(line[index+1:].strip())

        details['name'] = detail_file.readline().strip()
        details['uuid'] = detail_file.readline().strip()
        details['key'] = detail_file.readline().strip().encode('utf-8')
        
        for val in details.values():
            if not val:
                raise Exception(f'error while parsing {server_details_file} file')

    except Exception:
        print(f"error while trying to read {server_details_file}")
        return None
    finally:
        detail_file.close()


    return details




def msg_srv_proccess_request_from_client(client_request, server, session_key):
    header = client_request[:size.client_header]
    payload = client_request[size.client_header:].rstrip(b'\0')
    client_id,version, code, payload_size = funcs.deconstruct_message(header, block_type='header', details = 'client') 
    # deals with different requests - key/ticket exchange, messaging.]
    # deconstructs the request - based on the header details
    if code == codes.sym_key_to_serv:
        authenticator = payload[:size.authenticator]
        ticket = payload[size.authenticator:]
        # version, cl_id, srv_id, crt_time, ticket_iv, aes_key, exp_time = funcs.deconstruct_message(ticket, 'ticket', server)
        aes_key, exp_time = funcs.deconstruct_message(ticket, 'ticket', server)
        auth_iv, auth_version, auth_cl, auth_srv, auth_crt_time = funcs.deconstruct_message(authenticator, 'authenticator', session_key)
        recieved_message = aes_key, exp_time
    else:
        recieved_message = funcs.deconstruct_message(payload, 'message', session_key)
    return code, recieved_message
    



    

if __name__ == "__main__":
    initialize_server()


