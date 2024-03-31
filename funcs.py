import size, codes,crypty, struct

def encrypted_size(length):
    remainder = length%16
    return length+16-remainder

def header(header, sender):
    if sender == 'client':
        id = header[:size.id_size].hex()
        # convert id to str??
        header = header[size.id_size:]
    version, code, payload_size = struct.unpack('<BHI', header)
    # version = struct.unpack('B',header[:size.version])
    # code = struct.unpack('<H',header[size.version:size.version+size.code_no])
    # payload_size = struct.unpack('<I',header[size.version+size.code_no:])
    if sender == 'client':
        return id, version, code, payload_size
    else:
        return version, code, payload_size
    
def authenticator(auth, key):
    iv = auth[:size.iv]

    offset1 = size.iv+size.enc_ver
    offset2 = offset1+size.enc_id
    offset3 = offset2+size.enc_id

    version = struct.unpack('B', crypty.decrypt(iv, auth[size.iv:offset1], key))[0]
    cl_id = crypty.decrypt(iv, auth[offset1:offset2],key)
    srv_id = crypty.decrypt(iv,auth[offset2:offset3],key)
    decrypted_create_time = crypty.decrypt(iv, auth[offset3:], key)
    create_time = struct.unpack('<d', decrypted_create_time)[0]

    return iv, version, cl_id, srv_id, create_time

def ticket(_ticket, details):
    offset = size.version+size.id_size*2+size.time
    key_offset = offset+size.iv
    ticket_iv = _ticket[offset:key_offset]
    encrypted_key = _ticket[key_offset:key_offset+size.enc_aes]
    encypted_exp_time = _ticket[key_offset+size.enc_aes:]
    aes_key = crypty.decrypt(ticket_iv, encrypted_key, details['key'])
    expr_time = crypty.decrypt(ticket_iv, encypted_exp_time, details['key'])

    return aes_key, expr_time

def client_register(request, details):
    name = request[:size.name].rstrip(b'\0').decode('utf-8')
    psw = request[size.name:].rstrip(b'\0').decode('utf-8')
    return name, psw# return name, password  - without null termination!!

def key_request(request, details):
    server_id = request[:size.id_size].hex()
    nonce = request[size.id_size:]
    return server_id, nonce

def message(request, key):
    offset1 = size.message+size.iv
    iv = request[size.message:offset1]
    msg = request[offset1:].rstrip(b'\0')
    try:
        dcr_msg = crypty.decrypt(iv, msg, key)
    except Exception:
        return 'error occured while attempting to decrypt incoming message.\nplease check the validity of session key recieved, if at all'
    return dcr_msg.decode('utf-8')

funcions = {'message':message,'register_client': client_register, 'key_req':key_request,'ticket':ticket, 'authenticator':authenticator, 'header':header}

def deconstruct_message(block, block_type, details = None):
    return funcions[block_type](block, details)