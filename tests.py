import client, msg_server, kdc, funcs, codes , size, struct, os, time, crypty, uuid, random





clients = kdc.get_details_for_all_clients()
# # kdc.backup_clients_info_to_file(clients)

server = msg_server.get_details_from_msginfo_file()

# # print(len(kdc.construct_uuid_response(None)))



client_ = client.get_client_details_from_meinfo_file()[0]
nonce = os.urandom(size.nonce)

# # request = client.construct_register_request(client_)
# # unpacked_request = kdc.kdc_process_request_from_client(request)
request = client.construct_request_for_key_from_kdc(client_, nonce)
unpacked_request = kdc.kdc_process_request_from_client(request)
response = kdc.create_aes_and_ticket(unpacked_request, clients, server)
aes,ticket = client.proccess_response_from_kdc(response, nonce)
offset1 = size.enc_time+size.enc_aes
t_key = ticket[-(offset1):-(size.enc_time)]
t_iv = ticket[-(offset1+size.iv):-(offset1)]
dec_t_key = crypty.decrypt(t_iv, t_key, server['key'])
print(dec_t_key == aes, len(aes))
# dec_key = crypty.decrypt(iv, aes, client_['psw'].encode('utf-8'))
# print(dec_key==dec_t_key)

#################################################################################################

# uid  = client.proccess_response_from_kdc(response, register=True)
# print(uid)
# print(client_['uuid'])

# # unpacked_request['uuid'] = '23445914caed4b239b99dd212e625f8d'
# print(clients)
# response = kdc.register_client(unpacked_request, clients, None)
# header = response[:size.kdc_header]
# print(struct.unpack('<BHI', header))
# # id_b = response[-(size.id_size):]
# # print(id_b.hex())



# err = kdc.get_error_response(unpacked_request)
# print(err)
# print(err.decode('utf-8'))

# server = msg_server.get_details_from_msginfo_file()
# # print(request)
# unpacked_request = kdc.kdc_process_request_from_client(request)
# response = kdc.create_aes_and_ticket(unpacked_request, client_, server)
# print(response)
# header = response[:size.kdc_header]
# x = struct.unpack('<BHI', header)
# print(x)
# print(x[2] == size.key_payload+size.ticket)


# session_key = os.urandom(size.aes_key)
# ticket = kdc.construct_ticket(unpacked_request, client_, server, session_key)
# server_key = server['key']
# offset1 = size.version+size.id_size*2+size.time
# iv = ticket[offset1:offset1+size.iv]
# encrypted_key = ticket[-(size.enc_aes+size.enc_time):-(size.enc_time)]
# encrypted_time = ticket[-(size.enc_time):]
# dec_key = crypty.decrypt(iv, encrypted_key, server_key)
# decrypted_time = crypty.decrypt(iv, encrypted_time, server_key)

# print(session_key == dec_key)
# print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(struct.unpack('<d', decrypted_time)[0])))

# psw = crypty.hash_password('kuhagevfueyvqgqrliur    ')
# client_['psw'] = psw
# aes = kdc.get_aes_key(unpacked_request, client_, None)[0]
# print(aes)
# enc_key = aes[-(size.enc_aes):]
# iv = aes[:size.iv]
# enc_nonce = aes[size.iv:size.iv+size.enc_nonce]
# key = crypty.decrypt(iv, enc_key, psw.encode('utf-8'))
# _nonce = crypty.decrypt(iv, enc_nonce, psw.encode('utf-8'))
# print(str(nonce), str(_nonce), nonce==_nonce)

# print(unpacked_request)


# with open(kdc.clients_data_file, 'w') as f:
#     for i in range(4):
#         f.write(':'.join((uuid.uuid4().hex, random.choice('asdfghjkl')*15, crypty.hash_password(random.choice('asdfghjkl')*15), time.strftime("%Y-%m-%d %H-%M-%S", time.localtime(time.time()+random.randint(-1000,1000))) ))+'\n')
# print(kdc.get_details_for_all_clients())

# print(kdc.get_port_number_for_kdc())



# client_details = client.get_client_details_from_meinfo_file()[0]
# server = msg_server.get_details_from_msginfo_file()
# key = os.urandom(size.aes_key)
# msg = client.construct_message_for_server('hello, world :)', key)
# header = client.construct_client_header(client_details['uuid'], 24, codes.msg_to_serv, len(msg))
# packed_message = header+msg
# padded_message = packed_message.ljust(size.pack, b'\0')
# print(msg_server.msg_srv_proccess_request_from_client(padded_message, server, key))
# print(msg_server.msg_srv_proccess_request_from_client(padded_message, server, os.urandom(size.aes_key)))

# # server['key'] = os.urandom(size.aes_key)
# nonce = os.urandom(size.nonce)
# request = client.construct_request_for_key_from_kdc(client_details, nonce)[size.client_header:]
# ticket = kdc.construct_ticket(request, client_details, server, key)
# auth = client.construct_authenticator(client_details, key, client.VERSION)
# payload = auth+ticket
# header = client.construct_client_header(client_details['uuid'], client.VERSION, codes.sym_key_to_serv, len(payload))
# full = header+payload
# padded = full.ljust(size.pack, b'\0')
# c, t = msg_server.msg_srv_proccess_request_from_client(padded, server, key)
# k, x = t
# x = struct.unpack('<d', x)[0]
# print(f'code:  {c}')
# print(f'key recieved: {k}   ::   key: {key}\nand if you wonder if they are the same, the answer is {key==k}')
# print(f'expiration time in seconds: {x}  ::  and in normal format: {time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(x))}')



# server = msg_server.get_details_from_msginfo_file()
# if server:
#     for key in server.keys():
#         print(f'{key}::{server[key]}')

# print(client.procces_key_ack_from_server(struct.pack('<H', codes.key_ack)))
# print(client.procces_key_ack_from_server(struct.pack('<H', codes.err)))
# print(client.procces_key_ack_from_server(struct.pack('<H', codes.msg_ack)))




# nonce = os.urandom(size.nonce)
# print(nonce)
# client_details = client.get_client_details_from_meinfo_file()[0]
# request = client.construct_request_for_key_from_kdc(client_details, nonce)
# print(request)
# srv_id = request[size.client_header:size.client_header+size.id_size]
# print(srv_id.hex())
# nonced = request[-(size.nonce):]
# print(nonced)



# key = os.urandom(size.aes_key)
# client_details = client.get_client_details_from_meinfo_file()[0]
# print(client_details)
# auth = client.construct_authenticator(client_details, key, 24)
# print(auth)
# print('\n\n')
# iv = auth[:size.iv]
# encrypted_time = auth[-(size.enc_time):]
# dec_time = struct.unpack('<d',crypty.decrypt(iv, encrypted_time, key))[0]
# formatted = time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(dec_time))
# print(encrypted_time)
# print(dec_time)
# print(formatted)
# print('\n\nid check:\n')
# enc_client = auth[size.iv+size.enc_ver:size.iv+size.enc_ver+size.enc_id]
# enc_srv = auth[size.iv+size.enc_ver+size.enc_id:size.iv+size.enc_ver+size.enc_id*2]
# cl_id = crypty.decrypt(iv, enc_client, key)
# srv_id = crypty.decrypt(iv, enc_srv, key)
# print(cl_id.hex())
# print(srv_id.hex())



# print(client.proccess_msg_response_from_message_server(struct.pack('<H', codes.msg_ack)))
# print(client.proccess_msg_response_from_message_server(struct.pack('<H',codes.key_ack,)))
# print(client.proccess_msg_response_from_message_server(struct.pack('<H',codes.err,)))
# print(client.proccess_msg_response_from_message_server(struct.pack('<H',1024,)))
# print(client.proccess_msg_response_from_message_server(struct.pack('<H',1023,)))


# key = os.urandom(32)
# packed_message = client.construct_message_for_server('hello, world! :)', key)
# print(len(packed_message))
# print(packed_message[size.message:size.message+size.iv])
# print(packed_message.rstrip(b'\0'))
# print(packed_message)
# msg = packed_message[size.message+size.iv:]
# iv = packed_message[size.message:size.message+size.iv]
# print(f'encrypted:    {msg}\ndecrypted:    {crypty.decrypt(iv, msg, key).decode('utf-8')}\n\nc\'mon - this is SUPER COOLLLLLLL!')


# print(client.get_client_details_from_meinfo_file())
# details, reg = client.get_client_details_from_meinfo_file()
# print(details)
# print(reg)


# x = client.get_server_and_kdc_details()
# if not (x['server'] and x['kdc'] and True):
#     print('problem')
# else:
#     print('worked')
#     print(x['kdc'], x['server'])


# header = client.construct_client_header('1a'*16, 24, 1024, 255)
# print(header)
# print(list(header))
# c_id = header[:size.id_size].hex()
# header = header[size.id_size:]
# v , code, pld_sz = struct.unpack('<BHI', header)
# print('::'.join((str(c_id), str(v),str(code), str(pld_sz))))