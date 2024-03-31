import funcs
name = password = 254
pack = 2048
id_size = 16
enc_id = funcs.encrypted_size(id_size)
ip = 4
port = 2
name = 255
password = 255

version = 1
enc_ver = funcs.encrypted_size(version)
code_no = 2
payload = 4
message = 4

nonce = 8
enc_nonce = funcs.encrypted_size(nonce)
iv = 16
aes_key = 32
enc_aes = funcs.encrypted_size(aes_key)
time = 8
enc_time = funcs.encrypted_size(time)

kdc_header = version+code_no+payload
client_header = version+code_no+payload+id_size

key_payload = iv+enc_nonce+enc_aes
ticket = version+id_size*2+time+iv+enc_aes+enc_time
authenticator = iv+enc_ver+enc_id*2+enc_time

