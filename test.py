import sys
import asyncio
from bleak import BleakClient, BleakError
from Crypto.Cipher import AES
import hashlib
import binascii
from pyasn1.codec.der.encoder import encode
from pyasn1.type.univ import Integer, Sequence
from pyasn1.type.univ import SequenceOf
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from Crypto.Util.Padding import pad
from ecdsa import SigningKey, NIST256p, VerifyingKey, SECP256k1
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from ecdsa.util import sigencode_der

# Define variables
DEVICE_MAC = "C9:9C:3C:7B:C7:80"  # Replace with your device's MAC address
NOTIFICATION_UUID = "0000ff01-0000-1000-8000-00805f9b34fb"
WRITE_UUID = "0000ff02-0000-1000-8000-00805f9b34fb"
CONST_LOCAL_KEY = "459FC535808941F17091E0993EE3E93D"

CONST_PRIVATE_KEY_L1 = "4F19A16E3E87BDD9BD24D3E5495B88041511943CBC8B969ADE9641D0F56AF337"
CONST_PRIVATE_KEY_TEST = "4F19A16E3E87BDD9BD24D3E5495B88041511943CBC8B969ADE9641D0F56A0000"
CONST_PUBLIC_KEY_K2 = "3059301306072a8648ce3d020106082a8648ce3d03010703420004A73ABF5D2232C8C1C72E68304343C272495E3A8FD6F30EA96DE2F4B3CE60B251EE21AC667CF8A71E18B46B664EAEFFE3C489F24F695B6411DB7E22CCC85A8594"

SECP_256K1_PUBLIC_PREFIX = "3056301006072A8648CE3D020106052B8104000A03420004"
SECP_256R1_PRIVATE_PART1 = "308193020100301306072a8648ce3d020106082a8648ce3d0301070479"
SECP_256R1_PRIVATE_PART2 = "30770201010420"
SECP_256R1_PRIVATE_PART3 = "a00a06082a8648ce3d030107a14403420004"
SECP_256R1_PUBLIC_PREFIX = "3059301306072a8648ce3d020106082a8648ce3d03010703420004"

client = None
aes_key = None
aes_iv = None
my_private_key = None
my_public_key = None

def md5_encode(byte_array):
    md5_hash = hashlib.md5(byte_array)
    return md5_hash.hexdigest()

def edcsa_to_der_signature(token_signature: bytes) -> bytes:
    if token_signature is None:
        raise ValueError("tokenSignature cannot be None")
    
    mid = len(token_signature) // 2
    first_half = token_signature[:mid]
    second_half = token_signature[mid:]

    sequence = Sequence()
    sequence.setComponentByPosition(0, Integer(int.from_bytes(first_half, byteorder='big')))
    sequence.setComponentByPosition(1, Integer(int.from_bytes(second_half, byteorder='big')))

    return encode(sequence)

def verify_edcsa256(data, signature, public_key_der):
    public_key = serialization.load_der_public_key(public_key_der)

    try:
        # Verify the signature
        public_key.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except InvalidSignature:
        return False


def int_to_hex_str(value: int, length: int) -> str:
    hex_str = hex(value)[2:]  # Convert to hex and remove '0x' prefix
    return hex_str.zfill(length)

def hex_str_sum(hex_str: str, return_byte_len: int) -> str:
    if hex_str is None:
        raise ValueError("hexStr cannot be None")
    if len(hex_str) % 2 != 0:
        return None

    chunked = [hex_str[i:i+2] for i in range(0, len(hex_str), 2)]
    
    total = 0
    for chunk in chunked:
        total += int(chunk, 16)

    return int_to_hex_str(total, return_byte_len * 2)

def hex_str_xor(hex_str1, hex_str2):
    if hex_str1 is None or hex_str2 is None:
        raise ValueError("hex_str1 and hex_str2 cannot be None")

    if len(hex_str1) % 2 != 0 or len(hex_str1) != len(hex_str2):
        return None

    result = []
    for i in range(0, len(hex_str1), 2):
        byte1 = int(hex_str1[i:i + 2], 16)
        byte2 = int(hex_str2[i:i + 2], 16)
        xor_byte = byte1 ^ byte2
        result.append(f"{xor_byte:02X}")

    return ''.join(result)

def calc_aes_key(data):
    global aes_key
    global aes_iv

    # Example hex string
    # 2A 2A   01 04 4D 0D 99 18    01 10
    # PREFIX  DATA                 HEXSUM
    hex_string = data.hex()
    hex_string_pfx = hex_string[0:4]
    hex_string_key = hex_string[4:8]
    hex_string_value = hex_string[8:len(hex_string)-4]
    hex_string_sum = hex_str_sum(hex_string_key+hex_string_value, 2)

    # Convert hex string to bytes
    byte_array = bytes.fromhex(hex_string_value)

    # Reverse the byte array
    reversed_byte_array = byte_array[::-1]

    # Compute the MD5 hash of the reversed byte array
    aes_iv = md5_encode(reversed_byte_array)

    # Reply should be "2A2A0204 + substring + hexsum"
    aes_iv_sub = aes_iv[16:24]
    enc_reply = "2A2A0204" + aes_iv_sub + hex_str_sum("0204"+aes_iv_sub, 2)

    # Calculate AES key
    aes_key = hex_str_xor(aes_iv, CONST_LOCAL_KEY)

    print("Received: " + hex_string)
    print("Prefix: " + hex_string_pfx)
    print("Key: " + hex_string_key)
    print("Value: " + hex_string_value)
    print("Hexsum: " + hex_string_sum)
    print("MD5 Key: " + aes_iv)
    print("AES Key: " + aes_key)
    print("Reply: " + enc_reply)
    return enc_reply

def edcsa_dersignature_parse(hex_str):
    if len(hex_str) < 128:
        raise ValueError("Input hex string is too short to parse")

    substring = hex_str[6:8]
    parse_int = int(substring, 16)
    sb = []

    if parse_int == 32:
        substring2 = hex_str[8:72]
        sb.append(substring2)
    elif parse_int == 33:
        substring3 = hex_str[10:74]
        sb.append(substring3)
    
    substring4 = hex_str[-64:]
    sb.append(substring4)

    return ''.join(sb)

def sign_string(private_key_hex, message):
    # Convert the hex string to bytes
    private_key_bytes = bytes.fromhex(private_key_hex)
    
    # Load private key from bytes
    private_key = ec.derive_private_key(
        int.from_bytes(private_key_bytes, byteorder='big'),
        ec.SECP256R1(),
        default_backend()
    )

    # Sign the message hash using the private key
    signature = private_key.sign(bytes.fromhex(message), ec.ECDSA(hashes.SHA256()))
    
    # Encode the signature in DER format
    r, s = decode_dss_signature(signature)
    der_signature = encode_dss_signature(r, s)
    
    return der_signature

def enc_aes_cbc_data(data_str, aes_key, iv=None, add_space=False):
    if not aes_key:
        return ""

    try:
        # Convert data to bytes
        data_bytes = bytes.fromhex(data_str)
        data_len = len(data_bytes)

        # Create padding for data to fit block size (AES block size is 16 bytes)
        padding_len = 16 - (data_len % 16)
        padded_data = data_bytes + bytes([padding_len] * padding_len)

        # Convert the length of the original data to a 4-byte hexadecimal string
        data_len_hex = format(data_len, '04x')

        # Generate IV if not provided
        if iv is None:
            substring2 = hashlib.md5(padded_data[:4]).hexdigest()
            iv = hashlib.md5(binascii.unhexlify(substring2)).digest()
            data_hex = data_len_hex + substring2
        else:
            data_hex = data_len_hex

        # Encrypt the data in CBC mode
        encrypted_data = []
        for i in range(0, len(padded_data), 16):
            block = padded_data[i:i+16]
            if i == 0:
                iv_part = iv
            else:
                iv_part = encrypted_data[-1]

            aes = AES.new(binascii.unhexlify(aes_key), AES.MODE_CBC, iv_part)
            encrypted_part = aes.encrypt(block)
            encrypted_data.append(encrypted_part)

        # Combine all encrypted blocks into a single hex string
        encrypted_hex = ''.join(binascii.hexlify(block).decode() for block in encrypted_data)
        final_result = data_hex + encrypted_hex

        if add_space:
            final_result = ' '.join(final_result[i:i+2] for i in range(0, len(final_result), 2))

        return final_result
    except (ValueError, IndexError) as e:
        print(f"Error occurred: {str(e)}")
        return data_str

def parse_aes_cbc_data(data_str, aes_key, iv=None, add_space=False):
    if not aes_key:
        return ""

    try:
        # Remove spaces
        data_str = data_str.replace(" ", "")

        # Parse the initial parts of the string
        parse_int = int(data_str[:4], 16)
        substring2 = data_str[4:12]

        if iv is None:
            iv = hashlib.md5(binascii.unhexlify(substring2)).digest()
            start_index = 12
        else:
            start_index = 4

        substring3 = data_str[start_index:]
        length = len(substring3) // 32

        decrypted_data = []

        for i in range(length):
            start = i * 32
            end = start + 32
            encrypted_part = binascii.unhexlify(substring3[start:end])

            if i == 0:
                iv_part = iv
            else:
                previous_start = (i - 1) * 32
                previous_end = previous_start + 32
                iv_part = binascii.unhexlify(substring3[previous_start:previous_end])

            aes = AES.new(binascii.unhexlify(aes_key), AES.MODE_CBC, iv_part)
            decrypted_part = aes.decrypt(encrypted_part)
            decrypted_data.append(decrypted_part)

        result = b''.join(decrypted_data)[:parse_int]

        if add_space:
            result = ' '.join(format(x, '02x') for x in result)
        else:
            result = result.hex()

        return result
    except (ValueError, IndexError) as e:
        print(f"Error occurred: {str(e)}")
        return data_str

async def ble_encrypted_handle(data):
    global client
    global aes_key
    global aes_iv
    global my_private_key
    global my_public_key


    if (data[:4] == "2a2a"):
        parseint = int(data[4:6], 16)

        if parseint == 4:
            print("Checking signature validity...")
        
            lot_pk_hex_str = data[8:136]
            signature = data[136:len(data)-4]

            hex_bytes2 = bytes.fromhex(lot_pk_hex_str + aes_iv)
            hex_bytes3 = bytes.fromhex(signature)
            edcsa_der_signature = edcsa_to_der_signature(hex_bytes3)
            hex_bytes4 = bytes.fromhex(CONST_PUBLIC_KEY_K2)
            
            print("Signature: "+ edcsa_der_signature.hex())
            isValidSignature = verify_edcsa256(hex_bytes2, edcsa_der_signature, hex_bytes4)
            
            if isValidSignature:
                print("Remote signature is valid!")

                # Not yet sure what this does or if its needed
                #iot_public_key = SECP_256R1_PUBLIC_PREFIX + lot_pk_hex_str
                
                # Generate private key
                my_private_key = ec.generate_private_key(ec.SECP256R1())

                #my_private_key_bytes = bytes.fromhex(CONST_PRIVATE_KEY_L1)
                #my_private_key = ec.derive_private_key(
                #    int.from_bytes(my_private_key_bytes, 'big'), ec.SECP256R1(), default_backend()
                #)

                # Get the public key from the private key
                my_public_key = my_private_key.public_key()

                # Serialize the public key to bytes
                public_key_bytes = my_public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

                # Remove prefix
                public_key_str = public_key_bytes.hex()[-128:]
                print("My public key: " + public_key_str)
                
                # Parse signature
                my_signature = sign_string(CONST_PRIVATE_KEY_L1, public_key_str + aes_iv).hex()
                edcsa_der_signature_parse = edcsa_dersignature_parse(my_signature)

                # Temp checking for validity
                iot_private_key_bytes = bytes.fromhex(CONST_PRIVATE_KEY_L1)
                iot_private_key = ec.derive_private_key(
                    int.from_bytes(iot_private_key_bytes, byteorder='big'),
                    ec.SECP256R1(),
                    default_backend()
                )
                iot_public_key = iot_private_key.public_key()
                iot_public_key_bytes = iot_public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                iot_public_key_str = iot_public_key_bytes.hex()[-128:]
                hex_bytes2 = bytes.fromhex(public_key_str + aes_iv)
                edcsa_der_signature = edcsa_to_der_signature(bytes.fromhex(edcsa_der_signature_parse))
                hex_bytes4 = bytes.fromhex(SECP_256R1_PUBLIC_PREFIX + iot_public_key_str)
                isValidSignature2  = verify_edcsa256(hex_bytes2, edcsa_der_signature, hex_bytes4)
                
                if isValidSignature2:
                    print("My signature is valid!")

                # Send response
                #"2A2A0580" + my_public_key + edcsa_der_signature_parse + hex_str_sum("0580" + my_public_key + edcsa_der_signature_parse)
                response = "2A2A0580" + public_key_str + edcsa_der_signature_parse + hex_str_sum("0580" + public_key_str + edcsa_der_signature_parse, 2)
                enc_response = enc_aes_cbc_data(response, aes_key, bytes.fromhex(aes_iv), False)
                print(response)
                print(enc_response)
                if client.is_connected:
                    await client.write_gatt_char(WRITE_UUID, bytearray.fromhex(enc_response))
                
                return

        elif parseint == 6 and int(data[6:8], 16) == 0:
            print("Key accepted!")
            return
        elif parseint == 6 and int(data[6:8], 16) == 1:
            print("Something interesting happened... error maybe?")
            return

async def notification_handler(sender, data):
    global client
    global aes_key
    global aes_iv
    
    print(f"Notification from {sender}: {data.hex()}")
    
    # Check for 2A2A and respond to the notification
    if data.hex()[0:4] == "2a2a":
        key = data.hex()[4:8]
        if key == "0104":
            response = calc_aes_key(data)
            if response is not None:
                if client.is_connected:
                    await client.write_gatt_char(WRITE_UUID, bytearray.fromhex(response))
                    print(f"Response sent: {response}")
        elif key == "0301":
            print("MD5 Challenge accepted!")
    else:
        decrypted = parse_aes_cbc_data(data.hex(), aes_key, bytes.fromhex(aes_iv), False)
        print("Decrypted: " + decrypted)
        await ble_encrypted_handle(decrypted)
        
            
async def handle_notifications():
    global client
    
    while True:
        try:
            await client.start_notify(NOTIFICATION_UUID, notification_handler)
            print(f"Notification handler started for {NOTIFICATION_UUID}")

            # Keep the script running to listen for notifications
            while client.is_connected:
                await asyncio.sleep(1)  # Adjust the duration as needed

            print(f"Device {DEVICE_MAC} disconnected")
            return

        except BleakError as e:
            print(f"BleakError: {e}")
            return
        except Exception as e:
            print(f"Unexpected error: {e}")
            return

async def main(device_mac):
    global client
    
    try:
        async with BleakClient(device_mac) as client:
            if client.is_connected:
                print(f"Connected to {device_mac}")
                await handle_notifications()
            else:
                print(f"Failed to connect to {device_mac}")

    except BleakError as e:
        print(f"BleakError: {e}")
        await asyncio.sleep(5)  # Wait before retrying
    except Exception as e:
        print(f"Unexpected error: {e}")
        await asyncio.sleep(5)  # Wait before retrying

async def dryrun():
    global aes_key
    global aes_iv

    data = bytes.fromhex(sys.argv[1])
    payload = bytes.fromhex(sys.argv[2])
    
    calc_aes_key(data);
    
    decrypted = parse_aes_cbc_data(payload.hex(), aes_key, bytes.fromhex(aes_iv), False)
    print("Decrypted: " + decrypted)
    #await ble_encrypted_handle(decrypted)
    
    return

# Run the main function
if len( sys.argv ) > 2:
    asyncio.run(dryrun())
else:
    asyncio.run(main(DEVICE_MAC))
