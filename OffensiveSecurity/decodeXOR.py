#!/usr/bin/env python3

# Array containing the raw data that will be processed
# This represents the extracted data that will be "decrypted"
raw_data = [
    0x53, 0x51, 0x51, 0x55, 0x52, 0x5e, 0x56, 0x07,
    0x01, 0x04, 0x0d, 0x02, 0x00, 0x03, 0x56, 0x5b,
    0x0f, 0x50, 0x07, 0x01, 0x53, 0x50, 0x0b, 0x50,
    0x55, 0x00, 0x51, 0x5b, 0x01, 0x06, 0x53, 0x06
]

# Array containing the key (hashed bytes)
# These are the values used to "decrypt" the raw data
key_bytes = [
    0x31, 0x65, 0x63, 0x66, 0x66, 0x38, 0x62, 0x65, 
    0x63, 0x65, 0x39, 0x34, 0x38, 0x36, 0x32, 0x38, 
    0x37, 0x64, 0x63, 0x37, 0x36, 0x35, 0x32, 0x31,
    0x61, 0x38, 0x34, 0x62, 0x62, 0x37, 0x63, 0x30
]

# Initializing an array to store the result of XOR operations between raw_data and key_bytes
decrypted_bytes = bytearray()

# Iterate over each byte in the raw data
for index in range(len(raw_data)):
    # Perform the XOR operation between the current byte and the corresponding byte from the key
    # The modulo ensures the key wraps around if it's shorter than the raw data
    decrypted_byte = raw_data[index] ^ key_bytes[index % len(key_bytes)]
    decrypted_bytes.append(decrypted_byte)

# Append the closing brace for the flag (ASCII value of '}')
decrypted_bytes.append(0x7d)

# Construct the full flag by adding the 'flag{' prefix
final_flag = b'flag{' + decrypted_bytes

# Decode the byte array into a string and print the final flag
print(final_flag.decode())
