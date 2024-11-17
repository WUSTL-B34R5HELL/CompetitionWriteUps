import hashlib

# charset
charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}"

# dictionary
hashes = {char: hashlib.sha256(char.encode()).hexdigest() for char in charset}

# reverse dictionary
reverse_hashes = {hash_value: char for char, hash_value in hashes.items()}

# Crack function
def crack(hash_list):
    decoded_string = ""  # store the final string
    current_string = ""  # store the current string
    for target_hash in hash_list:
        for char in charset:
            attempt = current_string + char  
            attempt_hash = hashlib.sha256(attempt.encode()).hexdigest()
            if attempt_hash == target_hash:
                decoded_string += char
                current_string = attempt
                break
        else:
            raise ValueError(f"Failed to crack hash: {target_hash}")
    return decoded_string

# read pieces.txt
with open("pieces.txt", "r") as f:
    pieces = f.read().splitlines()

# crack
try:
    result = crack(pieces)
    print(f"Decoded string: {result}")
except ValueError as e:
    print(f"Error: {e}")