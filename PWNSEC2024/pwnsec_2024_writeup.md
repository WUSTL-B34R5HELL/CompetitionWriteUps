# PWNSEC_2024 Writeup

## Pieces
> I found a weird file on one of our employees' devices along with a note that says, "Will you be able to assemble the pieces and reveal the secret message?"k. Does he thin he is going to get paid by making CTF challenges instead of working???

The pieces.txt contains several lines of strings, and it is a bit like hash value. And then I search the first line `5c62e091b8c0565f1bafad0dad5934276143ae2ccef7a5381e8ada5b1a8d26d2` on the Internet and find that the first line is the sha256 of the letter `P`.

So I first guess that all the lines are the sha256 of the letter of the alphabet. And I write a script to try solving it, however, this is not correct.

Then I search the second line on the Internet and then I find that the second line `bc8478052e3ca9de6522b003c9297f7a5319cc5e8477991b48a2402c8c5ced61` is the sha256 of the word `PW`. So I guess that for each new line, it is the letter of the previous line plus the next letter of the flag.

Then I write a script to brute force the flag.

```python
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
```


## TickTock
> Time is what we want most but what we use worst.

The TickTock.pcap contains a lot of http packets, and we find that all the http responses are very similar, and the counts of the request is 30. 30 is a common length and not very long, so I guess that it must be related to the length of the final flag.

Check the description of the challenge, it tells us that the time is very important, so I check the http request and response packets. I find that the first packet of the request contains a special header `Accept-CH-Lifetime` with decimal number 80 and if we convert it to ascii, it is `P` and then I check the second packets is `W`. So I guess that the flag is the ascii of the `Accept-CH-Lifetime` of each packet of the request.

I use the following script to extract the `.pcap` file. And then change the decimal number to ascii.

```bash
tick-tock % tshark -r TickTock.pcap -Y 'http' -T fields -e http.request.line | sed -n 's/.*Accept-CH-Lifetime: \([0-9]*\).*/\1/p' > out
```
