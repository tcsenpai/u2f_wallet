import binascii

# Can generate a mnemonic seed from data of 16, 20, 24, 28 or 32 bytes
def gen_from_data(data):
    # Checking if the data length is correct
    if len(data) not in [16, 20, 24, 28, 32]:
        raise ValueError(
         "Data length should be one of the following: [16, 20, 24, 28, 32], but it is not (%d).” % len(data)"
        )
    
    # Converting the data to binary
    bindata = bin(int(binascii.hexlify(data), 16))[2:].zfill(8 * len(data))
    
    # Opening wordlist
    with open("data/wordlist.txt", "r") as f:
         wordlist = [w.strip() for w in f.readlines()]
    # Generating a seed from the binary data
    seed = []
    for i in range(len(bindata)//11):
        index = int(bindata[11*i:11*(i+1)],2)
        seed.append(wordlist[index])
    return seed