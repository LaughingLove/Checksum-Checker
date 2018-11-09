import hashlib
import sys

# Getting md5 checksum
def md5(fname):
    hash_md5 = hashlib.md5()
    try:
        # Opening it, reading it and passing it to hash_md5
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
    except FileNotFoundError:
        # If the filename given is not found on the computer then the program will exit
        print("The file location you gave does not exist!")
        sys.exit(0)
    return hash_md5.hexdigest()

# Basically the same thing as md5 func but for different hashes

def sha_1(fname):
    hash_sha1 = hashlib.sha1()
    try:
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha1.update(chunk)
    except FileNotFoundError:
        print("The file location you gave does not exist!")
        sys.exit(0)
    return hash_sha1.hexdigest()

def sha_256(fname):
    hash_sha256 = hashlib.sha256()
    try:
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
    except FileNotFoundError:
        print("The file location you gave does not exist!")
        sys.exit(0)
    return hash_sha256.hexdigest()

def sha_512(fname):
    hash_sha512 = hashlib.sha512()
    try:
        with open(fname, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha512.update(chunk)
    except FileNotFoundError:
        print("The file location you gave does not exist!")
        sys.exit(0)
    return hash_sha512.hexdigest()


def main():
    # Opening statements
    print("Welcome to the checksum checker! This is where you can check for specific files' hashes or verify it with another hash!")
    print("")
    print("Checksum Checker")
    print("1.) Find hash of a file")
    print("2.) Verify a checksum of a file with a given hash.")
    option = input("Please select an option! ")
    
    # Checking if it's a digit
    if not option.isdigit():
        print("The option has to be a number! (e.g. 1)")
        return

    # If it's option 1 we're just gonna return all the hashes that were generated using the funcs about main()
    if option == "1":
        file_name = input("Please give the location of the file: ")

        md5_hash = md5(file_name)
        sha1_hash = sha_1(file_name)
        sha256_hash = sha_256(file_name)
        sha512_hash = sha_512(file_name)

        print("MD5: {}".format(md5_hash))
        print("SHA-1: {}".format(sha1_hash))
        print("SHA-256: {}".format(sha256_hash))
        print("SHA-512: {}".format(sha512_hash))
    # If it's option 2 we're gonna get all the hases, put them in a dict, then just iterate over the dict until we find a match.
    elif option == "2":
        file_name = input("Please give the location of the file: ")

        md5_hash = md5(file_name)
        sha1_hash = sha_1(file_name)
        sha256_hash = sha_256(file_name)
        sha512_hash = sha_512(file_name)

        checksums = {
            "MD5": md5_hash,
            "SHA-1": sha1_hash,
            "SHA-256": sha256_hash,
            "SHA-512": sha512_hash
        }

        checksum = input("Input the checksum that you already have (The supported checksums are MD5, SHA-1, SHA-256, and SHA-512): ")
        # Iterating of the dict to see if we find a match
        for key, value in checksums.items():
            if value == checksum:
                print("--------------------")
                print("{} CHECKSUM MATCHED!".format(key))
                print("--------------------")
                sys.exit(1)

        print("--------------------")
        print("NO CHECKSUMS MATCHED")
        print("--------------------")  

if __name__ == "__main__":
    main()