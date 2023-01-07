import argparse                                            import hashlib

# Set up the argument parser
parser = argparse.ArgumentParser()
parser.add_argument("file", help="the file to calculate the hashes of")
args = parser.parse_args()

# Open the file in binary mode
with open(args.file, "rb") as file:
    # Read the contents of the file
    content = file.read()

    # Calculate the SHA-256 hash
    sha256_hash = hashlib.sha256(content).hexdigest()

    # Calculate the SHA-1 hash
    sha1_hash = hashlib.sha1(content).hexdigest()

    # Calculate the MD5 hash
    md5_hash = hashlib.md5(content).hexdigest()

print(f"SHA-256 hash: {sha256_hash}")
print(f"SHA-1 hash: {sha1_hash}")
print(f"MD5 hash: {md5_hash}")
