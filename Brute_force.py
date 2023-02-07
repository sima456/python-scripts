import hashlib, os

type_of_hash = str(input('Enter type of hash you want to bruteforce (md5, sha1, sha256, sha512): '))
file_path = str(input('Enter path to the file to bruteforce with: '))
hash_to_decrypt = str(input('Enter hash value to bruteforce: '))

if os.path.exists(file_path) == False:
    print('[!!] That File/Path Doesnt Exist')
    exit(1)

with open(file_path, 'r') as file:
    for line in file.readlines():
        if type_of_hash == 'md5':
            hash_object = hashlib.md5(line.strip().encode())
            hashed_word = hash_object.hexdigest()
            if hashed_word == hash_to_decrypt:
                print('Found MD5 Password: ' + line.strip())
                exit(0)

        elif type_of_hash == 'sha1':
            hash_object = hashlib.sha1(line.strip().encode())
            hashed_word = hash_object.hexdigest()
            if hashed_word == hash_to_decrypt:
                print('Found SHA1 Password: ' + line.strip())
                exit(0)

        elif type_of_hash == 'sha256':
            hash_object = hashlib.sha256(line.strip().encode())
            hashed_word = hash_object.hexdigest()
            if hashed_word == hash_to_decrypt:
                print('Found SHA256 Password: ' + line.strip())
                exit(0)

        elif type_of_hash == 'sha512':
            hash_object = hashlib.sha512(line.strip().encode())
            hashed_word = hash_object.hexdigest()
            if hashed_word == hash_to_decrypt:
                print('Found SHA512 Password: ' + line.strip())
                exit(0)

        else:
            print('[!!] Type of Hash is Incorrect.')
            exit(1)

    print('Password Is Not In File.')
