from Hash_Functions import check_values
import sys
import os.path
import multiprocessing as mp
import time

process_number = mp.cpu_count()


if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("Error! Enter 4 parameters: file with passwords, encoding, hash function, file with hash values.")
        exit()

    if not os.path.isfile(sys.argv[1]):
        print("Error! File with passwords doesn't exist.")
        exit(-1)

    if not os.path.isfile(sys.argv[4]):
        print("Error! File with hash values doesn't exist.")
        exit(-1)

    supported_encodings = ['utf8', 'utf-16', 'utf-16-le', 'utf-16-be', 'ascii']

    in_encoding = sys.argv[2]

    if in_encoding not in supported_encodings:
        print("Error! {0} is not supported encoding. Try these: {1}".format(in_encoding, supported_encodings))
        exit(-1)

    passwords_file = open(sys.argv[1], 'r', encoding=in_encoding)

    hashes_file = open(sys.argv[4], 'r')

    try:
        hash_func = sys.argv[3]
        hashes = hashes_file.read().splitlines()
        hashes_file.close()
        b_hashes = []
        for i in range(0, len(hashes)):
            b_hashes.append(bytes.fromhex(hashes[i]))
        passwords = passwords_file.read().splitlines()
        b_passwords = [password.encode(encoding=in_encoding) for password in passwords]
        passwords_file.close()
        len_of_part = len(passwords) // (process_number - 1)
        password_groups = [b_passwords[i:i + len_of_part] for i in range(0, len(b_passwords), len_of_part)]
        processes = []
        cur_time = time.time()
        for group in password_groups:
            process = mp.Process(target=check_values, args=(group, b_hashes, in_encoding, hash_func))
            process.start()
            processes.append(process)
        for process in processes:
            process.join()
        wasted_time = time.time() - cur_time
        print("Time: {}".format(wasted_time))
    except Exception as error:
        print(error)
