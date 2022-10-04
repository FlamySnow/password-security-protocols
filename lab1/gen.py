import sys
import os.path
from Crypto.Random import get_random_bytes
from Hash_Functions import calculate

supported_encodings = ['utf8', 'utf-16', 'utf-16-le', 'utf-16-be', 'ascii']

if len(sys.argv) != 6:
    print("Error! Enter 5 parameters: file with passwords, encoding, hash function, number of output values, "
          "name of output file.")
    exit(-1)

str_file = sys.argv[1]
in_encoding = sys.argv[2]
function = sys.argv[3]
number = int(sys.argv[4])
str_output = sys.argv[5]

if in_encoding not in supported_encodings:
    print("{} is not supported encoding.".format(in_encoding) +
          "Please try these: {}".format(str(supported_encodings)))
    exit(-1)

if number < 1:
    print("Error! Enter number above zero.")
    exit(-1)

try:
    output = open(str_output, 'w')
    num_of_lines = 0
    if os.path.isfile(str_file):
        file = open(str_file, 'r', encoding=in_encoding)
        passwords = file.read().splitlines()
        for line in passwords:
            result = calculate(line.encode(in_encoding), function)
            output.write(result.hex() + '\n')
            num_of_lines += 1
            if num_of_lines >= number:
                break
        file.close()
    else:
        print("Warning! Input file doesn't exist. All values will be pseudorandom.")
    if num_of_lines < number:
        for i in range(num_of_lines, number):
            data = get_random_bytes(50)
            result = calculate(data, function)
            output.write(result.hex() + '\n')
    output.close()
except Exception as e:
    print(e)
