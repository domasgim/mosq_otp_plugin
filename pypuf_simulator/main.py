from pypuf.simulation import XORArbiterPUF
from pypuf.io import random_inputs
import numpy as np
import random

# challenges_new = [-1, 1, 1, 1, -1, -1, 1, 1]

def int_to_bit_array(num):
    # Ensure the number is within the 8-bit range (0 to 255)
    if 0 <= num <= 255:
        # Convert to binary, remove '0b' prefix, and pad with leading zeros to ensure 8 bits
        binary_str = format(num, '08b')
        # Convert each binary digit to an integer, replacing 0 with -1
        return [int(bit) if bit == '1' else -1 for bit in binary_str]
    else:
        raise ValueError("Number must be in the range 0-255 for an 8-bit integer.")

# Example usage of pypuf bit converter
# bit_array = int_to_bit_array(4)
# print(bit_array)

# Generate random number
# random.randint(0, 255)

puf = XORArbiterPUF(n=8, k=2, seed=3)
# challenges = random_inputs(n=8, N=32, seed=3) # Pypuf challenges generator
# challenges_new = np.array([[-1, 1, 1, 1, -1, -1, 1, 1],[1, 1, 1, -1, -1, 1, 1, 1]]) # Using custom byte arrays
challenges_new = np.array([int_to_bit_array(2),int_to_bit_array(13)]) # Last iteration; easy way to create appropriate byte arrays for each challenge
print(challenges_new)
resp = puf.eval(challenges_new)
# print(challenges)
print("RESPONSES:")
print(resp)


# Generate a number from adding response bits (also converting pypuf bit format to regular format)
out = 0

for resp_bit in resp:
        if resp_bit == -1:
                resp_bit = 0
        else:
                resp_bit = 1
        # print("got a bit ", resp_bit)
        out = (out << 1 ) | resp_bit
        # print('{:032b}'.format(out))

print(out)