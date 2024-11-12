from pypuf.simulation import XORArbiterPUF
from pypuf.io import random_inputs
import numpy as np
import random
import sys

g_dbg = False

def puf_log(msg):
        if g_dbg:
                print(msg)

if __name__ == "__main__":
    puf_log(f"Arguments count: {len(sys.argv)}")
    for i, arg in enumerate(sys.argv):
        puf_log(f"Argument {i:>6}: {arg}")


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
# puf_log(bit_array)

# Generate random number
# random.randint(0, 255)

puf = XORArbiterPUF(n=8, k=2, seed=3)
# challenges = random_inputs(n=8, N=32, seed=3) # Pypuf challenges generator
# challenges_new = np.array([[-1, 1, 1, 1, -1, -1, 1, 1],[1, 1, 1, -1, -1, 1, 1, 1]]) # Using custom byte arrays
challenges_new = np.array([int_to_bit_array(int(arg)) for arg in sys.argv[1:]]) # Create appropriate byte arrays for each command line argument
puf_log(challenges_new)
resp = puf.eval(challenges_new)
# puf_log(challenges)
puf_log("RESPONSES:")
puf_log(resp)


# Generate a number from adding response bits (also converting pypuf bit format to regular format)
out = 0

for resp_bit in resp:
        if resp_bit == -1:
                resp_bit = 0
        else:
                resp_bit = 1
        # puf_log("got a bit ", resp_bit)
        out = (out << 1 ) | resp_bit
        # puf_log('{:032b}'.format(out))

# Print all answers appended to each, intented to be a 32bit unsigned integer
print(out)
