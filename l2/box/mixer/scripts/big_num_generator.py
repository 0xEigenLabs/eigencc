import json
from random import getrandbits
def generate_random_number(length=1024):
    p = 4

    # generate random bits
    p = getrandbits(length)
    # apply a mask to set MSB and LSB to 1
    p |= (1 << length - 1) | 1

    return p

if __name__ == "__main__":
    input_nums = []
    for i in range(8):
        input_nums.append(str(generate_random_number(154)))
    with open("/tmp/.nums.json", "w") as f:
        f.write(json.dumps(input_nums))
    print(input_nums)
