import random

base_code = open("code_template/base.c", 'r').read()
main_code = open("code_template/main.c", 'r').read()
wrong_code = open("code_template/wrong.c", 'r').read()
correct_code = open("code_template/correct.c", 'r').read()
function_template = open("code_template/function_template.c", 'r').read()

crypto_functions = ['aes256', 'aes192', 'aes128', 'des', 'blowfish', 'rc4', 'xor']
key_iv_gen = {
    'aes256': lambda: (random.randbytes(32).hex(), random.randbytes(16).hex()),
    'aes192': lambda: (random.randbytes(24).hex(), random.randbytes(16).hex()),
    'aes128': lambda: (random.randbytes(16).hex(), random.randbytes(16).hex()),
    'des': lambda: (random.randbytes(8).hex(), random.randbytes(8).hex()),
    'blowfish': lambda: (random.randbytes(16).hex(), random.randbytes(8).hex()),
    'rc4': lambda: (random.randbytes(16).hex(), None),
    'xor': lambda: (random.randbytes(16).hex(), None),
}
candidate_char = [chr(i) for i in \
            list(range(ord('a'), ord('z')+1))+ \
            list(range(ord('A'), ord('Z')+1))+ \
            list(range(ord('0'), ord('9')+1))]

def generate_path():
    lengths = random.sample(range(1, 16), 3)
    while sum(lengths) > 31 or 32 - sum(lengths) > 15:
        lengths = random.sample(range(1, 16), 3)
    lengths.append(32 - sum(lengths))
    path = [''.join([random.choice(candidate_char) for i in range(length)]) for length in lengths]
    return path

def recursive_gen(path, correct, depth, algorithm='', key='', iv=''):
    if depth == 4:
        if correct:
            return [correct_code.format(algorithm=algorithm, key=key, iv=iv)]
        else:
            return [wrong_code.format(algorithm=algorithm, key=key, iv=iv)]
    selection = path[0]
    next_algorithm = [random.choice(crypto_functions) for i in range(6)]
    next_key_iv = [key_iv_gen[next_algorithm]() for next_algorithm in next_algorithm]
    next_key = [key_iv[0] for key_iv in next_key_iv]
    next_iv = [key_iv[1] for key_iv in next_key_iv]
    length = len(selection)
    random_str = [''.join([random.choice(candidate_char) for i in range(length)]) for i in range(6)]
    random_str[random.randint(0, 5)] = selection
    if correct:
        next_func = [recursive_gen(path[1:], random_str[i] == selection, depth+1, next_algorithm[i], next_key[i], next_iv[i]) for i in range(6)]
    else:
        next_func = [recursive_gen(path[1:], False, depth+1, next_algorithm[i], next_key[i], next_iv[i]) for i in range(6)]
    next_func = [item for sublist in next_func for item in sublist]
    next_key_decode = [''.join(['\\x'+k[i:i+2] for i in range(0, len(k), 2)]) for k in next_key]
    next_iv_decode = [''.join(['\\x'+v[i:i+2] for i in range(0, len(v), 2)]) if v else '' for v in next_iv]
    return next_func + [function_template.format(
        algorithm=algorithm, 
        key=key, iv=iv, 
        next_algorithm=next_algorithm, 
        next_key=next_key, 
        next_key_decode=next_key_decode,
        next_iv=next_iv, 
        next_iv_decode=next_iv_decode, 
        input_length=length, 
        random_str=random_str
    )]


def generate_code(path):
    recursive_code = recursive_gen(path, True, 0)
    recursive_code = '\n'.join(recursive_code)
    return base_code + recursive_code + main_code

if __name__ == '__main__':
    path = generate_path()
    code = generate_code(path)
    with open("code.c", 'w') as f:
        f.write(code)



