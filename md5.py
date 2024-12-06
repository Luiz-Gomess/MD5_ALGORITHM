import hashlib
import math

# Rotação em bits usada em cada etapa do processamento
ROTATE_BY = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
]

# Constantes derivadas dos valores absolutos do seno, escaladas e convertidas para 32 bits
CONSTANTS = [int(abs(math.sin(i + 1)) * 4294967296) for i in range(64)]

# Estado inicial do buffer MD5
MD_BUFFERS = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]


def pad_message(message):
    """Aplica o padding ao final da mensagem para atender às especificações do MD5."""
    # print(len(message))
    message_len_bits = (8 * len(message))
    # print(message_len_bits)
    message.append(128)
    # print(len(message))

    # Preenche com zeros até que o comprimento seja congruente a 448 mod 512
    while len(message) % 64 != 56:
        message.append(0)
    # print(len(message))

    # Anexa o comprimento original da mensagem em bits como um inteiro de 64 bits (little-endian)
    message += message_len_bits.to_bytes(8, byteorder='little')
    
    return message


def left_rotate(value, shift):
    """Realiza uma rotação de bits para a esquerda."""
    value &= 0xFFFFFFFF
    return ((value << shift) | (value >> (32 - shift)))


def process_block(message):
    print(len(message))
    """Processa cada bloco de 512 bits da mensagem."""
    buffer_copy = MD_BUFFERS[:]
    count = 0
    #idb512 = início do bloco de 512 bits/64 bytes
    for idb512 in range(0, len(message), 64):

        count += 1
        A, B, C, D = buffer_copy
        bloco = message[idb512:idb512 + 64]

        for i in range(64):
            if i < 16:
                F = (B & C) | (~B & D)
                g = i
            elif i < 32:
                F = (D & B) | (~D & C)
                g = (5 * i + 1) % 16
            elif i < 48:
                F = B ^ C ^ D
                g = (3 * i + 5) % 16
            else:
                F = C ^ (B | ~D)
                g = (7 * i) % 16

            to_rotate = A + F + CONSTANTS[i] + int.from_bytes(bloco[4 * g:4 * g + 4], byteorder='little')
            A, B, C, D = D, (B + left_rotate(to_rotate, ROTATE_BY[i])), B, C

        # Atualiza o buffer_copy com os resultados do bloco processado
        for i, val in enumerate([A, B, C, D]):
            buffer_copy[i] = (buffer_copy[i] + val) & 0xFFFFFFFF

    # Constrói o digest final
    # print(count)
    return sum(val << (32 * i) for i, val in enumerate(buffer_copy))


def digest_to_hex(digest):
    """Converte o digest em uma string hexadecimal de 128 bits."""
    raw = digest.to_bytes(16, byteorder='little')
    return '{:032x}'.format(int.from_bytes(raw, byteorder='big'))


def md5(message):
    """Calcula o hash MD5 de uma mensagem de entrada."""
    message_bytes = bytearray(message, 'ascii')
    padded_message = pad_message(message_bytes)
    digest = process_block(padded_message)
    return digest_to_hex(digest)


if __name__ == "__main__":
    input_message = "ABCD"
    custom_hash = md5(input_message)
    print("Custom MD5 Hash:", custom_hash)

    # Validação com a implementação oficial
    official_hash = hashlib.md5(input_message.encode()).hexdigest()
    print("Official MD5 Hash:", official_hash)
    print(official_hash == custom_hash)
