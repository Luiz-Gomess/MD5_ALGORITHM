import hashlib
import math


# Contém os valores de deslocamento utilizados nas operações de rotação à esquerda
# durante cada uma das 64 iterações da etapa de digest.
ROTATE_BY = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,  # Primeira rodada
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,  # Segunda rodada
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,  # Terceira rodada
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21   # Quarta rodada
]



# Contém 64 valores pré-calculados usados durante o processamento de cada uma das 64 iterações da etapa de digest.
# Eles são derivados das funções seno (sin) para garantir que os valores sejam pseudo-aleatórios e bem distribuídos.

# Como os valores são gerados:
# - Para cada índice `i` (de 0 a 63), o valor absoluto do seno de `(i + 1)` é calculado.
# - O valor do seno é multiplicado por 2^32 (4294967296) e convertido em um inteiro.
#   Isso garante que os valores sejam números inteiros de 32 bits.
# - Essa abordagem usa o seno como uma função matemática "imprevisível" para gerar constantes únicas.

# Significado:
# - Os valores gerados fornecem um conjunto fixo de números que são usados para adicionar variação
#   ao cálculo do hash em cada iteração.
# - Isso torna o algoritmo mais resistente a padrões previsíveis e ajuda a espalhar os bits da mensagem original.

# Observação:
# - A fórmula `math.sin(i + 1)` usa `i + 1` porque o índice `i` em Python começa em 0,
#   mas o MD5 usa índices começando em 1 para calcular os senos.
# - Os valores são multiplicados por 2^32 porque o algoritmo opera com números de 32 bits.

CONSTANTS = [int(abs(math.sin(i + 1)) * 4294967296) for i in range(64)]


# Constante MD_BUFFERS:
# Essa lista contém os quatro valores iniciais (em hexadecimal) utilizados como vetores de estado do algoritmo MD5.
# Esses valores são conhecidos como buffers `A`, `B`, `C` e `D` e representam o estado interno do hash
# ao longo do processamento da mensagem.

# Valores iniciais:
# - Esses valores foram definidos na especificação original do MD5 (RFC 1321).
# - Cada valor é um número inteiro de 32 bits, representado em formato hexadecimal:
#   - 0x67452301: Representa o buffer A
#   - 0xefcdab89: Representa o buffer B
#   - 0x98badcfe: Representa o buffer C
#   - 0x10325476: Representa o buffer D

# Significado:
# - Os valores iniciais são cuidadosamente escolhidos para garantir que o algoritmo seja determinístico
#   e funcione corretamente para todas as entradas possíveis.
# - Durante o processamento da mensagem, esses valores serão constantemente atualizados
#   com base nas operações realizadas em cada bloco de 512 bits.

# Função dos buffers:
# - Cada buffer armazena uma parte intermediária do estado do hash.
# - No final do processamento, os valores finais de A, B, C e D são concatenados para formar o hash MD5,
#   que tem um tamanho fixo de 128 bits (32 caracteres em formato hexadecimal).

# Exemplo:
# - A mensagem de entrada é dividida em blocos de 512 bits.
# - Para cada bloco, os valores de A, B, C e D são atualizados com base nas operações do algoritmo.
# - Os valores finais desses buffers formam o hash da mensagem.

MD_BUFFERS = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]


def rotacao_a_esquerda(valor, qtde):
    """
    Realiza uma rotação de bits para a esquerda.

    Args:
        valor (int): O valor de 32 bits a ser rotacionado.
        qtde (int): A quantidade de bits pela qual o valor será rotacionado para a esquerda.

    Returns:
        int: O resultado da rotação, garantindo que seja um valor de 32 bits.
    """

    # Garante que o valor esteja limitado a 32 bits (4 bytes)
    # Isso é feito aplicando uma máscara com 0xFFFFFFFF (32 bits com todos os bits em 1).
    # Isso é necessário porque em Python os inteiros podem crescer além de 32 bits.
    valor &= 0xFFFFFFFF

    # Realiza a rotação para a esquerda:
    # - `valor << qtde`: Move os bits do valor para a esquerda em `qtde` posições.
    # - `valor >> (32 - qtde)`: Move os bits que "sairam" pela esquerda para a direita,
    #    para que eles reapareçam do lado direito.
    # - O operador `|` combina os bits dos dois resultados.
    # O resultado final é uma rotação, e não um deslocamento simples.
    return ((valor << qtde) | (valor >> (32 - qtde)))



def pad_message(message):
    """
    Aplica o padding ao final da mensagem para atender às especificações do algoritmo MD5.

    O algoritmo MD5 exige que a mensagem de entrada tenha um comprimento total múltiplo de 512 bits (64 bytes)
    após o preenchimento. Este processo de padding é feito seguindo as seguintes etapas:
    1. Adicionar um bit `1` ao final da mensagem.
    2. Adicionar bits `0` até que o comprimento da mensagem (em bytes) seja congruente a 56 (mod 64).
    3. Acrescentar o comprimento original da mensagem (em bits) em 64 bits (8 bytes), no formato little-endian.

    Args:
        message (bytearray): A mensagem original como uma sequência de bytes.

    Returns:
        bytearray: A mensagem com o padding aplicado.
    """
    # Calcula o comprimento da mensagem original em bits.
    message_len_bits = (8 * len(message))

    # Adiciona o byte `0x80` (128 em decimal) ao final da mensagem.
    # Esse byte representa o bit `1` seguido de sete bits `0`.
    message.append(128)

    # Preenche a mensagem com bytes `0x00` até que seu comprimento (em bytes) seja congruente a 56 (mod 64).
    # Isso deixa espaço suficiente para os 8 bytes que serão adicionados ao final.
    while len(message) % 64 != 56:
        message.append(0)

    # Converte o comprimento original da mensagem (em bits) para um valor de 8 bytes (64 bits) no formato little-endian
    # e adiciona ao final da mensagem.
    # O formato little-endian armazena o valor com o byte menos significativo primeiro.
    message += message_len_bits.to_bytes(8, byteorder='little')

    # Retorna a mensagem com o padding completo.
    return message


def process_block(message):
    """
    Processa cada bloco de 512 bits da mensagem de entrada conforme o algoritmo MD5.

    Args:
        message (bytearray): A mensagem de entrada já preenchida (padded) e em múltiplos de 512 bits (64 bytes).

    Returns:
        int: O valor hash intermediário após processar todos os blocos da mensagem.
    """
    print(len(message))  # Para depuração, exibe o comprimento total da mensagem.

    # Cria uma cópia dos valores iniciais do estado (buffers A, B, C e D) definidos em MD_BUFFERS.
    buffer_copy = MD_BUFFERS[:]

    # Itera sobre cada bloco de 512 bits (64 bytes) da mensagem.
    for idb512 in range(0, len(message), 64):

        # Inicializa os buffers A, B, C e D com os valores atuais do estado.
        A, B, C, D = buffer_copy

        # Extrai o bloco atual de 512 bits (64 bytes) da mensagem.
        bloco = message[idb512:idb512 + 64]

        # Executa 64 iterações de transformação para o bloco atual.
        for i in range(64):
            # Aplica uma das quatro funções não-lineares F, G, H ou I dependendo da iteração.
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

            # Calcula o valor a ser rotacionado.
            # Inclui o buffer atual (A), o valor F, uma constante específica da iteração e 
            # um valor derivado do bloco de 512 bits.
            to_rotate = A + F + CONSTANTS[i] + int.from_bytes(bloco[4 * g:4 * g + 4], byteorder='little')

            # Realiza a rotação à esquerda e atualiza os valores dos buffers A, B, C e D.
            A, B, C, D = D, (B + rotacao_a_esquerda(to_rotate, ROTATE_BY[i])) & 0xFFFFFFFF, B, C

        # Após processar todas as 64 iterações, atualiza os valores dos buffers no estado.
        for i, val in enumerate([A, B, C, D]):
            buffer_copy[i] = (buffer_copy[i] + val) & 0xFFFFFFFF

    # Combina os valores finais dos buffers A, B, C e D em um único hash de 128 bits.
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
