import hashlib
import math
import time


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

CONSTANTS = [int(abs(math.sin(i + 1)) * 4294967296) for i in range(64)]

# Essa lista contém os quatro valores iniciais (em hexadecimal) utilizados como vetores de estado do algoritmo MD5.
# Esses valores são conhecidos como buffers `a`, `b`, `c` e `d` e representam o estado interno do hash
# ao longo do processamento da mensagem.

MD_BUFFERS = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]


def rotacao_a_esquerda(valor, qtde):
    """
    Realiza uma rotação de bits para a esquerda.

    Args:
        valor (int): O valor de 32 bits a ser rotacionado.
        qtde (int): a quantidade de bits pela qual o valor será rotacionado para a esquerda.

    Returns:
        int: O resultado da rotação, garantindo que seja um valor de 32 bits.
    """

    # Aplica um truncamento ao valor, garantindo que ele tenha 32 bits.
    valor &= 0xFFFFFFFF

    # Realiza a rotação para a esquerda. Mova os bits para esquerda n posições de acordo com o parâmetro 'qtde'.
    # Os bits que saírem do alcance de 32 bits irão ser direcionados para a direita (final da mensagem),
    # garantindo um rotaionamento dos bits. Ao final, une as duas partes por meio do operador '|'.
    return ((valor << qtde) | (valor >> (32 - qtde)))



def padding(message):
    """
    Aplica o padding ao final da mensagem.
    Para que a mensagem passe para a etapa do hashing em si, é necessário que ela esteja no tamanho padrão de 512 bits.
    Para isso, adiciona-se o bit 1 a mensagem e finitos numeros 0 até que a mensagem esteja com um tamanho de 448 bits 
    modulo 512, ou seja, que a mensagem possua 64 bits a menos que o multilo mais próximo de 512.

    Args:
        message (bytearray): a mensagem original como uma sequência de bytes.

    Returns:
        bytearray: a mensagem com o padding aplicado.
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
        message (bytearray): a mensagem de entrada já preenchida (padded) e em múltiplos de 512 bits (64 bytes).

    Returns:
        int: O valor hash intermediário após processar todos os blocos da mensagem.
    """
    # Cria uma cópia dos valores iniciais do estado (buffers a, b, c e d) definidos em MD_BUFFERS.
    buffer_copy = MD_BUFFERS[:]

    # Itera sobre cada bloco de 512 bits (64 bytes) da mensagem.
    for idb512 in range(0, len(message), 64):

        # Inicializa os buffers a, b, c e d com os valores atuais do estado.
        a, b, c, d = buffer_copy

        # Extrai o bloco atual de 512 bits (64 bytes) da mensagem.
        bloco = message[idb512:idb512 + 64]

        # Executa 64 iterações de transformação para o bloco atual.
        for i in range(64):
            # Aplica uma das quatro funções bit a bit f, G, H ou I dependendo da iteração.
            # A variável g é utilzada para acessar blocos da mensagem de forma não-linear. 
            if i < 16:
                f = (b & c) | (~b & d) #Função f
                g = i
            elif i < 32:
                f = (d & b) | (~d & c) #Função G
                g = (5 * i + 1) % 16
            elif i < 48:
                f = b ^ c ^ d  #Função H
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | ~d) #Função I
                g = (7 * i) % 16

            # Calcula o valor a ser rotacionado.
            # Inclui o buffer atual (a), o valor f, uma constante específica da iteração e 
            # um valor derivado do bloco de 512 bits.
            to_rotate = a + f + CONSTANTS[i] + int.from_bytes(bloco[4 * g:4 * g + 4], byteorder='little')

            # Realiza a rotação à esquerda e atualiza os valores dos buffers a, b, c e d.
            d_temp = d
            d = c
            c = b
            b = (b + rotacao_a_esquerda(to_rotate, ROTATE_BY[i])) & 0xFFFFFFFF 
            a = d_temp
            # O valor 0xFFFFFFFF é necessário para garantir que os valores tenham 32 bits, visto que python consegue trabalhar com numeros maiores.


        # Após processar todas as 64 iterações, atualiza os valores dos buffers no estado.
        for i, val in enumerate([a, b, c, d]):
            buffer_copy[i] = (buffer_copy[i] + val) & 0xFFFFFFFF

    # Combina os valores finais dos buffers a, b, c e d em um único hash de 128 bits.
    return sum(val << (32 * i) for i, val in enumerate(buffer_copy))



def digest_para_hexa(digest):
    """Converte o digest em uma string hexadecimal de 128 bits."""
    raw = digest.to_bytes(16, byteorder='little')
    return '{:032x}'.format(int.from_bytes(raw, byteorder='big'))               


def md5(message):
    """Calcula o hash MD5 de uma mensagem de entrada."""
    message_bytes = bytearray(message, 'ascii')
    padded_message = padding(message_bytes)
    digest = process_block(padded_message)
    return digest_para_hexa(digest)


if __name__ == "__main__":

    messagem = "MD5"

    #-----Teste de validação---------

    # Mede o tempo da implementação customizada
    md5_customizado = md5(messagem)
    print("MD5 Implementado:", md5_customizado)

    # Mede o tempo da implementação oficial
    md5_hashlib = hashlib.md5(messagem.encode()).hexdigest()
    print("MD5 hashlib:", md5_hashlib)

    # Compara os resultados
    print("É igual ?", md5_hashlib == md5_customizado)

    #-----Testes de tempo de execução com entrada maior-----

    entrada_grande = open("entrada_md5.txt", 'r')
    texto = entrada_grande.read()

    inicio_customizado = time.time()
    md5_customizado = md5(texto)
    fim_customizado = time.time()
    print("MD5 Implementado:", md5_customizado)
    print("Tempo de execução (customizado): {:.6f} segundos".format(fim_customizado - inicio_customizado))

    inicio_hashlib = time.time()
    md5_hashlib = hashlib.md5(texto.encode()).hexdigest()
    fim_hashlib = time.time()
    print("MD5 hashlib:", md5_hashlib)
    print("Tempo de execução (hashlib): {:.6f} segundos".format(fim_hashlib - inicio_hashlib))

    print("É igual ?", md5_hashlib == md5_customizado)

    #-----Testes de imutabilidade-------

    menssagem_1 = "MD5"
    menssagem_2 = "mD5"

    md5_customizado = md5(menssagem_1)
    print("MD5 Implementado:", md5_customizado)

    md5_hashlib = hashlib.md5(menssagem_2.encode()).hexdigest()
    print("MD5 hashlib:", md5_hashlib)

    print("É igual ?", md5_hashlib == md5_customizado)






