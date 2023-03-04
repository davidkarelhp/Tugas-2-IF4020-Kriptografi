import math
import numpy as np

def encrypt(plaintext: bytes, key: bytes):
    if (len(key) != 16):
        raise(Exception("Key length has to be 128 bit (16 bytes)"))
    
    if (len(plaintext) % 16 != 0):
        raise(Exception("Plaintext length has to be multiple of 128 bit (16 bytes)"))
    
    ciphertext = bytearray()
    blocks = splitBytesIntoBlocks(plaintext)

    splitKey1, splitKey2 = split128BitTo64Bit(key)
    keyMatrix = generateMatrixFrom64Bit(XOR(splitKey1, splitKey2))

    for block in blocks:
        block = XOR(block, key)
        left, right = split128BitTo64Bit(block)
        for i in range(16):
            rightMatrix = generateMatrixFrom64Bit(right)
            roundKey = np.multiply(rightMatrix, keyMatrix).transpose() % 16

            tempRight = right
            right = cipherFunctionEncrypt(left, roundKey)
            left = tempRight

        blockBytes = bytearray(left)
        blockBytes.extend(right)
        blockBytes = XOR(blockBytes, key)

        ciphertext.extend(blockBytes)

    return ciphertext

def decrypt(ciphertext: bytes, key: bytes):
    if (len(key) != 16):
        raise(Exception("Key length has to be 128 bit (16 bytes)"))

    if (len(ciphertext) % 16 != 0):
        raise(Exception("Ciphertext length has to be multiple of 128 bit (16 bytes)"))
    
    plaintext = bytearray()
    blocks = splitBytesIntoBlocks(ciphertext)
    
    splitKey1, splitKey2 = split128BitTo64Bit(key)
    keyMatrix = generateMatrixFrom64Bit(XOR(splitKey1, splitKey2))

    for block in blocks:
        block = XOR(block, key)
        left, right = split128BitTo64Bit(block)
        for i in range(16):
            leftMatrix = generateMatrixFrom64Bit(left)
            roundKey = np.multiply(leftMatrix, keyMatrix).transpose() % 16

            tempLeft = left
            left = cipherFunctionDecrypt(right, roundKey)
            right = tempLeft

        blockBytes = bytearray(left)
        blockBytes.extend(right)
        blockBytes = XOR(blockBytes, key)
        
        plaintext.extend(blockBytes)

    return plaintext

def cipherFunctionEncrypt(left, roundKey):
    playfairMap = fillPlayFairMatrix(roundKey)

    bigrams = split64BitTo4BitBigrams(left)
    ret = bytearray()

    for bigram in bigrams:
        first, second = playfairAlgorithmEncrypt(bigram, roundKey, playfairMap)
        ret.append((first << 4) | second)

    return ret

def cipherFunctionDecrypt(left, roundKey):
    playfairMap = fillPlayFairMatrix(roundKey)

    bigrams = split64BitTo4BitBigrams(left)
    ret = bytearray()

    for bigram in bigrams:
        first, second = playfairAlgorithmDecrypt(bigram, roundKey, playfairMap)
        ret.append((first << 4) | second)

    return ret

def playfairAlgorithmEncrypt(bigram, matrix, playfairMap):
    retFirst = 0
    retSecond = 0

    first = bigram[0]
    second = bigram[1]

    if playfairMap[first][0] == playfairMap[second][0]:
        retFirst = matrix[playfairMap[first][0]][(playfairMap[first][1] + 1) % 4]
        retSecond = matrix[playfairMap[second][0]][(playfairMap[second][1] + 1) % 4]
    
    elif playfairMap[first][1] == playfairMap[second][1]:
        retFirst = matrix[(playfairMap[first][0] + 1) % 4][playfairMap[first][1]]
        retSecond = matrix[(playfairMap[second][0] + 1) % 4][playfairMap[second][1]]
    
    else:
        retFirst = matrix[playfairMap[first][0]][playfairMap[second][1]]
        retSecond = matrix[playfairMap[second][0]][playfairMap[first][1]]
    
    return retFirst, retSecond

def playfairAlgorithmDecrypt(bigram, matrix, playfairMap):
    retFirst = 0
    retSecond = 0

    first = bigram[0]
    second = bigram[1]

    if playfairMap[first][0] == playfairMap[second][0]:
        retFirst = matrix[playfairMap[first][0]][(playfairMap[first][1] - 1) % 4]
        retSecond = matrix[playfairMap[second][0]][(playfairMap[second][1] - 1) % 4]
    
    elif playfairMap[first][1] == playfairMap[second][1]:
        retFirst = matrix[(playfairMap[first][0] - 1) % 4][playfairMap[first][1]]
        retSecond = matrix[(playfairMap[second][0] - 1) % 4][playfairMap[second][1]]
    
    else:
        retFirst = matrix[playfairMap[first][0]][playfairMap[second][1]]
        retSecond = matrix[playfairMap[second][0]][playfairMap[first][1]]
    
    return retFirst, retSecond

def fillPlayFairMatrix(matrix: np.ndarray[np.int32]):
    ret = {}
    existInMatrix = set()
    emptyIndex = set()

    for i in range(len(matrix)):
        for j in range(len(matrix[0])):
            if (matrix[i][j] not in existInMatrix):
                existInMatrix.add(matrix[i][j])
                ret[matrix[i][j]] = [i, j]
            else:
                emptyIndex.add(i * 4 + j)

    numberFill = 0
    for element in emptyIndex:
        while numberFill < 16:
            if numberFill not in existInMatrix:
                i = element // 4
                j = element - ((element // 4) * 4)
                matrix[i][j] = numberFill
                existInMatrix.add(numberFill)
                ret[numberFill] = [i, j]
                break
            
            numberFill += 1

    return ret

def generateMatrixFrom64Bit(byte: bytes):
    matrix = []
    for i in range(8):
        if i % 2== 0:
            matrix.append([])

        first, second = split8BitTo4Bit(byte[i])
        matrix[math.floor(i / 2.0)].append(first)
        matrix[math.floor(i / 2.0)].append(second)

    return np.array(matrix, np.int32)

def split8BitTo4Bit(byte: int):
    first = byte >> 4
    second = (byte & 0x0F)
    return first, second

def split128BitTo64Bit(byte: bytes):
    return byte[:8], byte[8:]

def split64BitTo4BitBigrams(byte: bytes):
    ret = []

    for element in byte:
        first, second = split8BitTo4Bit(element)
        ret.append([first, second])
    
    return ret

def splitBytesIntoBlocks(byte: bytes) -> list[bytes]:
    ret = []
    byteLen = len(byte)
    numOfBlocks = math.ceil(byteLen / 16.0)

    for i in range(numOfBlocks):
        if i != numOfBlocks - 1:
            ret.append(byte[i * 16:((i * 16) + 16)])
        else:
            ret.append(byte[i * 16:])
    
    return ret

def XOR(byte1: bytes, byte2: bytes):
    return bytes(a ^ b for a, b in zip(byte1, byte2))

def AND(byte1: bytes, byte2: bytes):
    return bytes(a & b for a, b in zip(byte1, byte2))

def main():
    inputString = "plaintext yang sangat panjang lo"
    key = "MBCHc1RWuPJIDxn0"

    resultEncrpyt = encrypt(bytes(inputString, "utf-8"), bytes(key, "utf-8"))
    resultDecrypt = decrypt(resultEncrpyt, bytes(key, "utf-8"))

    print(f"Encrypted Bytes = {resultEncrpyt}")
    print(f'Encrypted String = {resultEncrpyt.decode("utf-8", errors="replace")}')
    print(f"Decrypted Bytes = {resultDecrypt}")

if __name__ == "__main__":
    main()