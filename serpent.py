'''
    TITLE: Serpent
    DESCRIPTION: This is a file for class Serpent algorithm,
    CAUTION: use only hexadecimal keys
'''

import re


class Serpent():
#     key should be hexadecimal and multiple of 16 upto 256
    def __init__(self, key):
        self.round_count = 32
        self.block_size = 128
        self.key_size = 128
        self.keys = self.generateRoundKeys(key, self.round_count, self.key_size)
        
#     block should be 128-bit binary data
    def encryptBlock(self, block):
        assert len(block) == self.block_size, f'Length of input block {len(block)} doesnot match block size {self.block_size} for encryption'

        BHati = self.IP(block)
        for i in range(self.round_count):
            BHati = self.round_(i, BHati, self.keys)
        cipher = self.FP(BHati)
        return cipher

#      block should be 128-bit binary data
    def decryptBlock(self, block):
        assert len(block) == self.block_size, f'Length of input block {len(block)} doesnot match block size {self.block_size} for decryption'

        BHatiPlus1 = self.IP(block)
        for i in range(self.round_count - 1, -1, -1):
            BHatiPlus1 = self.inverseRound_(i, BHatiPlus1, self.keys)
        plaintext = self.FP(BHatiPlus1)
        return plaintext

    def round_(self, i, BHat, KHat):
        xored = self.xor_(BHat, KHat[i])
        s_boxed = ''.join([self.S(i, xored[ind:ind + 4]) for ind in range(0, len(xored), 4)])

        if 0 <= i <= self.round_count - 2:
            transformed = self.linearTransformation(s_boxed)
        elif i == self.round_count - 1:
            transformed = self.xor_(s_boxed, KHat[self.round_count])
        else:
            raise ValueError(f'round number {i} out of range')
        return transformed

    def inverseRound_(self, i, transformed, KHat):
        if 0 <= i <= self.round_count - 2:
            to_s_box = self.linearTransformation(transformed, inverse=True)
        elif i == self.round_count - 1:
            to_s_box = self.xor_(transformed, KHat[self.round_count])
        else:
            raise ValueError(f'Invalid round number {i}')

        to_xor = ''.join([self.S(i, to_s_box[ind:ind + 4], inverse=True) for ind in range(0, len(to_s_box), 4)])
        output = self.xor_(to_xor, KHat[i])
        return output

    def linearTransformation(self, inp, inverse=False):
        assert len(inp) == 128, f'Length of input for Linear Transformation is not 128, but {len(inp)}'

        if inverse == False:
            table = LTTable
        else:
            table = LTInverseTable
        result = ''
        for array in table:
            outbit = '0'
            for array_element in array:
                outbit = self.xor_(outbit, inp[array_element])
            result += outbit
        return result

    def generateRoundKeys(self, key, round_count, key_size):
        # generate key of length key_size for each round
        binary_key = self.convertToBitstring(key, len(key) * 4)
        padded_key = self.makeLongKey(binary_key, 256)

        phi = 0x9e3779b9
        # Initializing w
        w = {}
        for i in range(-8, 0):
            w[i] = padded_key[(8 + i) * 32: (9 + i) * 32]

        # Prekey generation
        for i in range(132):
            w[i] = self.rotateLeft(
                self.xor_(w[i - 8], w[i - 5], w[i - 3], w[i - 1], self.bitstring(phi, 32), self.bitstring(i, 32)), 11)

        # Grouping prekey and generation of round keys
        K = []
        for i in range(round_count + 1):
            # each w element is 32-bi word
            # consider 4 words
            # group 4 corresponding words from considered 4 words
            # then send it to s-box
            s_box_num = (round_count + 3 - i) % round_count
            temp = [''] * 4
            for a, b, c, d in zip(w[(4 * i)], w[(4 * i) + 1], w[(4 * i) + 2], w[(4 * i) + 3]):
                s_box_input = a + b + c + d
                output = list(self.S(s_box_num, s_box_input))
                temp = [x + y for x, y in zip(temp, output)]
            K.append(''.join(temp))

        KHat = list(map(self.IP, K))
        return KHat

    def IP(self, inp):
        IPTable = [
            0, 32, 64, 96, 1, 33, 65, 97, 2, 34, 66, 98, 3, 35, 67, 99,
            4, 36, 68, 100, 5, 37, 69, 101, 6, 38, 70, 102, 7, 39, 71, 103,
            8, 40, 72, 104, 9, 41, 73, 105, 10, 42, 74, 106, 11, 43, 75, 107,
            12, 44, 76, 108, 13, 45, 77, 109, 14, 46, 78, 110, 15, 47, 79, 111,
            16, 48, 80, 112, 17, 49, 81, 113, 18, 50, 82, 114, 19, 51, 83, 115,
            20, 52, 84, 116, 21, 53, 85, 117, 22, 54, 86, 118, 23, 55, 87, 119,
            24, 56, 88, 120, 25, 57, 89, 121, 26, 58, 90, 122, 27, 59, 91, 123,
            28, 60, 92, 124, 29, 61, 93, 125, 30, 62, 94, 126, 31, 63, 95, 127,
        ]
        return self.applyPermutation(IPTable, inp)

    def FP(self, inp):
        FPTable = [
            0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60,
            64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124,
            1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61,
            65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125,
            2, 6, 10, 14, 18, 22, 26, 30, 34, 38, 42, 46, 50, 54, 58, 62,
            66, 70, 74, 78, 82, 86, 90, 94, 98, 102, 106, 110, 114, 118, 122, 126,
            3, 7, 11, 15, 19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59, 63,
            67, 71, 75, 79, 83, 87, 91, 95, 99, 103, 107, 111, 115, 119, 123, 127,
        ]
        return self.applyPermutation(FPTable, inp)

    def applyPermutation(self, table, inp):
        assert len(inp) == len(table), f'the length of input{len(input)} doesnot match with length of table {len(table)}'
        return ''.join([inp[table[i]] for i in range(len(table))])

    def S(self, box_num, inp, inverse=False):
        assert inverse in [True, False], 'Choose either True / False for Inverse'
        box_num = box_num % 8
        SBoxDecimalTable = [
            [3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12],  # S0
            [15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4],  # S1
            [8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2],  # S2
            [0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14],  # S3
            [1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13],  # S4
            [15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1],  # S5
            [7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0],  # S6
            [1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6],  # S7
        ]
        SBoxBitString = []
        InverseSBoxBitString = []
        for box in SBoxDecimalTable:
            Dict = {}
            InverseDict = {}
            for i in range(len(box)):
                ind = self.bitstring(i, 4)
                val = self.bitstring(box[i], 4)
                Dict[ind] = val
                InverseDict[val] = ind
            SBoxBitString.append(Dict)
            InverseSBoxBitString.append(InverseDict)

        if inverse == False:
            return SBoxBitString[box_num][inp]
        else:
            return InverseSBoxBitString[box_num][inp]

    def rotateLeft(self, word, shift):
        shift = shift % len(word)
        return word[-shift:] + word[:-shift]

    def xor_(self, *args):
        result = args[0]
        for arg in args[1:]:
            result = self.xor_2(result, arg)
        return result

    def xor_2(self, word1, word2):
        return ''.join(['1' if a != b else '0' for a, b in zip(word1, word2)])

    def bitstring(self, number, minlen=1):
        assert number >= 0, "can't derive bitstring for negative numbers"

        result = ''
        while number > 0:
            result += '1' if number & 1 else '0'
            number >>= 1

        if len(result) < minlen:
            result += '0' * (minlen - len(result))
        return result

    def hexstring2bitstring(self, hx):
        return ''.join(['{:04b}'.format(int(i, 16))[::-1] for i in hx[::-1]])  # reversing binary for little endian

    def convertToBitstring(self, hexa, fit):
        if re.match('^[0-9a-f]+$', hexa):
            bitstring = self.hexstring2bitstring(hexa)
        else:
            raise ValueError(f'{hexa} is not a valid hex key!')

        if len(bitstring) > fit:
            raise ValueError(f"bitstring is too large to fit in {fit} bits")
        else:
            bitstring += '0' * (fit - len(bitstring))

        return bitstring

    def makeLongKey(self, partial_key, minlen):
        assert len(partial_key) % 32 == 0 and len(partial_key) in range(64, minlen + 1), f'The length of key bitstring is not valid: {len(partial_key)}'

        if len(partial_key) == minlen:
            return partial_key
        elif len(partial_key) == minlen - 1:
            partial_key += '1'
            return partial_key
        else:
            partial_key += '1'
            partial_key += "0" * (minlen - len(partial_key))
            return partial_key


LTTable = [
    [16, 52, 56, 70, 83, 94, 105],
    [72, 114, 125],
    [2, 9, 15, 30, 76, 84, 126],
    [36, 90, 103],
    [20, 56, 60, 74, 87, 98, 109],
    [1, 76, 118],
    [2, 6, 13, 19, 34, 80, 88],
    [40, 94, 107],
    [24, 60, 64, 78, 91, 102, 113],
    [5, 80, 122],
    [6, 10, 17, 23, 38, 84, 92],
    [44, 98, 111],
    [28, 64, 68, 82, 95, 106, 117],
    [9, 84, 126],
    [10, 14, 21, 27, 42, 88, 96],
    [48, 102, 115],
    [32, 68, 72, 86, 99, 110, 121],
    [2, 13, 88],
    [14, 18, 25, 31, 46, 92, 100],
    [52, 106, 119],
    [36, 72, 76, 90, 103, 114, 125],
    [6, 17, 92],
    [18, 22, 29, 35, 50, 96, 104],
    [56, 110, 123],
    [1, 40, 76, 80, 94, 107, 118],
    [10, 21, 96],
    [22, 26, 33, 39, 54, 100, 108],
    [60, 114, 127],
    [5, 44, 80, 84, 98, 111, 122],
    [14, 25, 100],
    [26, 30, 37, 43, 58, 104, 112],
    [3, 118],
    [9, 48, 84, 88, 102, 115, 126],
    [18, 29, 104],
    [30, 34, 41, 47, 62, 108, 116],
    [7, 122],
    [2, 13, 52, 88, 92, 106, 119],
    [22, 33, 108],
    [34, 38, 45, 51, 66, 112, 120],
    [11, 126],
    [6, 17, 56, 92, 96, 110, 123],
    [26, 37, 112],
    [38, 42, 49, 55, 70, 116, 124],
    [2, 15, 76],
    [10, 21, 60, 96, 100, 114, 127],
    [30, 41, 116],
    [0, 42, 46, 53, 59, 74, 120],
    [6, 19, 80],
    [3, 14, 25, 100, 104, 118],
    [34, 45, 120],
    [4, 46, 50, 57, 63, 78, 124],
    [10, 23, 84],
    [7, 18, 29, 104, 108, 122],
    [38, 49, 124],
    [0, 8, 50, 54, 61, 67, 82],
    [14, 27, 88],
    [11, 22, 33, 108, 112, 126],
    [0, 42, 53],
    [4, 12, 54, 58, 65, 71, 86],
    [18, 31, 92],
    [2, 15, 26, 37, 76, 112, 116],
    [4, 46, 57],
    [8, 16, 58, 62, 69, 75, 90],
    [22, 35, 96],
    [6, 19, 30, 41, 80, 116, 120],
    [8, 50, 61],
    [12, 20, 62, 66, 73, 79, 94],
    [26, 39, 100],
    [10, 23, 34, 45, 84, 120, 124],
    [12, 54, 65],
    [16, 24, 66, 70, 77, 83, 98],
    [30, 43, 104],
    [0, 14, 27, 38, 49, 88, 124],
    [16, 58, 69],
    [20, 28, 70, 74, 81, 87, 102],
    [34, 47, 108],
    [0, 4, 18, 31, 42, 53, 92],
    [20, 62, 73],
    [24, 32, 74, 78, 85, 91, 106],
    [38, 51, 112],
    [4, 8, 22, 35, 46, 57, 96],
    [24, 66, 77],
    [28, 36, 78, 82, 89, 95, 110],
    [42, 55, 116],
    [8, 12, 26, 39, 50, 61, 100],
    [28, 70, 81],
    [32, 40, 82, 86, 93, 99, 114],
    [46, 59, 120],
    [12, 16, 30, 43, 54, 65, 104],
    [32, 74, 85],
    [36, 90, 103, 118],
    [50, 63, 124],
    [16, 20, 34, 47, 58, 69, 108],
    [36, 78, 89],
    [40, 94, 107, 122],
    [0, 54, 67],
    [20, 24, 38, 51, 62, 73, 112],
    [40, 82, 93],
    [44, 98, 111, 126],
    [4, 58, 71],
    [24, 28, 42, 55, 66, 77, 116],
    [44, 86, 97],
    [2, 48, 102, 115],
    [8, 62, 75],
    [28, 32, 46, 59, 70, 81, 120],
    [48, 90, 101],
    [6, 52, 106, 119],
    [12, 66, 79],
    [32, 36, 50, 63, 74, 85, 124],
    [52, 94, 105],
    [10, 56, 110, 123],
    [16, 70, 83],
    [0, 36, 40, 54, 67, 78, 89],
    [56, 98, 109],
    [14, 60, 114, 127],
    [20, 74, 87],
    [4, 40, 44, 58, 71, 82, 93],
    [60, 102, 113],
    [3, 18, 72, 114, 118, 125],
    [24, 78, 91],
    [8, 44, 48, 62, 75, 86, 97],
    [64, 106, 117],
    [1, 7, 22, 76, 118, 122],
    [28, 82, 95],
    [12, 48, 52, 66, 79, 90, 101],
    [68, 110, 121],
    [5, 11, 26, 80, 122, 126],
    [32, 86, 99],
]

LTInverseTable = [
    [53, 55, 72],
    [1, 5, 20, 90],
    [15, 102],
    [3, 31, 90],
    [57, 59, 76],
    [5, 9, 24, 94],
    [19, 106],
    [7, 35, 94],
    [61, 63, 80],
    [9, 13, 28, 98],
    [23, 110],
    [11, 39, 98],
    [65, 67, 84],
    [13, 17, 32, 102],
    [27, 114],
    [1, 3, 15, 20, 43, 102],
    [69, 71, 88],
    [17, 21, 36, 106],
    [1, 31, 118],
    [5, 7, 19, 24, 47, 106],
    [73, 75, 92],
    [21, 25, 40, 110],
    [5, 35, 122],
    [9, 11, 23, 28, 51, 110],
    [77, 79, 96],
    [25, 29, 44, 114],
    [9, 39, 126],
    [13, 15, 27, 32, 55, 114],
    [81, 83, 100],
    [1, 29, 33, 48, 118],
    [2, 13, 43],
    [1, 17, 19, 31, 36, 59, 118],
    [85, 87, 104],
    [5, 33, 37, 52, 122],
    [6, 17, 47],
    [5, 21, 23, 35, 40, 63, 122],
    [89, 91, 108],
    [9, 37, 41, 56, 126],
    [10, 21, 51],
    [9, 25, 27, 39, 44, 67, 126],
    [93, 95, 112],
    [2, 13, 41, 45, 60],
    [14, 25, 55],
    [2, 13, 29, 31, 43, 48, 71],
    [97, 99, 116],
    [6, 17, 45, 49, 64],
    [18, 29, 59],
    [6, 17, 33, 35, 47, 52, 75],
    [101, 103, 120],
    [10, 21, 49, 53, 68],
    [22, 33, 63],
    [10, 21, 37, 39, 51, 56, 79],
    [105, 107, 124],
    [14, 25, 53, 57, 72],
    [26, 37, 67],
    [14, 25, 41, 43, 55, 60, 83],
    [0, 109, 111],
    [18, 29, 57, 61, 76],
    [30, 41, 71],
    [18, 29, 45, 47, 59, 64, 87],
    [4, 113, 115],
    [22, 33, 61, 65, 80],
    [34, 45, 75],
    [22, 33, 49, 51, 63, 68, 91],
    [8, 117, 119],
    [26, 37, 65, 69, 84],
    [38, 49, 79],
    [26, 37, 53, 55, 67, 72, 95],
    [12, 121, 123],
    [30, 41, 69, 73, 88],
    [42, 53, 83],
    [30, 41, 57, 59, 71, 76, 99],
    [16, 125, 127],
    [34, 45, 73, 77, 92],
    [46, 57, 87],
    [34, 45, 61, 63, 75, 80, 103],
    [1, 3, 20],
    [38, 49, 77, 81, 96],
    [50, 61, 91],
    [38, 49, 65, 67, 79, 84, 107],
    [5, 7, 24],
    [42, 53, 81, 85, 100],
    [54, 65, 95],
    [42, 53, 69, 71, 83, 88, 111],
    [9, 11, 28],
    [46, 57, 85, 89, 104],
    [58, 69, 99],
    [46, 57, 73, 75, 87, 92, 115],
    [13, 15, 32],
    [50, 61, 89, 93, 108],
    [62, 73, 103],
    [50, 61, 77, 79, 91, 96, 119],
    [17, 19, 36],
    [54, 65, 93, 97, 112],
    [66, 77, 107],
    [54, 65, 81, 83, 95, 100, 123],
    [21, 23, 40],
    [58, 69, 97, 101, 116],
    [70, 81, 111],
    [58, 69, 85, 87, 99, 104, 127],
    [25, 27, 44],
    [62, 73, 101, 105, 120],
    [74, 85, 115],
    [3, 62, 73, 89, 91, 103, 108],
    [29, 31, 48],
    [66, 77, 105, 109, 124],
    [78, 89, 119],
    [7, 66, 77, 93, 95, 107, 112],
    [33, 35, 52],
    [0, 70, 81, 109, 113],
    [82, 93, 123],
    [11, 70, 81, 97, 99, 111, 116],
    [37, 39, 56],
    [4, 74, 85, 113, 117],
    [86, 97, 127],
    [15, 74, 85, 101, 103, 115, 120],
    [41, 43, 60],
    [8, 78, 89, 117, 121],
    [3, 90],
    [19, 78, 89, 105, 107, 119, 124],
    [45, 47, 64],
    [12, 82, 93, 121, 125],
    [7, 94],
    [0, 23, 82, 93, 109, 111, 123],
    [49, 51, 68],
    [1, 16, 86, 97, 125],
    [11, 98],
    [4, 27, 86, 97, 113, 115, 127],
]
