cipher = [0b11110001,0b11011111,0b10100100,0b10001010,0b10110000,0b10100100,0b10001010,0b111110,0b10001010,0b11101111,0b10001010,0b11011111,0b11110001,0b10110000,0b10001010,0b11101111,0b101010,0b111110,0b11101111,0b10100100,0b111110,0b101010,0b1111111,0b11101111,0b1111111,0b11101111,0b1,0b1,0b10100100,0b1111111,0b11110001,0b11101111,0b1,0b10100100,0b10110000,0b10001010,0b1,0b111110,0b11011111,0b10100100,0b11110001,0b11101111,0b101010,0b1,0b11101111,0b101010,0b1111111,0b11011111,0b11110001,0b111110,0b11101111,0b10110000,0b10110000,0b10110000,0b111110,0b11011111,0b111110,0b11101111,0b10110000,0b11101111,0b11101111,0b1111111,0b1111111,0b1111111,0b1111111,0b11101111,0b10001010,0b10100100,0b10001010,0b11101111,0b10100100,0b111110,0b10100100,0b10001010,0b101010,0b11101111,0b11011111]

plain_id = "590610636".encode('utf-8')

KeyLength = 10
SubKeyLength = 8
DataLength = 8
FLength = 4

# Tables for initial and final permutations
IPtable = [2, 6, 3, 1, 4, 8, 5, 7]
FPtable = [4, 1, 3, 5, 7, 2, 8, 6]

# Tables for subkey generation
P10table = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8table = [6, 3, 7, 4, 8, 5, 10, 9]

# Tables for the fk function
EPtable = [4, 1, 2, 3, 2, 3, 4, 1]
S0table = [["01", "00", "11", "10"], ["11", "10", "01", "00"], ["00", "10", "01", "11"], ["11", "01", "11", "10"]]
S1table = [["00", "01", "10", "11"], ["10", "00", "01", "11"], ["11", "00", "01", "00"], ["10", "01", "00", "11"]]
P4table = [2, 4, 3, 1]


def eightbitformat(bit, n = 8):
    bitstr = str(bin(bit))
    bitstr = bitstr[2:len(bitstr)]
    temp = ""
    for i in range(n - len(bitstr)):
        temp += "0"
    bitstr = temp + bitstr
    return bitstr


def swap(inputByte, table):
    outByte = ""
    for i in table:
        outByte += inputByte[i - 1]
    return outByte


def permutationIP(inputByte):
    inpstr = eightbitformat(inputByte)
    return swap(inpstr, IPtable)


def permutationEP(inputByte):
    return swap(inputByte, EPtable)


def permutationP10(inputByte):
    return swap(inputByte, P10table)


def permutationP8(inputByte):
    return swap(inputByte, P8table)


def permutationP4(inputByte):
    return swap(inputByte, P4table)


def permutationFP(inputByte):
    return swap(inputByte, FPtable)


def FKsbox(inputByte):

    leftNibble = inputByte[0:4]
    rightNibble = inputByte[4:8]
    row = int(leftNibble[0] + leftNibble[3], base=2)
    col = int(leftNibble[1] + leftNibble[2], base=2)
    r_s0 = S0table[row][col]
    row = int(rightNibble[0] + rightNibble[3], base=2)
    col = int(rightNibble[1] + rightNibble[2], base=2)
    r_s1 = S1table[row][col]
    return r_s0 + r_s1


def xor8(text, s_key):
    output = ""
    s_key = eightbitformat(s_key)
    for i in range(len(s_key)):
        output += str(int(text[i]) ^ int(s_key[i]))
    return output


def xor(txt1, txt2):
    output = ""
    for i in range(len(txt1)):
        output += str(int(txt1[i]) ^ int(txt2[i]))
    return output


def GenKey(subkey1, subkey2):

    for i in range(1024):
        fullkey = eightbitformat(i, 10)
        rvshift1 = str(reversshift(permutationP10(fullkey)[0:5], 1)) + str(reversshift(permutationP10(fullkey)[5:10], 1))
        sk1 = permutationP8(rvshift1)
        rvshift1 = str(reversshift(permutationP10(fullkey)[0:5], 3)) + str(reversshift(permutationP10(fullkey)[5:10], 3))
        sk2 = permutationP8(rvshift1)
        if int(sk1, base=2) == subkey1 and int(sk2, base=2) == subkey2 or int(sk1, base=2) == subkey2 and int(sk2, base=2) == subkey1:
            return fullkey


def findsubkey(cipertext, hinttext):
    subkeys = [None for i in range(2)]

    for j in range(256):
        subkey1 = j
        for k in range(256):
            subkey2 = k
            miss = 0
            for x in range(len(cipertext)):
                test_subkey = Decrypt(cipertext[x], subkey1, subkey2)

                if int(test_subkey, base=2) != int(hinttext[x]):
                    break
                if x == len(cipertext) - 1:
                    subkeys[0] = subkey1
                    subkeys[1] = subkey2
                    return subkeys


def reversshift(k, n):
    if n == 1:
        table = [1, 2, 3, 4, 0]
    if n == 3:
        table = [3, 4, 0, 1, 2]
    return swap(k, table)


def Decrypt(plaintext, subkey1, subkey2):
    permu1 = permutationEP(permutationIP(plaintext)[4:8])
    xorsubkey2 = xor8(permu1, subkey2)
    sbox = FKsbox(xorsubkey2)
    permuP4 = permutationP4(sbox)
    xorop = xor(permutationIP(plaintext)[0:4], permuP4)
    outp1 = xorop + permutationIP(plaintext)[4:8]
    outp2 = outp1[4:8] + outp1[0:4]
    xorsubkey1 = xor8(permutationEP(outp2[4:8]), subkey1)
    permuP4_2 = permutationP4(FKsbox(xorsubkey1))
    xorop2 = xor(permuP4_2, outp2[0:4])
    outp3 = xorop2 + outp2[4:8]
    result = permutationFP(outp3)
    return result


def Encrypt(plaintext, subkey1, subkey2):
    permu1 = permutationEP(permutationIP(plaintext)[4:8])
    xorsubkey1 = xor(permu1, subkey1)
    sbox = FKsbox(xorsubkey1)
    permuP4 = permutationP4(sbox)
    xorop = xor(permutationIP(plaintext)[0:4],permuP4)
    outp1 = xorop + permutationIP(plaintext)[4:8]
    outp2 = outp1[4:8] + outp1[0:4]
    xorsubkey2 = xor(permutationEP(outp2[4:8]), subkey2)
    permuP4_2 = permutationP4(FKsbox(xorsubkey2))
    xorop2 = xor(permuP4_2, outp2[0:4])
    outp3 = xorop2 + outp2[4:8]
    result = permutationFP(outp3)
    return result


if __name__ == '__main__':

    findsubket = [None for i in range(2)]
    findsubket = findsubkey(cipher[0:9], plain_id)
    print("subkey1 = " + str(findsubket[0]))
    print("subkey2 = " + str(findsubket[1]))

    fullkey = GenKey(findsubket[0], findsubket[1])
    print("fullkey : " + str(fullkey))

    plaintext = []
    for i in range(len(cipher)):
        getdecrypt = int(Decrypt(cipher[i], findsubket[0], findsubket[1]), base=2)
        getdecrypt = chr(getdecrypt)
        plaintext.append(getdecrypt)

    print(plaintext)

    for x in plaintext:
        print(x)
