import math
import struct

s = [
    7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
    5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
    4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
    6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
]

K_md5 = [int(abs(math.sin(i + 1)) * 2**32) & 0xFFFFFFFF for i in range(64)]

def md5_left_rotate(x, amount):
    x &= 0xFFFFFFFF
    return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF

def md5_from_scratch(input_string):
    message_bytes = bytearray(input_string.encode('utf-8'))

   
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476

    original_length_bits = (len(message_bytes) * 8) & 0xFFFFFFFFFFFFFFFF 
    message_bytes.append(0x80) 
    while len(message_bytes) % 64 != 56:
        message_bytes.append(0x00) 

    message_bytes += struct.pack('<Q', original_length_bits)


    for i in range(0, len(message_bytes), 64):
        chunk = message_bytes[i:i+64]
        M = struct.unpack('<16I', chunk) 

        A = h0
        B = h1
        C = h2
        D = h3

        for j in range(64): # 64轮运算
            if 0 <= j <= 15: 
                F_logic = (B & C) | (~B & D)
                g = j
            elif 16 <= j <= 31: 
                F_logic = (D & B) | (~D & C)
                g = (5 * j + 1) % 16
            elif 32 <= j <= 47: 
                F_logic = B ^ C ^ D
                g = (3 * j + 5) % 16
            elif 48 <= j <= 63: 
                F_logic = C ^ (B | ~D)
                g = (7 * j) % 16
            
            F_logic = F_logic & 0xFFFFFFFF
            temp_D = D
            D = C
            C = B
            B = (B + md5_left_rotate((A + F_logic + K_md5[j] + M[g]) & 0xFFFFFFFF, s[j])) & 0xFFFFFFFF
            A = temp_D
        
        h0 = (h0 + A) & 0xFFFFFFFF
        h1 = (h1 + B) & 0xFFFFFFFF
        h2 = (h2 + C) & 0xFFFFFFFF
        h3 = (h3 + D) & 0xFFFFFFFF

    
    digest_bytes = struct.pack('<IIII', h0, h1, h2, h3)
    md5_hex = digest_bytes.hex()

    md5_int = int.from_bytes(digest_bytes, byteorder='little')

    return md5_hex, md5_int



def sha1_left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff

def sha1_from_scratch(input_string):
    message_bytes = bytearray(input_string.encode('utf-8'))

    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    original_length_bits = len(message_bytes) * 8 
    message_bytes.append(0x80) 
    while len(message_bytes) % 64 != 56:
        message_bytes.append(0x00) 


    message_bytes += struct.pack('>Q', original_length_bits)

    for i in range(0, len(message_bytes), 64):
        chunk = message_bytes[i:i+64]
        
        w = [0] * 80
   
        for j in range(16):
            w[j] = struct.unpack('>I', chunk[j*4:j*4+4])[0]
    
        for j in range(16, 80):
            w[j] = sha1_left_rotate(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)

        a = h0
        b = h1
        c = h2
        d = h3
        e = h4

        for j in range(80): 
            if 0 <= j <= 19: 
                f_logic = (b & c) | ((~b) & d)
                k_constant = 0x5A827999
            elif 20 <= j <= 39: 
                f_logic = b ^ c ^ d
                k_constant = 0x6ED9EBA1
            elif 40 <= j <= 59: 
                f_logic = (b & c) | (b & d) | (c & d)
                k_constant = 0x8F1BBCDC
            elif 60 <= j <= 79: 
                f_logic = b ^ c ^ d
                k_constant = 0xCA62C1D6
            
            temp = (sha1_left_rotate(a, 5) + f_logic + e + k_constant + w[j]) & 0xffffffff
            e = d
            d = c
            c = sha1_left_rotate(b, 30)
            b = a
            a = temp

        h0 = (h0 + a) & 0xffffffff
        h1 = (h1 + b) & 0xffffffff
        h2 = (h2 + c) & 0xffffffff
        h3 = (h3 + d) & 0xffffffff
        h4 = (h4 + e) & 0xffffffff

    digest_bytes = struct.pack('>IIIII', h0, h1, h2, h3, h4)
    sha1_hex = digest_bytes.hex()

    sha1_int = int.from_bytes(digest_bytes, byteorder='big')

    return sha1_hex, sha1_int

if __name__ == "__main__":

    student_name = "zhangzhuohang" 
    student_id = "2024141456"  
    tag_string_literal = "信息与网络安全"
    tag_string = f"{tag_string_literal}{student_name}{student_id}"


    md5_hex_tag, md5_int_tag = md5_from_scratch(tag_string)
    sha1_hex_tag, sha1_int_tag = sha1_from_scratch(tag_string)


  
    sum_hashes = md5_int_tag + sha1_int_tag
    mod_2_128 = 2**128
    Q = sum_hashes % mod_2_128

   
    N = 1 + (Q % 21)

   
    print("--- 计算结果 ---")
    print(f"1. Tag 字符串: {tag_string}")
    print(f"2. Tag 的 MD5 哈希值 (十六进制): {md5_hex_tag}")
    print(f"3. Tag 的 MD5 哈希值 (128位无符号整数): {md5_int_tag}")
    print(f"4. Tag 的 SHA-1 哈希值 (十六进制): {sha1_hex_tag}")
    print(f"5. Tag 的 SHA-1 哈希值 (160位无符号整数): {sha1_int_tag}")
    print(f"6. 计算得到的 Q 值: {Q}")
    print(f"7. 计算得到的 N 值: {N}")

