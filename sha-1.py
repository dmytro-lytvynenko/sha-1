import struct,hashlib,time

class SHA1Hash:
    def __init__(self):
        self.h0, self.h1, self.h2, self.h3, self.h4 = (
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0
        )

    def _left_rotate(self, n, b):
        return ((n << b) | (n >> (32 - b))) & 0xffffffff

    def update(self, message):
        original_byte_len = len(message)
        original_bit_len = original_byte_len * 8
        message += b'\x80'
        message += b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64)
        message += struct.pack('>Q', original_bit_len)

        for i in range(0, len(message), 64):
            w = [0] * 80
            for j in range(16):
                w[j] = struct.unpack('>I', message[i + j*4:i + j*4 + 4])[0]

            for j in range(16, 80):
                w[j] = self._left_rotate(w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16], 1)

            a, b, c, d, e = self.h0, self.h1, self.h2, self.h3, self.h4

            for j in range(80):
                if 0 <= j <= 19:
                    f = d ^ (b & (c ^ d))
                    k = 0x5A827999
                elif 20 <= j <= 39:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif 40 <= j <= 59:
                    f = (b & c) | (b & d) | (c & d) 
                    k = 0x8F1BBCDC
                elif 60 <= j <= 79:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6

                temp = self._left_rotate(a, 5) + f + e + k + w[j] & 0xffffffff
                e = d
                d = c
                c = self._left_rotate(b, 30)
                b = a
                a = temp

            self.h0 = (self.h0 + a) & 0xffffffff
            self.h1 = (self.h1 + b) & 0xffffffff
            self.h2 = (self.h2 + c) & 0xffffffff
            self.h3 = (self.h3 + d) & 0xffffffff
            self.h4 = (self.h4 + e) & 0xffffffff

        return self._digest()

    def _digest(self):
        return '%08x%08x%08x%08x%08x' % (self.h0, self.h1, self.h2, self.h3, self.h4)

    def hexdigest(self, message):
        self.__init__()
        return self.update(message.encode())
    
def measure_performance_custom_sha1(message, sha1_instance, iterations=100000):
    start_time = time.time()
    for _ in range(iterations):
        sha1_instance.hexdigest(message)
    end_time = time.time()
    return end_time - start_time

def measure_performance_hashlib_sha1(message, iterations=100000):
    start_time = time.time()
    for _ in range(iterations):
        hashlib.sha1(message.encode()).hexdigest()
    end_time = time.time()
    return end_time - start_time

messages = [
    "Short message",
    "This is a longer message that spans more than one block...",
    "This is a really long message, " * 10 + "intended to span multiple blocks to test the SHA1 implementation thoroughly."
]

sha1 = SHA1Hash()
for message in messages:
    test_result = hashlib.sha1(message.encode()).hexdigest()
    our_result = sha1.hexdigest(message)
    
    if test_result == our_result:
        print(f'{message}->{our_result} is correct')
    else:
        print(f'{message}->{our_result} is incorrect. Correct hash = {test_result}')

custom_sha1_time = measure_performance_custom_sha1(messages[0], sha1)
hashlib_sha1_time = measure_performance_hashlib_sha1(messages[0])

print(f"Custom SHA1 implementation time: {custom_sha1_time} seconds")
print(f"hashlib SHA1 implementation time: {hashlib_sha1_time} seconds")
