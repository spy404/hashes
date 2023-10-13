#include <algorithm>
#include <array>
#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

namespace hashing {
namespace sha1 {
uint32_t leftRotate32bits(uint32_t n, std::size_t rotate) {
    return (n << rotate) | (n >> (32 - rotate));
}

std::string sig2hex(void* sig) {
    const char* hexChars = "0123456789abcdef";
    auto* intsig = static_cast<uint8_t*>(sig);
    std::string hex = "";
    for (uint8_t i = 0; i < 20; i++) {
        hex.push_back(hexChars[(intsig[i] >> 4) & 0xF]);
        hex.push_back(hexChars[(intsig[i]) & 0xF]);
    }
    return hex;
}

void* hash_bs(const void* input_bs, uint64_t input_size) {
    auto* input = static_cast<const uint8_t*>(input_bs);

    uint32_t h0 = 0x67452301, a = 0;
    uint32_t h1 = 0xEFCDAB89, b = 0;
    uint32_t h2 = 0x98BADCFE, c = 0;
    uint32_t h3 = 0x10325476, d = 0;
    uint32_t h4 = 0xC3D2E1F0, e = 0;

    uint64_t padded_message_size = 0;
    if (input_size % 64 < 56) {
        padded_message_size = input_size + 64 - (input_size % 64);
    } else {
        padded_message_size = input_size + 128 - (input_size % 64);
    }

    std::vector<uint8_t> padded_message(padded_message_size);

    std::copy(input, input + input_size, padded_message.begin());

    padded_message[input_size] = 1 << 7;
    for (uint64_t i = input_size; i % 64 != 56; i++) {
        if (i == input_size) {
            continue;
        }
        padded_message[i] = 0;
    }

    uint64_t input_bitsize = input_size * 8;
    for (uint8_t i = 0; i < 8; i++) {
        padded_message[padded_message_size - 8 + i] =
            (input_bitsize >> (56 - 8 * i)) & 0xFF;
    }

    std::array<uint32_t, 80> blocks{};

    for (uint64_t chunk = 0; chunk * 64 < padded_message_size; chunk++) {
        for (uint8_t bid = 0; bid < 16; bid++) {
            blocks[bid] = 0;

            for (uint8_t cid = 0; cid < 4; cid++) {
                blocks[bid] = (blocks[bid] << 8) +
                              padded_message[chunk * 64 + bid * 4 + cid];
            }

            for (uint8_t i = 16; i < 80; i++) {
                blocks[i] =
                    leftRotate32bits(blocks[i - 3] ^ blocks[i - 8] ^
                                         blocks[i - 14] ^ blocks[i - 16],
                                     1);
            }
        }

        a = h0;
        b = h1;
        c = h2;
        d = h3;
        e = h4;

        for (uint8_t i = 0; i < 80; i++) {
            uint32_t F = 0, g = 0;
            if (i < 20) {
                F = (b & c) | ((~b) & d);
                g = 0x5A827999;
            } else if (i < 40) {
                F = b ^ c ^ d;
                g = 0x6ED9EBA1;
            } else if (i < 60) {
                F = (b & c) | (b & d) | (c & d);
                g = 0x8F1BBCDC;
            } else {
                F = b ^ c ^ d;
                g = 0xCA62C1D6;
            }

            uint32_t temp = leftRotate32bits(a, 5) + F + e + g + blocks[i];
            e = d;
            d = c;
            c = leftRotate32bits(b, 30);
            b = a;
            a = temp;
        }
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    auto* sig = new uint8_t[20];
    for (uint8_t i = 0; i < 4; i++) {
        sig[i] = (h0 >> (24 - 8 * i)) & 0xFF;
        sig[i + 4] = (h1 >> (24 - 8 * i)) & 0xFF;
        sig[i + 8] = (h2 >> (24 - 8 * i)) & 0xFF;
        sig[i + 12] = (h3 >> (24 - 8 * i)) & 0xFF;
        sig[i + 16] = (h4 >> (24 - 8 * i)) & 0xFF;
    }

    return sig;
}

void* hash(const std::string& message) {
    return hash_bs(&message[0], message.size());
}
}
}

static void test() {
    void* sig = hashing::sha1::hash("");
    std::cout << "Hashing empty string" << std::endl;
    std::cout << hashing::sha1::sig2hex(sig) << std::endl << std::endl;
    assert(hashing::sha1::sig2hex(sig).compare(
               "da39a3ee5e6b4b0d3255bfef95601890afd80709") == 0);

    void* sig2 =
        hashing::sha1::hash("The quick brown fox jumps over the lazy dog");
    std::cout << "Hashing The quick brown fox jumps over the lazy dog"
              << std::endl;
    std::cout << hashing::sha1::sig2hex(sig2) << std::endl << std::endl;
    assert(hashing::sha1::sig2hex(sig2).compare(
               "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12") == 0);

    void* sig3 =
        hashing::sha1::hash("The quick brown fox jumps over the lazy dog.");
    std::cout << "Hashing "
                 "The quick brown fox jumps over the lazy dog."
              << std::endl;
    std::cout << hashing::sha1::sig2hex(sig3) << std::endl << std::endl;
    assert(hashing::sha1::sig2hex(sig3).compare(
               "408d94384216f890ff7a0c3528e8bed1e0b01621") == 0);

    void* sig4 = hashing::sha1::hash(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    std::cout
        << "Hashing "
           "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        << std::endl;
    std::cout << hashing::sha1::sig2hex(sig4) << std::endl << std::endl;
    assert(hashing::sha1::sig2hex(sig4).compare(
               "761c457bf73b14d27e9e9265c46f4b4dda11f940") == 0);
}

static void interactive() {
    while (true) {
        std::string input;
        std::cout << "Enter a message to be hashed (Ctrl-C to exit): "
                  << std::endl;
        std::getline(std::cin, input);
        void* sig = hashing::sha1::hash(input);
        std::cout << "Hash is: " << hashing::sha1::sig2hex(sig) << std::endl;

        while (true) {
            std::cout << "Want to enter another message? (y/n) ";
            std::getline(std::cin, input);
            if (input.compare("y") == 0) {
                break;
            } else if (input.compare("n") == 0) {
                return;
            }
        }
    }
}

int main() {
    test();
    interactive();
    return 0;
}
