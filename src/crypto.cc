#include "crypto.h"
namespace radius {

std::array<byte, 16> md5Bin(const std::vector<byte> &data) {
    MD5 md5;
    md5(&data[0], data.size());
    byte hashBuf[16];
    md5.getHash((unsigned char *)&hashBuf);

    std::array<byte, 16> hashArr;
    std::copy(hashBuf, &hashBuf[16], hashArr.begin());
    return hashArr;
}

std::array<byte, 16> md5HmacBin(const std::vector<byte> &data,
                                const std::string &secret) {
    std::string hmac_str =
        hmac<MD5>((void *)&data[0], (size_t)data.size(), (void *)&secret[0],
                  (size_t)secret.length());
    std::vector<byte> hmac_bytes;

    byte b;
    int bt;
    for (int i = 0; i < hmac_str.length(); i += 2) {
        std::string hex_str(hmac_str, i, 2);
        std::stringstream(hex_str) >> std::hex >> bt;
        b = bt;
        hmac_bytes.push_back(b);
    }
    std::array<byte, 16> hmac_arr;
    std::copy(hmac_bytes.begin(), hmac_bytes.end(), hmac_arr.begin());
    return hmac_arr;
}
}
