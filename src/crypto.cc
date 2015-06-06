#include "crypto.h"
namespace radius {
namespace crypto {

std::array<byte, 16> md5Bin(const std::vector<byte> &data) {
    MD5 md5;
    md5(&data[0], data.size());
    byte hashBuf[16];
    md5.getHash((unsigned char *)&hashBuf);

    std::array<byte, 16> hashArr;
    std::copy(hashBuf, &hashBuf[15], hashArr.begin());
    return hashArr;
}
}}
