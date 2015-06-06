#pragma once
#include <iostream>
#include "md5.h"
#include "typedefs.h"
#include <vector>
#include <array>

namespace radius {
namespace crypto {

inline std::array<byte, 16> md5Bin(const std::vector<byte> &data) {
    MD5 md5;
    md5(&data[0], data.size());
    byte hashBuf[16];
    md5.getHash((unsigned char *)&hashBuf);

    std::array<byte, 16> hashArr;
    std::copy(hashBuf, &hashBuf[15], hashArr.begin());
    return hashArr;
}

/* inline std::string md5Text(unsigned char *data, int n) { */
/*   MD5 md5; */
/*   return md5(data, n); */
/* } */
}
}
