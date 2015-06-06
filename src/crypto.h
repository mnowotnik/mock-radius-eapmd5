#pragma once
#include <iostream>
#include "md5.h"
#include "typedefs.h"
#include <vector>
#include <array>

namespace radius {
namespace crypto {

std::array<byte, 16> md5Bin(const std::vector<byte> &data);

/* inline std::string md5Text(unsigned char *data, int n) { */
/*   MD5 md5; */
/*   return md5(data, n); */
/* } */
}
}
