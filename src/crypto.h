#pragma once
#include <iostream>
#include "md5.h"
#include "hmac.h"
#include "typedefs.h"
#include <vector>
#include <array>
#include <sstream>

namespace radius {
std::array<byte, 16> md5Bin(const std::vector<byte> &data);
std::array<byte, 16> md5HmacBin(const std::vector<byte> &data,
                                const std::string &secret);
}
