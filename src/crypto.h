#pragma once
#include <iostream>
#include "md5.h"

namespace crypto {

inline void md5Bin(unsigned char *data, int n, unsigned char *buffer) {
  MD5 md5;
  md5(data, n);
  return md5.getHash(buffer);
}

inline std::string md5Text(unsigned char *data, int n) {
  MD5 md5;
  return md5(data, n);
}

}
