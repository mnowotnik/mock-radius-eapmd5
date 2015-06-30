#ifndef CRYPTO_H_UTAHSOL9
#define CRYPTO_H_UTAHSOL9

#include <iostream>
#include "crc32.h"
#include "md5.h"
#include "sha1.h"
#include "hash.h"
#include "sha256.h"
#include "sha3.h"
#include "hmac.h"
#include "typedefs.h"
#include <vector>
#include <array>
#include <sstream>

/* typedef MD5 MD5Hash; */
/* typedef SHA256 SHA256Hash; */
/* typedef SHA3 SHA3Hash; */
namespace radius {
enum HashAlg { MD5, SHA256, SHA3 };
std::array<byte, 16> md5Bin(const std::vector<byte> &data);
std::array<byte, 16> md5HmacBin(const std::vector<byte> &data,
                                const std::string &secret);

std::string hashStr(const std::string &str, HashAlg alg);
}
#endif /* end of include guard: CRYPTO_H_UTAHSOL9 */
