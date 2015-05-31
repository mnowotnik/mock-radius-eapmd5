#include "packet.h"


namespace radius {
namespace internal {
unsigned short networkBytes2Short(std::array<byte, 2> bytes) {
  return (unsigned short)(bytes[0] << 8 & 0xFF) | (bytes[1] & 0xFF);
}

std::array<byte, 2> short2NetworkBytes(unsigned short s) {
  s = htons(s);
  std::array<byte, 2> b;
  b[0] = s & 0xff;
  b[1] = (s >> 8) & 0xff;
  return b;
}
}
}
