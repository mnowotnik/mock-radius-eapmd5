#pragma once
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <WS2tcpip.h>
#include <iostream>
#include <array>
#include <vector>
#include <string>
#include "crypto.h"

typedef unsigned char byte;

#ifdef DEBUG
namespace packet_h_private {
#else
namespace {
#endif
short networkBytes2Short(std::array<byte, 2> bytes) {
  short s = (bytes[1] << 8) | bytes[2];
  return ntohs(s);
}

std::array<byte, 2> short2NetworkBytes(short s) {
  s = htons(s);
  std::array<byte, 2> b;
  b[0] = s & 0xff;
  b[1] = (s >> 8) & 0xff;
  return b;
}

const int RADIUS_MIN_SIZE = 20;
}

const int RADIUS_MIN_SIZE = 20;
class RadiusAVP;

/**
 * 0 : code
 * 1 : identifier
 * 2-3 : length
 * 4-20 : authenticator
 * 21+ : attribute-value list
 */
class RadiusPacket {
private:
  std::vector<byte> buffer();
  std::vector<RadiusAVP> avpList;

public:
  // codes
  const byte ACCESS_REQUEST = 1, ACCESS_ACCEPT = 2, ACCESS_REJECT = 3,
              ACCESS_CHALLENGE = 11;

  RadiusPacket() { }
  RadiusPacket(byte inputBuf[], int n);
/*
  void setCode(byte code) { buffer[0] = code; }
  byte getCode() { return buffer[0]; }
  void setIdentifier(byte identifier) { buffer[1] = identifier; }
  byte getIdentifier() { return buffer[1]; }
  void setLength(short length) {
    std::array<byte, 2> bytes = short2NetworkBytes(length);
    buffer[2] = bytes[0];
    buffer[3] = bytes[1];
  }
  short getLength() {
    short l = networkBytes2Short(std::array({{buffer[2], buffer[3]}}));
    return l;
  }
  void setAuthenticator(std::array<byte, 16> arr) {
    for (int i = 0; i < 16; i++) {
      buffer[i + 4] = arr[i];
    }
  }
  std::array<byte, 16> getAuthenticator() {
    std::array<byte, 16> auth;
    for (int i = 0; i < 16; i++) {
      auth[i] = buffer[i + 4];
    }
  }
  std::vector<RadiusAVP> getAVPList() { return avpList; }
  */
};

/**
 * 0 : type
 * 1 : length
 * 2+ : data
 */
class RadiusAVP {
public:
  // types
  const byte MESSAGE_AUTHENTICATOR = 80, EAP_MESSAGE = 79, NAS_IP_ADDRESS = 4,
              NAS_IDENTIFIER = 32;
};

/**
 * 0 : code
 * 1 : identifier
 * 2-3 : length
 */
class EapPacket {
public:
  // codes
  const byte REQUEST = 1, RESPONSE = 2, SUCCESS = 3, FAILURE = 4;
};
