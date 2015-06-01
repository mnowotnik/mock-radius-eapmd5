#pragma once
#include "packets/packet.h"
#include "packets/eap_packet.h"

class RadiusPacket;

/**
 * 0 : type
 * 1 : length
 * 2+ : value
 */
class RadiusAVP {
  friend RadiusPacket;

public:
  // types
  static const byte MESSAGE_AUTHENTICATOR = 80, EAP_MESSAGE = 79,
                    NAS_IP_ADDRESS = 4, NAS_IDENTIFIER = 32;
  static const byte VAL_OFFSET = 2;

protected:
  std::vector<byte> buffer;

public:
  RadiusAVP() : buffer(VAL_OFFSET) {}
  RadiusAVP(const std::vector<byte>& bytes) : buffer(bytes) {}

  void setType(byte type) { buffer[0] = type; }
  byte getType() { return buffer[0]; }

  void setLength(byte length) { buffer[1] = length; }
  byte getLength() { return buffer[1]; }

  void setValue(const std::vector<byte> &value) {
    buffer.insert(buffer.begin() + VAL_OFFSET, value.begin(), value.end());
  }
  std::vector<byte> getValue() {
    std::vector<byte> value(buffer.begin() + VAL_OFFSET, buffer.end());
    return value;
  }

  std::vector<byte> getBuffer() { return buffer; }
};

/**
 * type : 79
 * length : varying
 * value -> (concatenated EapPacket)
 *      0 : type
 *      1 : identifier
 *      2-3 : length
 *      4+ : data -> (EPData)
 *          0 : protocol type
 *          1+ : type-data (if any)
 *
 * EapPacket can have >253 bytes so byte arrays have to be retrieved
 * and concatenated (or split) per instance
 */
class EapMessage : public RadiusAVP {
protected:
  const int MIN_LENGTH = 4;

public:
  EapMessage() { setType(RadiusAVP::EAP_MESSAGE); }
};

/**
 * type : 80
 * length : 16
 * value : md5
 */
class MessageAuthenticator : public RadiusAVP {
  const byte length = 18;

public:
  MessageAuthenticator();

  void setMd5(const std::array<byte, 16> &md5);
  std::array<byte, 16> getMd5();
};

/**
 * type : 4
 * length : 4
 * value : ipv4
 */
class NasIpAddr : public RadiusAVP {

  const byte length = 4;

public:
  NasIpAddr() { setType(RadiusAVP::NAS_IP_ADDRESS); }

  void setIp(std::array<byte, 4> ip);

  void setIp(const std::string &ipStr);

  in_addr getIp();
};

/**
 * type  : 32
 * length : 3+
 * value : string
 */
class NasIdentifier : public RadiusAVP {

public:
  NasIdentifier() { setType(RadiusAVP::NAS_IDENTIFIER); }

  void setIdentifier(std::vector<byte> id);

  std::string getIdentifier();
};

/**
 * 0 : code
 * 1 : identifier
 * 2-3 : length
 * 4-20 : authenticator
 * 21+ : attribute-value list
 */
class RadiusPacket {
private:
  const int radiusMinSize = 20;
  std::vector<byte> buffer;

public:
  // codes
  static const byte ACCESS_REQUEST = 1, ACCESS_ACCEPT = 2, ACCESS_REJECT = 3,
                    ACCESS_CHALLENGE = 11;
  static const int AVP_OFFSET = 20, AUTH_OFFSET = 4, AUTH_LEN = 16;

  RadiusPacket() : buffer(radiusMinSize) {}
  RadiusPacket(const byte inputBuf[], int n);

  void setCode(byte code) { buffer[0] = code; }
  byte getCode() { return buffer[0]; }

  void setIdentifier(byte identifier) { buffer[1] = identifier; }
  byte getIdentifier() { return buffer[1]; }

  void setLength(unsigned short length);
  short getLength();

  void setAuthenticator(const std::array<byte, AUTH_LEN> &arr);
  std::array<byte, 16> getAuthenticator();

  std::vector<byte> getBuffer() { return buffer; }

  void addAVP(const RadiusAVP &avp);
  std::vector<RadiusAVP> getAVPList();
};
