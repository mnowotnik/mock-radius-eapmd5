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

  void setType(byte type) { buffer[0] = type; }
  byte getType() { return buffer[0]; }

  void setLength(byte length) { buffer[1] = length; }
  byte getLength() { return buffer[1]; }

  void setValue(const std::vector<byte> &value){
      buffer.insert(buffer.begin()+VAL_OFFSET,value.begin(),value.end());
  }
  std::vector<byte> getValue(){
      std::vector<byte>value(buffer.begin()+VAL_OFFSET,buffer.end());
  }

  std::vector<byte> getBuffer() { return buffer; }
};

/**
 * type : 79
 * length : varying
 * value -> (EapPacket)
 *      0 : type
 *      1 : identifier
 *      2-3 : length
 *      4+ : data -> (EPData)
 *          0 : protocol type
 *          1+ : type-data (if any)
 */
class EapMessage : public RadiusAVP {
protected:
    const int MIN_LENGTH=4; 

public:
  EapMessage() { 
      setType(RadiusAVP::EAP_MESSAGE); }

  void setEapPacket(const EapPacket &packet){
      buffer.insert(buffer.begin()+RadiusAVP::VAL_OFFSET,packet.buffer.begin(),packet.buffer.end());
      setLength(buffer.size());
  }

  EapPacket getEapPacket(){
      std::vector<byte>eapBytes(buffer.begin()+RadiusAVP::VAL_OFFSET,buffer.end());
      return EapPacket(eapBytes);
  }
};


/**
 * type : 80
 * length : 16
 * value : md5
 */
class MessageAuthenticator : public RadiusAVP {
  const byte length = 16;

public:
  MessageAuthenticator() {
    this->buffer.resize(length);
    setType(RadiusAVP::MESSAGE_AUTHENTICATOR);
  }

  void setMd5(std::array<byte, 16> md5) {
    int offset = RadiusAVP::VAL_OFFSET;
    buffer.insert(buffer.begin() + offset, md5.begin(), md5.end());
    setLength(buffer.size());
  }

  std::array<byte, 16> getMd5() {
    std::array<byte, 16> md5;
    int offset = RadiusAVP::VAL_OFFSET;
    std::copy(buffer.begin() + offset, buffer.begin() + offset + length,
              md5.begin());
    return md5;
  }
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

  void setIp(std::array<byte, 4>ip) {
    buffer.insert(buffer.begin() + RadiusAVP::VAL_OFFSET, ip.begin(),
                  ip.end());
    setLength(length);
  }

  void setIp(const std::string &ipStr) {
      std::array<byte, 4> ip;
      in_addr addr;
      inet_pton(AF_INET,ipStr.c_str(),&addr);
      memcpy((void*) &ip[0], &addr, sizeof(in_addr));
      setIp(ip);
  }

  in_addr getIp() {
      byte* addrPtr = &buffer[RadiusAVP::VAL_OFFSET];
      struct in_addr addr;
      /* inet_ntop(AF_INET,&addr,ipStr.c_str(),ipStr.length()); */
      memcpy((void*) &addr, addrPtr, sizeof(in_addr));
      return addr;
  }
};

/**
 * type  : 32
 * length : 3+
 * value : string
 */
class NasIdentifier : public RadiusAVP {

public:
  NasIdentifier() { setType(RadiusAVP::NAS_IDENTIFIER); }

  void setIdentifier(std::vector<byte> id) {
    buffer.insert(buffer.begin() + RadiusAVP::VAL_OFFSET, id.begin(),
                  id.end());
    setLength(buffer.size());
  }

  std::string getIdentifier() {
    int offset = RadiusAVP::VAL_OFFSET;
    return std::string((const char *)&buffer[offset],buffer.size()-offset);
  }
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
  static const int AVP_OFFSET = 20;

  RadiusPacket() : buffer(radiusMinSize) {}
  RadiusPacket(const byte inputBuf[], int n);

  void setCode(byte code) { buffer[0] = code; }
  byte getCode() { return buffer[0]; }

  void setIdentifier(byte identifier) { buffer[1] = identifier; }
  byte getIdentifier() { return buffer[1]; }

  void setLength(unsigned short length) {
    std::array<byte, 2> bytes = radius::internal::short2NetworkBytes(length);
    buffer[2] = bytes[0];
    buffer[3] = bytes[1];
  }
  short getLength() {
    unsigned short l = radius::internal::networkBytes2Short(
        std::array<byte, 2>({{buffer[2], buffer[3]}}));
    return l;
  }

  void setAuthenticator(const std::array<byte, 16> &arr) {
    for (int i = 0; i < 16; i++) {
      buffer[i + 4] = arr[i];
    }
  }
  std::array<byte, 16> getAuthenticator() {
    std::array<byte, 16> auth;
    std::copy(buffer.begin() + 4, buffer.begin() + 4 + auth.size(),
              auth.begin());
    return auth;
  }

  std::vector<byte> getBuffer() { return buffer; }

  void addAVP(const RadiusAVP &avp){
      buffer.insert(buffer.end(),avp.buffer.begin(),avp.buffer.end());
  }
  std::vector<RadiusAVP> getAVPList(){
      std::vector<RadiusAVP> avpList;
  
      //TODO
      return avpList;
  
  }
};
