#pragma once
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <WS2tcpip.h>
#include <iostream>
#include <array>
#include <vector>
#include <string>
#include <vector>
#include "crypto.h"
#include "exception.h"

typedef unsigned __int8 byte;


class PacketAccessException: public Exception {
    explicit PacketAccessException(const std::string& message): Exception(message) {}
};

namespace radius {
namespace internal {
unsigned short networkBytes2Short(std::array<byte, 2> bytes);
std::array<byte, 2> short2NetworkBytes(unsigned short s);
}
}

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

public:
  EapMessage() { 
      buffer.resize()
      setType(RadiusAVP::EAP_MESSAGE); }

  void setEapPacket(const EapPacket &packet){
      buffer.insert(buffer.begin()+RadiusAVP::DATA_OFFSET,packet.buffer.begin(),packet.buffer.end());
      setLength(buffer.size());
  }

  EapPacket getEapPacket(){
      std::vector<byte>eapBytes(buffer.begin()+RadiusAVP::VAL_OFFSET,buffer.end());
      return EapPacket(eapBytes);
  }
};


/**
 * 0 : type
 * 1 : identifier
 * 2-3 : length
 * 4+ : type-data
 */
class EapPacket {

    friend EapMessage;
    std::vector<byte>buffer;
    const int MIN_LENGTH=4;
    const int DATA_OFFSET=MIN_LENGTH;
    public:
        static const byte REQUEST = 1, RESPONSE = 2, SUCCESS = 3, FAILURE = 4;

        EapPacket(): buffer(MIN_LENGTH) {}
        EapPacket(const std::vector<byte> &bytes) : buffer(bytes) {}

        void setType(byte type){
            buffer[0] = type;
        }
        byte getType(){
            return buffer[0];
        }

        void setIdentifier(byte id){
            buffer[1] = id;
        }
        byte getIdentifier(){
            return buffer[1];
        }

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

        void setData(const EapData &data){
            buffer.insert(buffer.begin()+DATA_OFFSET,data.buffer.begin(),data.buffer.end());
        }

        EapData getData(){
            byte type =getType();
            if(type == SUCCESS || type == FAILURE){
                throw PacketAccessException("The EapPacket of this type doesn't have the data field");
            }

            std::vector tdBytes(buffer.begin()+DATA_OFFSET,buffer.end());
            return EapData(tdBytes);
        }


};

/**
 * EapPacket data field
 * 0 : type
 * 1+ : type-data
 */
class EapData {
    friend EapPacket;
    const MIN_LENGTH = 1;
    const DATA_OFFSET = MIN_LENGTH;
    protected:
    std::vector<byte>buffer;
    public:
    static const byte IDENTITY = 1,
                 MD5_CHALLENGE=4,
                 NAK = 3;

    EapTypeData(const std::vector<byte> & bytes) : buffer(bytes){}
    EapTypeData() : buffer(MIN_LENGTH) {}

    void setType(byte type){
        buffer[0] = type;
    }

    byte getType(){
        return buffer[0];
    }
    
};

/**
 * type : 1
 * type-data : username/message
 */
class EapIdentity : public EapData{

    public:
    EapIdentity(const std::vector<byte> & bytes) : buffer(bytes){ }
    EapIdentity() : buffer(MIN_LENGTH) {
        setType(EapTypeData::IDENTITY);
    }

    setIdentity(string identity){
        buffer.insert(buffer.begin()+DATA_OFFSET,identity.begin(),identity.end());
    }

    getIdentity(){
        return string(buffer.begin()+DATA_OFFSET,buffer.size()-DATA_OFFSET);
    }



};

/**
 * type : 3
 * type-data :
 *      1 : desired authentication mechanism (EapData type)
 */
class EapNak : public EapData{

    const LENGTH = 2;
    public:
    EapNak(const std::vector<byte> & bytes) : buffer(bytes){ }
    EapNak() : buffer(MIN_LENGTH) {
        setType(EapTypeData::NAK);
        buffer.resize(LENGTH);
    }

    setPrefAlgorithm(byte type){
        buffer[1] = type;
    }

    getPrefAlgorithm(){
        return buffer[1];
    }
};

/**
 * type : 4
 * type-data :
 *      1 : value-size
 *      + : value
 *      + : name
 */
class EapMd5Challenge : public EapData{

    const VAL_OFFSET = DATA_OFFSET + 1;

    public:
    EapMd5Challenge(const std::vector<byte> & bytes) : buffer(bytes){ }
    EapMd5Challenge() : buffer(MIN_LENGTH) {
        setType(EapTypeData::MD5_CHALLENGE);
    }

    byte getValueSize(){
        return buffer[1];
    }

    void setValueSize(byte size){
        buffer[1]= size;
    }

    void setValue(const std::vector<byte> &value){
        buffer.insert(buffer.begin()+VAL_OFFSET,value.begin(),value.end());
        setValueSize(value.size());
    }

    std::vector<byte> getValue(){
        byte * endPtr = buffer.begin()+DATA_OFFSET + getValueSize();
        return std::vector<byte> (buffer.begin()+DATA_OFFSET,endPtr);
    }

    void setName(const string &name){
        int offset = VAL_OFFSET + getValueSize();
        buffer.insert(buffer.begin()+offset,name.begin(),name.end());
    }

    string getName(){
        int offset = VAL_OFFSET + getValueSize();
        int len = buffer.size() - offset;
        return string(buffer.begin()+offset,len);
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

  void setIp(const string &ipStr) {
      std::array<byte, 4> ip;
      in_addr addr = inet_addr(ipStr.c_str());
      memcpy((void*) ip.begin(), &addr, sizeof(in_addr));
      setIp(ip);
  }

  in_addr getIp() {
    byte* addrPtr = buffer.begin() + RadiusAVP::VAL_OFFSET;
    struct in_addr addr;
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

  string getIdentifier() {
    int offset = RadiusAVP::VAL_OFFSET;
    return string(buffer.begin()+offset,buffer.size()-offset);
  }
};
