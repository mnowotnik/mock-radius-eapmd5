#pragma once
#include "packets/packet.h"

class EapMessage;
class EapPacket;


/**
 * EapPacket data field
 * 0 : type
 * 1+ : type-data
 */
class EapData {
    friend EapPacket;
    protected:
    const int MIN_LENGTH = 1;
    const int DATA_OFFSET = MIN_LENGTH;
    std::vector<byte>buffer;
    public:
    static const byte IDENTITY = 1,
                 MD5_CHALLENGE=4,
                 NAK = 3;

    EapData(const std::vector<byte> & bytes) : buffer(bytes){}
    EapData() : buffer(MIN_LENGTH) {}

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
    EapIdentity(const std::vector<byte> & bytes) : EapData(bytes){ }
    EapIdentity(){
        setType(EapData::IDENTITY);
    }

    void setIdentity(const std::string &identity){
        buffer.insert(buffer.begin()+DATA_OFFSET,identity.begin(),identity.end());
    }

    std::string getIdentity(){
        return std::string((const char*)&(buffer[DATA_OFFSET]),buffer.size()-DATA_OFFSET);
    }



};

/**
 * type : 3
 * type-data :
 *      1 : desired authentication mechanism (EapData type)
 */
class EapNak : public EapData{

    const int LENGTH = 2;
    public:
    EapNak(const std::vector<byte> & bytes) : EapData(bytes){ }
    EapNak(){
        setType(EapData::NAK);
        buffer.resize(LENGTH);
    }

    void setPrefAlgorithm(byte type){
        buffer[1] = type;
    }

    byte getPrefAlgorithm(){
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

    const int VAL_OFFSET = DATA_OFFSET + 1;

    public:
    EapMd5Challenge(const std::vector<byte> & bytes) : EapData(bytes){ }
    EapMd5Challenge(){
        setType(EapData::MD5_CHALLENGE);
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
        std::vector<byte>::iterator itEnd = buffer.begin()+DATA_OFFSET + getValueSize();
        return std::vector<byte> (buffer.begin()+DATA_OFFSET,itEnd);
    }

    void setName(const std::string &name){
        int offset = VAL_OFFSET + getValueSize();
        buffer.insert(buffer.begin()+offset,name.begin(),name.end());
    }

    std::string getName(){
        int offset = VAL_OFFSET + getValueSize();
        int len = buffer.size() - offset;
        return std::string((const char *)&buffer[offset],len);
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

            std::vector<byte> tdBytes(buffer.begin()+DATA_OFFSET,buffer.end());
            return EapData(tdBytes);
        }


};
