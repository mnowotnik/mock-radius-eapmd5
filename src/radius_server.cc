#include "radius_server.h"
using std::map;
using std::string;
using std::vector;
using radius::packets::Packet;

namespace radius{
RadiusServer::RadiusServer(const map<string,string> &userPassMap,const string &secret){
}

vector<Packet> RadiusServer::recvPacket(const Packet &packet){
    return vector<Packet>();
}

}
