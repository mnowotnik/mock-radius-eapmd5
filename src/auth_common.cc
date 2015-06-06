#include "auth_common.h"

using radius::packets::RadiusPacket;

namespace{




}

namespace radius{

    bool checkIntegrity(const RadiusPacket &packet,
            const std::string &secret,
            const std::vector<byte>&authenticator=std::vector<byte>()){
    
        return false;
    
    }


}
