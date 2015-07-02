#include <cstring>
#include "sockets.h"
#include "typedefs.h"
namespace radius{
void initAddr(sockaddr_in &addr,const std::string &ip,const int port);
}
