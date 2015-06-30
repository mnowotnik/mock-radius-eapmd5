#ifndef USER_H_ANZMS7CW
#define USER_H_ANZMS7CW

#include <iostream>
#include <string>
/**
Class for encapsulating user parameters
 */
class User {
  public:
    /**
       Self explanatory construktor
    */
    User(std::string Username, std::string Password);
    /**
       getting password
     */
    std::string getPassword();
    /**
       getting username
     */
    std::string getUsername();
}


#endif /* end of include guard: USER_H_ANZMS7CW */
