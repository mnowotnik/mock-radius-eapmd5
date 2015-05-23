#ifndef __USER_H_INCLUDED__
#define __USER_H_INCLUDED__
#include<iostream>
#include <string>
/**
Class for encapsulating user parameters
 */
class User
{  
  public:
  /**
     Self explanatory construktor
  */
  User(std::string Username,std::string Password);
  /**
     getting password
   */
  std::string getPassword();
  /**
     getting username
   */
  std::string getUsername();
}
#endif//__USER_H_INCLUDED__
