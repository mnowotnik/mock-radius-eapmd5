#include<iostream>
#include <string>
#pragma once
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
