#include<iostream>
#include<string>
class User
{
  
private:
  //std::string * const username;//czy tak jest bezpieczniej?
  //std::string * const password;
  std::string username,password;

public:
  User(const std::string Username,const std::string Password)
  {
    username = Username;
    password = Password;
  }
  std::string getPassword()
  {
    return password;
  }
  std::string getUsername()
  {
    return username;
  }
  
};
