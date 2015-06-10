#pragma once
#include <exception>

class Exception : public std::exception {
  public:
    explicit Exception(const std::string &message) : msg_(message) {}
    const char *what() const throw() { return msg_.c_str(); }

  protected:
    std::string msg_;
};

