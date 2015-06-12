#pragma once
#include <exception>

class Exception : public std::exception {
  public:
    explicit Exception(const std::string &message) : msg_(message) {}
    const char *what() const throw() { return msg_.c_str(); }

  protected:
    std::string msg_;
};

class FileNotFound : public Exception {
  public:
    explicit FileNotFound(const std::string &message) : Exception(message) {}
};
