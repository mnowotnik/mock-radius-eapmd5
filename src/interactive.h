#ifndef INTERACTIVE_H_RMHUOYRK
#define INTERACTIVE_H_RMHUOYRK

#include <string>
/**
Safely get string from standard input ('*' instead of input when
show_asterix=true)
 */
namespace radius {
std::string getPassword(const std::string &prompt = "Enter password> ");
std::string getUsername();
}


#endif /* end of include guard: INTERACTIVE_H_RMHUOYRK */
