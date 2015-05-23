#ifndef __INTERACTIVE_H_INCLUDED__
#define __INTERACTIVE_H_INCLUDED__


#include <string>



/**
Safely get string from standard input ('*' instead of input when show_asterix=true)
 */
std::string getPassword(const char *prompt, bool show_asterisk=true);
#endif//__INTERACTIVE_H_INCLUDED__
