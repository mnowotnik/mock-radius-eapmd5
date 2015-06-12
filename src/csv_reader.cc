#include "csv_reader.h"
namespace radius{
std::map<std::string,std::string> readFile(const std::string fileName){
	io::CSVReader<2> in(fileName);
	  in.read_header(io::ignore_extra_column, "user", "password");
	std::string user,password;
	std::map<std::string,std::string> map;
	  while(in.read_row(user,password)){
		  map.insert({user,password});
    
  }
  return map;
}
}