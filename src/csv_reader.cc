#include "csv_reader.h"

namespace radius{
	
std::map<std::string,std::string> readCsvFile(const std::string &fileName){
	
	  
	//std::cout<<"Mamo jestem w komputerze"<<std::endl;
	std::string user,password,line;
	std::ifstream fileStream;
	fileStream.open(fileName);
	
	std::map<std::string,std::string> map;
	std::map<std::string,std::string>::iterator it = map.begin();
	if (fileStream.is_open())
	{

    while(std::getline(fileStream,line))
    {
        std::stringstream  lineStream(line);
        std::string        cell;
        while(std::getline(lineStream,cell,','))
        {
            user = cell;
			std::getline(lineStream,cell,',');
			password = cell;
        }
		map[user]=password; 
    }
		 
  }
else
{
		std::cout<<"unable to open file"<<std::endl;
}
	fileStream.close();
  return map;
}
}//namespace