//Michal Szulc 03/05
//Radius Server
#include <boost/program_options.hpp>
namespace po = boost::program_options;

#include <iostream>
#include <algorithm>
#include <iterator>
using namespace std;

int test()
{
  return 0;
}

int main(int ac, char* av[])
{
  //zarzadzanie opcjami
  string ip;
  string user;
    try {

        po::options_description desc("Allowed options");
        desc.add_options()
	  ("help,h", "produce help message")
	  ("user,u", po::value<string>(&user), "set username")
	  ("test,t", "perform test")
	  ("client,c", "run as client")
	  ("server,s", "run as server")
	  ("ip", po::value<string>(&ip),"set ip address")
	  	  
        ;

        po::variables_map vm;        
        po::store(po::parse_command_line(ac, av, desc), vm);
        po::notify(vm);    

        if (vm.count("help")) {
            cout << desc << "\n";
            return 1;
        }

        if (vm.count("test,t"))
	  {
	  if (test())
	    {
	      cout<<"Test unsuccesfull";
	      return 1;
	    }
	  else
	    {
	      cout<<"Test succesfull";
	      return 0;
	    }
        }
    }
    catch(exception& e) {
        cerr << "error: " << e.what() << "\n";
        return 1;
    }
    catch(...) {
        cerr << "Exception of unknown type!\n";
    }
    //wlasciwy program
    return 0;
}

