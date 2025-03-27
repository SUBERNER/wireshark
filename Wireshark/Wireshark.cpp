#include <iostream>
#include <vector>
#include "Filter.h"
#include "ICMP.cpp"



// main method 
int main(int argc, char* argv[])
{
    std::cout << "All Active Filters: " << std::endl;
    
    //all below is testing
    Filter test1 = Filter("Block DNS", true);
    Filter test2 = Filter("Block ICMP", false, "127.0.0.1", "9.9.9.9", "127.5.5.127","127.20.20.127");
    ICMPFilter test4 = ICMPFilter("ICMP BIGGER TEST", false, "127.0.0.1", "9.9.9.9", "127.5.5.127", "127.20.20.127", 1, 1, 1, 1, true);
    
    for (int i = 0; i <= 5; i++)
    {
        std::cout << i << std::endl;
    }

    test1.Save();
    test2.Save();
    test4.Save();

    Filter test3 = Filter::Load(test2);
    std::cout << test3.GetName() << std::endl;
    std::cout << test3.GetEnable() << std::endl;
    std::cout << test3.GetSourceIP() << std::endl;
    std::cout << test3.GetSourceMAC() << std::endl;
    std::cout << test3.GetDestinationMAC() << std::endl;
    std::cout << test3.GetDestinationIP() << std::endl;
}

