#include <iostream>
#include <vector>
#include "Filter.h"



// main method 
int main(int argc, char* argv[])
{
    std::cout << "All Active Filters: " << std::endl;
    
    //all below is testing
    Filter test1 = Filter("Block DNS", true);
    Filter test2 = Filter("Block ICMP", false);
    
    for (int i = 0; i <= 5; i++)
    {
        std::cout << i << std::endl;
    }

    test1.Save();
    test2.Save();

    Filter test3 = Filter::Load(test2);
    std::cout << test3.GetName() << std::endl;
    std::cout << test3.GetEnable() << std::endl;
}

