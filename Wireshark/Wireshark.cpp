#include <iostream>
#include <vector>
#include <limits>
#include <filesystem>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <pcap.h>

#include "Filter.h"
#include "ICMP.cpp"
#include "ARP.cpp"
#include "DHCP.cpp"
#include "DNS.cpp"

namespace fs = std::filesystem;

// finds all json files and returns their names so they can be displayed
std::vector<std::string> GetFilterNames()
{
    std::vector<std::string> names;
    for (auto& entry : fs::directory_iterator(fs::current_path())) {
        if (!entry.is_regular_file())
            continue;
        if (entry.path().extension() == ".json") {
            names.push_back(entry.path().stem().string());
        }
    }
    return names;
}

// used to list all json filter files when asked
void listFilters()
{
    auto filterNames = GetFilterNames();
    if (filterNames.empty()) {
        std::cout << "-ERROR--NO FILTERS FOUND-" << std::endl;
    }
    else {
        std::cout << std::endl << "CURRENT FILTERS:" << std::endl;
        for (const auto& n : filterNames) {
            std::cout << "  - " << n << std::endl;
        }
    }
}

// Displays all data inside a json file
void viewFilters() {
    auto filterNames = GetFilterNames();
    if (filterNames.empty()) {
        std::cout << "-ERROR--NO FILTERS FOUND-" << std::endl;
        return;
    }
    listFilters();
    std::string filterName;
    std::cout << "\nENTER FILTER NAME TO VIEW DETAILS: ";
    std::getline(std::cin >> std::ws, filterName);

    std::ifstream file(filterName + ".json");
    if (file.is_open()) {
        json j;
        file >> j;
        file.close();
        std::cout << "\nFILTER DETAILS FOR: " << filterName << std::endl;
        for (auto& [key, value] : j.items()) {
            std::cout << key << ": " << value << std::endl;
        }
    }
    else {
        std::cout << "-ERROR--FILTER FILE NOT FOUND-" << std::endl;
    }
}
    

// Remove a filter by deleting the json file if you type its name
void removeFilter() {
    auto filterNames = GetFilterNames();
    if (filterNames.empty()) {
        std::cout << "-ERROR-EMPTY FILTER LIST-" << std::endl;
        return;
    }
    listFilters();
    std::string filterName;
    std::cout << std::endl << "ENTER FILE NAME TO REMOVE: ";
    std::getline(std::cin >> std::ws, filterName);

    std::string jsonFile = filterName + ".json";
    if (fs::exists(jsonFile)) {
        fs::remove(jsonFile);
        std::cout << "FILTER REMOVED: " << filterName << std::endl;
    }
    else {
        std::cout << "-ERROR--NO FILTERS FOUND-" << std::endl;
    }
}

// creates a new filter based on player input
void addFilters()
{
    // user inputs what kind of filter they want
    std::cout << "Select filter type to add:" << std::endl
        << "  1: ARP" << std::endl
        << "  2: ICMP" << std::endl
        << "  3: DNS" << std::endl
        << "  4: DHCP" << std::endl
        << "Choice: ";
    int filterType;
    std::cin >> filterType;

    // users input data based on which 
    std::string sourceIP, destinationIP, sourceMAC, destinationMAC, name;
    bool enable;
    switch (filterType) {
    case (1): { // ARP
        uint16_t hardwareType, protocolType, opcode;
        uint8_t hardwareSize, protocolSize;

        std::cout << "ENTER NAME [filter]: ";
        std::cin >> name;

        std::cout << "ENTER SOURCE IP [0.0.0.0]: ";
        std::cin >> sourceIP;

        std::cout << "ENTER DESTINATION IP [0.0.0.0]: ";
        std::cin >> destinationIP;

        std::cout << "ENTER SOURCE MAC [0.0.0.0]: ";
        std::cin >> sourceMAC;

        std::cout << "ENTER DESTINATION MAC [0.0.0.0]: ";
        std::cin >> destinationMAC;

        std::cout << "ENTER HARDWARE TYPE [1=Ethernet]: ";
        std::cin >> hardwareType;

        std::cout << "ENTER PROTOCOL TYPE [0x0800=IPv4]: ";
        std::cin >> protocolType;

        std::cout << "ENTER HARDWARE SIZE [6]: ";
        std::cin >> hardwareSize;

        std::cout << "ENTER PROTOCOL SIZE [4]: ";
        std::cin >> protocolSize;

        std::cout << "ENTER OPCODE [1=request, 2=reply]: ";
        std::cin >> opcode;

        std::cout << "ENTER ENABLED [1=yes,0=no]: ";
        std::cin >> enable;

        ARPFilter filter = ARPFilter(name, enable, sourceIP, destinationIP, sourceMAC, destinationMAC, hardwareType, protocolType, hardwareSize, protocolSize, opcode);
        filter.Save();

        break;
    }
    case (2): { // ICMP
        int icmpType, icmpCode, packetRate;
        uint16_t payloadSize;
        bool isBroadcast;

        std::cout << "ENTER NAME [filter]: ";
        std::cin >> name;

        std::cout << "ENTER SOURCE IP [0.0.0.0]: ";
        std::cin >> sourceIP;

        std::cout << "ENTER DESTINATION IP [0.0.0.0]: ";
        std::cin >> destinationIP;

        std::cout << "ENTER SOURCE MAC [0.0.0.0]: ";
        std::cin >> sourceMAC;

        std::cout << "ENTER DESTINATION MAC [0.0.0.0]: ";
        std::cin >> destinationMAC;

        std::cout << "ENTER ENABLED [1=yes,0=no]: ";
        std::cin >> enable;

        std::cout << "ENTER ICMP TYPE [8=Echo Request]: ";
        std::cin >> icmpType;

        std::cout << "ENTER ICMP CODE [0]: ";
        std::cin >> icmpCode;

        std::cout << "ENTER MAX PACKET RATE [/sec, 0=any]: ";
        std::cin >> packetRate;

        std::cout << "ENTER MAX PAYLOAD SIZE [bytes, 0=any]: ";
        std::cin >> payloadSize;

        std::cout << "ENTER IF BROADCAST? [1=yes, 0=no]: ";
        std::cin >> isBroadcast;

        ICMPFilter filter = ICMPFilter(name, enable, sourceIP, destinationIP, sourceMAC, destinationMAC, icmpType, icmpCode, packetRate, payloadSize, isBroadcast);
        filter.Save();

        break;
    }
    case (3): { // DNS
        int dnsType, queryRate;
        std::string domain;
        bool isRecursive;

        std::cout << "ENTER NAME [filter]: ";
        std::cin >> name;

        std::cout << "ENTER SOURCE IP [0.0.0.0]: ";
        std::cin >> sourceIP;

        std::cout << "ENTER DESTINATION IP [0.0.0.0]: ";
        std::cin >> destinationIP;

        std::cout << "ENTER SOURCE MAC [0.0.0.0]: ";
        std::cin >> sourceMAC;

        std::cout << "ENTER DESTINATION MAC [0.0.0.0]: ";
        std::cin >> destinationMAC;


        std::cout << "ENTER DNS TYPE [1=A record]: ";
        std::cin >> dnsType;

        std::cout << "ENTER MAX QUERY RATE [/sec, 0=any]: ";
        std::cin >> queryRate;

        std::cout << "ENTER DOMAIN FILTER [example.com]: ";
        std::cin >> domain;

        std::cout << "ENTER IF RECURSIVE? [1=yes, 0=no]: ";
        std::cin >> isRecursive;

        DNSFilter filter = DNSFilter(name, enable, sourceIP, destinationIP, sourceMAC, destinationMAC, dnsType, queryRate, domain, isRecursive);
        filter.Save();

        break;
    }
    case (4): { // DHCP
        int dhcpType, dhcpCode, packetRate;
        uint16_t payloadSize;
        bool isBroadcast;

        std::cout << "ENTER NAME [filter]: ";
        std::cin >> name;

        std::cout << "ENTER SOURCE IP [0.0.0.0]: ";
        std::cin >> sourceIP;

        std::cout << "ENTER DESTINATION IP [0.0.0.0]: ";
        std::cin >> destinationIP;

        std::cout << "ENTER SOURCE MAC [0.0.0.0]: ";
        std::cin >> sourceMAC;

        std::cout << "ENTER DESTINATION MAC [0.0.0.0]: ";
        std::cin >> destinationMAC;


        std::cout << "ENTER DHCP TYPE [1=request,2=reply]: ";
        std::cin >> dhcpType;

        std::cout << "ENTER DHCP CODE     [1-8]: ";
        std::cin >> dhcpCode;

        std::cout << "ENTER MAX PACKET RATE [/sec,0=any]: ";
        std::cin >> packetRate;

        std::cout << "ENTER MAX PAYLOAD SIZE [bytes,0=any]: ";
        std::cin >> payloadSize;

        std::cout << "ENTER IF BROADCAST [1=yes,0=no]: ";
        std::cin >> isBroadcast;

        std::cout << "ENTER ENABLED [1=yes,0=no]: ";
        std::cin >> enable;

        DHCPFilter filter = DHCPFilter(name, enable, sourceIP, destinationIP, sourceMAC, destinationMAC, dhcpType, dhcpCode, packetRate, payloadSize, isBroadcast);
        filter.Save();

        break;
    }
    default:
        std::cout << "-ERROR-INVALID CHOICE-" << std::endl;
    }
}

// main method 
int main(int argc, char* argv[]) {
    //user selects choice to interact with the filters
    while (true)
    {
        std::cout << std::endl << "---NETWORK-FILTER-MANAGER---" << std::endl
            << "1: LIST" << std::endl
            << "2: ADD" << std::endl
            << "3: REMOVE" << std::endl
            << "4: DETAILS" << std::endl
            << "5: END" << std::endl
            << "Choice: ";
        int choice;
        std::cin >> choice;
        switch (choice) //user inputs option for managing filter
        {
        case (1): {
            listFilters();
            break;
        }
        case (2): {
            addFilters();
            break;
        }
        case (3): {
            removeFilter();
            break;
        }
        case (4): {
            viewFilters();
            break;
        }
        case (6): {
            std::cout << std::endl << "-ENDING PROGRAM-!" << std::endl;
            return 0;
        }
        default:
            std::cout << "-ERROR-INVALID CHOICE-" << std::endl;
        }
    }
}
