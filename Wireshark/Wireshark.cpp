#include <iostream>
#include <vector>
#include <limits>
#include <filesystem>
#include <regex>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <pcap.h>
#undef max // allows max to work

#include "Filter.h"
#include "ICMP.cpp"
#include "ARP.cpp"
#include "DHCP.cpp"
#include "DNS.cpp"

namespace fs = std::filesystem;

// Validate filter names
bool IsValidName(const std::string& name) {
    if (name.empty()) return false;
    static const std::string allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_ ";
    return (name.find_first_not_of(allowed) == std::string::npos);
}

// Find all JSON files in filters/ directory (create directory if needed)
std::vector<std::string> GetFilterNames() {
    std::vector<std::string> names;
    fs::path filterDir = fs::current_path() / "filters";
    if (!fs::exists(filterDir)) {
        fs::create_directories(filterDir);
    }
    for (auto& entry : fs::directory_iterator(filterDir)) {
        if (!entry.is_regular_file()) continue;
        if (entry.path().extension() == ".json") {
            names.push_back(entry.path().stem().string());
        }
    }
    return names;
}

// List all filter names
void listFilters() {
    auto filterNames = GetFilterNames();
    if (filterNames.empty()) {
        std::cout << "-ERROR-NO FILTERS FOUND-" << std::endl;
    }
    else {
        std::cout << std::endl << "CURRENT FILTERS:" << std::endl;
        for (const auto& n : filterNames) {
            std::cout << "  - " << n << std::endl;
        }
    }
}

// Show contents of a filter JSON
void viewFilters() {
    auto filterNames = GetFilterNames();
    if (filterNames.empty()) {
        std::cout << "-ERROR-NO FILTERS FOUND-" << std::endl;
        return;
    }
    listFilters();
    std::string filterName;
    std::cout << "\nENTER FILTER NAME TO VIEW DETAILS: ";
    std::getline(std::cin >> std::ws, filterName);

    if (!IsValidName(filterName)) {
        std::cout << "-ERROR-INVALID FILTER NAME-" << std::endl;
        return;
    }
    fs::path filePath = fs::current_path() / "filters" / (filterName + ".json");
    std::ifstream file(filePath);
    if (file.is_open()) {
        json j;
        try {
            file >> j;
        }
        catch (const std::exception& e) {
            std::cerr << "-ERROR-INVALID JSON FORMAT-" << std::endl;
            file.close();
            return;
        }
        file.close();
        std::cout << "\nFILTER DETAILS FOR: " << filterName << std::endl;
        for (auto& [key, value] : j.items()) {
            std::cout << key << ": " << value << std::endl;
        }
    }
    else {
        std::cout << "-ERROR-FILTER FILE NOT FOUND-" << std::endl;
    }
}

// Remove (delete) a filter JSON file
void removeFilter() {
    auto filterNames = GetFilterNames();
    if (filterNames.empty()) {
        std::cout << "-ERROR-EMPTY FILTER LIST-" << std::endl;
        return;
    }
    listFilters();
    std::string filterName;
    std::cout << std::endl << "ENTER FILTER NAME TO REMOVE: ";
    std::getline(std::cin >> std::ws, filterName);

    if (!IsValidName(filterName)) {
        std::cout << "-ERROR-INVALID FILTER NAME-" << std::endl;
        return;
    }
    fs::path filePath = fs::current_path() / "filters" / (filterName + ".json");
    if (fs::exists(filePath)) {
        fs::remove(filePath);
        std::cout << "FILTER REMOVED" << std::endl;
    }
    else {
        std::cout << "-ERROR-FILTER NOT FOUND-" << std::endl;
    }
}

// Toggle enabled state of a filter
void toggleFilter() {
    auto filterNames = GetFilterNames();
    if (filterNames.empty()) {
        std::cout << "-ERROR-NO FILTERS FOUND-" << std::endl;
        return;
    }
    listFilters();
    std::string name;
    std::cout << "\nENTER FILTER NAME TO TOGGLE: ";
    std::getline(std::cin >> std::ws, name);
    if (!IsValidName(name)) {
        std::cout << "-ERROR-INVALID FILTER NAME-" << std::endl;
        return;
    }
    fs::path filePath = fs::current_path() / "filters" / (name + ".json");
    std::ifstream file(filePath);
    if (!file.is_open()) {
        std::cout << "-ERROR-FILTER NOT FOUND-" << std::endl;
        return;
    }
    json j;
    try {
        file >> j;
    }
    catch (const std::exception& e) {
        std::cerr << "-ERROR-INVALID-JSON-FORMAT-" << std::endl;
        file.close();
        return;
    }
    file.close();
    bool current = j.value("enabled", false);
    j["enabled"] = !current;
    std::ofstream out(filePath);
    if (!out.is_open()) {
        std::cout << "-ERROR-UNABLE TO WRITE-" << std::endl;
        return;
    }
    out << j.dump(4);
    out.close();
    std::cout << "-FILTER " << (j["enabled"].get<bool>() ? "ENABLED-" : "DISABLED-") << std::endl;
}

// Add a new filter based on user input, with validation
void addFilters() {
    std::cout << "Select filter type to add:" << std::endl
              << "  1: ARP" << std::endl
              << "  2: ICMP" << std::endl
              << "  3: DNS" << std::endl
              << "  4: DHCP" << std::endl
              << "Choice: ";
    int t; std::cin >> t;
    if (std::cin.fail() || t<1 || t>4) { std::cin.clear(); std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); std::cout<<"-ERROR-INVALID CHOICE-"<<std::endl; return; }

    std::string name, sp, dp, sm, dm;
    bool en;
    std::getline(std::cin, name); // eat newline
    std::cout << "ENTER NAME [filter]: ";
    std::getline(std::cin >> std::ws, name);
    if (!IsValidName(name)) { std::cout<<"-ERROR-INVALID NAME-"<<std::endl; return; }
    fs::path p = fs::current_path()/"filters"/(name+".json");
    if (fs::exists(p)) { std::cout<<"Filter already exists. Overwrite? [y/n]: "; char c; std::cin>>c; if(c!='y'&&c!='Y'){std::cout<<"ADD CANCELLED"<<std::endl;return;} }

    std::cout<<"ENTER SOURCE IP [0.0.0.0]: "; std::cin>>sp;
    std::cout<<"ENTER DESTINATION IP [0.0.0.0]: "; std::cin>>dp;
    std::cout<<"ENTER SOURCE MAC [0.0.0.0]: "; std::cin>>sm;
    std::cout<<"ENTER DESTINATION MAC [0.0.0.0]: "; std::cin>>dm;
    std::cout<<"ENTER ENABLED [1=yes,0=no]: "; std::cin>>en;

    switch(t) {
    case 1: { // ARP
        int ht,pt,hs,ps,op;
        std::cout<<"ENTER HARDWARE TYPE [1=Ethernet]: "; std::cin>>ht;
        std::cout<<"ENTER PROTOCOL TYPE [2048=IPv4]: "; std::cin>>pt;
        std::cout<<"ENTER HARDWARE SIZE [6]: "; std::cin>>hs;
        std::cout<<"ENTER PROTOCOL SIZE [4]: "; std::cin>>ps;
        std::cout<<"ENTER OPCODE [1=req,2=rep]: "; std::cin>>op;
        ARPFilter f(name,en,sp,dp,sm,dm,ht,pt,hs,ps,op);
        f.Save();
        break;
    }
    case 2: {
        int tp,cd,rate,pl; bool b;
        std::cout<<"ENTER ICMP TYPE [8=EchoReq]: "; std::cin>>tp;
        std::cout<<"ENTER ICMP CODE [0]: "; std::cin>>cd;
        std::cout<<"ENTER MAX PACKET RATE [/sec,0=any]: "; std::cin>>rate;
        std::cout<<"ENTER MAX PAYLOAD SIZE [bytes,0=any]: "; std::cin>>pl;
        std::cout<<"ENTER IF BROADCAST? [1=yes,0=no]: "; std::cin>>b;
        ICMPFilter f(name,en,sp,dp,sm,dm,tp,cd,rate,pl,b);
        f.Save();
        break;
    }
    case 3: {
        int dt,qr; std::string dom; bool r;
        std::cout<<"ENTER DNS TYPE [1=A]: "; std::cin>>dt;
        std::cout<<"ENTER MAX QUERY RATE [/sec,0=any]: "; std::cin>>qr;
        std::cout<<"ENTER DOMAIN FILTER [example.com]: "; std::getline(std::cin>>std::ws,dom);
        std::cout<<"ENTER IF RECURSIVE? [1=yes,0=no]: "; std::cin>>r;
        DNSFilter f(name,en,sp,dp,sm,dm,dt,qr,dom,r);
        f.Save();
        break;
    }
    case 4: {
        int dt,cd,rate,pl; bool b;
        std::cout<<"ENTER DHCP TYPE [1=req,2=rep]: "; std::cin>>dt;
        std::cout<<"ENTER DHCP CODE [1-8]: "; std::cin>>cd;
        std::cout<<"ENTER MAX PACKET RATE [/sec,0=any]: "; std::cin>>rate;
        std::cout<<"ENTER MAX PAYLOAD SIZE [bytes,0=any]: "; std::cin>>pl;
        std::cout<<"ENTER IF BROADCAST? [1=yes,0=no]: "; std::cin>>b;
        DHCPFilter f(name,en,sp,dp,sm,dm,dt,cd,rate,pl,b);
        f.Save();
        break;
    }
    }
}

// Main menu
int main(int argc, char* argv[]) {
    // Ensure filters directory exists
    fs::path filterDir = fs::current_path() / "filters";
    if (!fs::exists(filterDir)) {
        fs::create_directory(filterDir);
    }

    while (true) {
        std::cout << std::endl << "---NETWORK-FILTER-MANAGER---" << std::endl
                  << "1: LIST" << std::endl
                  << "2: ADD" << std::endl
                  << "3: REMOVE" << std::endl
                  << "4: DETAILS" << std::endl
                  << "5: ENABLE" << std::endl
                  << "6: END" << std::endl
                  << "Choice [1-6]: ";
        int choice;
        std::cin >> choice;

        // Validate main menu input
        if (std::cin.fail()) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            std::cout << "-ERROR-INVALID CHOICE-" << std::endl;
            continue;
        }

        switch (choice) {
            case 1:
                listFilters();
                break;
            case 2:
                addFilters();
                break;
            case 3:
                removeFilter();
                break;
            case 4:
                viewFilters();
                break;
            case 5:
                toggleFilter();
                break;
            case 6:
                std::cout << std::endl << "-ENDING PROGRAM-!" << std::endl;
                return 0;
            default:
                std::cout << "-ERROR-INVALID CHOICE-" << std::endl;
            }
    }
}