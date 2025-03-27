#ifndef FILTER_H
#define FILTER_H

#include <iostream>
#include <string>
#include <vector>
#include <fstream> // file handling
#include "json.hpp" // json Library (not ours)
using json = nlohmann::json;


// base filter class
class Filter {
    protected:
        // ALL TRACKING VARIABLES GO HERE
        std::string name;     // name of filter for identificaiton
        bool enabled;         // if filter is active and scanning packets

        // other metadata used in a packet
        std::string sourceIP;
        std::string destinationIP;
        std::string sourceMAC;
        std::string destinationMAC;

        // creates a json form a filter
        virtual json Convert() const {
            return json{ // PUT ALL VARIABLES IN HERE
                {"name", name},
                {"enabled", enabled},
                {"sourceIP", sourceIP},
                {"destinationIP", destinationIP},
                {"sourceMAC", sourceMAC},
                {"destinationMAC", destinationMAC}
            };
        }

        // creates a filter form a json
        static Filter DeConvert(const json& j) {
            return Filter( // PUT ALL VARIABLES IN HERE
                j.at("name").get<std::string>(),
                j.at("enabled").get<bool>(),
                j.at("sourceIP").get<std::string>(),
                j.at("destinationIP").get<std::string>(),
                j.at("sourceMAC").get<std::string>(),
                j.at("destinationMAC").get<std::string>()
            );
        }

    public:
        // constructor
        Filter(std::string n, bool e, std::string sp = "0.0.0.0", std::string dp = "0.0.0.0", std::string sm = "0.0.0.0", std::string dm = "0.0.0.0") : name(n), enabled(e), sourceIP(sp), destinationIP(dp), sourceMAC(sm), destinationMAC(dm) {} //LIST OF ALL VARIABLES THAT CAN BE ALTERED BY USER

        // Save filter to json
        void Save() const {
            std::ofstream file(name + ".json");
            if (file.is_open()) {
                file << Convert().dump(4);
                file.close();
                std::cout << "Saved: " << name + ".json" << std::endl;
            }
            else { // if file cannot be opened
                std::cout << "Error: Unable to open file for saving." << std::endl;
            }
        }

        // Load filter from json
        // can be used not directly form a filter object
        static Filter Load(Filter& filter) {
            std::ifstream file(filter.name + ".json"); //uses name of givin filter
            if (file.is_open()) {
                json j;
                file >> j;
                file.close();
                std::cout << "Loaded: " << filter.name + ".json" << std::endl;
                return DeConvert(j);
            }
            else { // if file cannot be opened
                std::cerr << "Error: Unable to open file for loading." << std::endl;
            }
        }

        // whenever changes to filters want to be saved, you will need to save the changes into the json file
        //SETTER and GETTERS
        void SetName(const std::string& n) { name = n; }
        std::string GetName() const { return name; }

        void SetEnable(bool e) { enabled = e; }
        bool GetEnable() const { return enabled; }

        void SetSourceIP(const std::string& ip) { sourceIP = ip; }
        std::string GetSourceIP() const { return sourceIP; }

        void SetDestinationIP(const std::string& ip) { destinationIP = ip; }
        std::string GetDestinationIP() const { return destinationIP; }

        void SetSourceMAC(const std::string& mac) { sourceMAC = mac; }
        std::string GetSourceMAC() const { return sourceMAC; }

        void SetDestinationMAC(const std::string& mac) { destinationMAC = mac; }
        std::string GetDestinationMAC() const { return destinationMAC; }

};

#endif FILTER_H



