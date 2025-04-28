#ifndef FILTER_H
#define FILTER_H

#include <iostream>
#include <string>
#include <vector>
#include <fstream>  // file handling
#include <filesystem>
#include "json.hpp" // nlohmann::json library
using json = nlohmann::json;
namespace fs = std::filesystem;

// base filter class
class Filter {
protected:
    // tracking variables for a filter
    std::string name;  // filter identification
    bool enabled;  // if filter is active
    // other metadata
    std::string sourceIP;
    std::string destinationIP;
    std::string sourceMAC;
    std::string destinationMAC;

    // serialize to JSON
    virtual json Convert() const {
        return json{
            {"name", name},
            {"enabled", enabled},
            {"sourceIP", sourceIP},
            {"destinationIP", destinationIP},
            {"sourceMAC", sourceMAC},
            {"destinationMAC", destinationMAC}
        };
    }

    // deserialize from JSON
    static Filter DeConvert(const json& j) {
        return Filter(
            j.at("name").get<std::string>(),
            j.at("enabled").get<bool>(),
            j.at("sourceIP").get<std::string>(),
            j.at("destinationIP").get<std::string>(),
            j.at("sourceMAC").get<std::string>(),
            j.at("destinationMAC").get<std::string>()
        );
    }

public:
    // Constructor
    Filter(std::string n, bool e, std::string sp = "0.0.0.0", std::string dp = "0.0.0.0", std::string sm = "0.0.0.0", std::string dm = "0.0.0.0") : name(n), enabled(e), sourceIP(sp), destinationIP(dp), sourceMAC(sm), destinationMAC(dm) {}

    virtual ~Filter() = default; //allows for virtual destructor for safe polymorphic use

    // save filter to JSON (in filters/ directory)
    void Save() const {
        // ensure the filters directory exists
        fs::path dir = fs::current_path() / "filters";
        if (!fs::exists(dir)) {
            fs::create_directories(dir);
        }
        fs::path filePath = dir / (name + ".json");
        std::ofstream file(filePath);
        if (file.is_open()) {
            file << Convert().dump(4);
            file.close();
            std::cout << "Saved: " << filePath.string() << std::endl;
        }
        else {
            std::cout << "Error: Unable to open file for saving." << std::endl;
        }
    }

    // load filter from JSON (from filters/ directory)
    static Filter Load(Filter& filter) {
        fs::path dir = fs::current_path() / "filters";
        fs::path filePath = dir / (filter.name + ".json");
        std::ifstream file(filePath);
        if (!file.is_open()) {
            std::cerr << "Error: Unable to open file for loading." << std::endl;
            return filter;
        }
        json j;
        try {
            file >> j;
        }
        catch (const std::exception& e) {
            std::cerr << "Error: Invalid JSON format in " << filePath.string() << std::endl;
            file.close();
            return filter;
        }
        file.close();
        std::cout << "Loaded: " << filePath.string() << std::endl;
        return DeConvert(j);
    }

    // setters and getters
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

#endif