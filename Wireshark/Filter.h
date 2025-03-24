#define FILTER_H

#include <iostream>
#include <string>
#include <vector>
#include <fstream> // file handling
#include "json.hpp" // json Library (not ours)
using json = nlohmann::json;


// base filter class
class Filter {
    private:
        // ALL TRACKING VARIABLES GO HERE
        std::string name;     // name of filter for identificaiton
        bool enabled;         // if filter is active and scanning packets

        // creates a json form a filter
        virtual json Convert() const {
            return json{ // PUT ALL VARIABLES IN HERE
                {"name", name},
                {"enabled", enabled}
            };
        }

        // creates a filter form a json
        static Filter DeConvert(const json& j) {
            return Filter( // PUT ALL VARIABLES IN HERE
                j.at("name").get<std::string>(),
                j.at("enabled").get<bool>()
            );
        }

    public:
        // constructor
        Filter(std::string n, bool e) : name(n), enabled(e) {} //LIST OF ALL VARIABLES THAT CAN BE ALTERED BY USER

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
        void SetName(std::string n) { name = n; }
        std::string GetName() { return name; }

        void SetEnable(bool e) { enabled = e; }
        bool GetEnable() { return enabled; }
};


