#include "Filter.h"
#include <filesystem>
using namespace std;
namespace fs = std::filesystem;

class ARPFilter : public Filter {
private:
    uint16_t hardwareType; // Hardware type
    uint16_t protocolType; // Protocol type
    uint8_t hardwareSize;  // Hardware size
    uint8_t protocolSize;  // Protocol size
    uint16_t opcode;       // Opcode

    // Override Convert with corrected keys
    json Convert() const override {
        json base = Filter::Convert();
        base["hardwareType"] = hardwareType;
        base["protocolType"] = protocolType;  // FIX: Use correct key name
        base["hardwareSize"] = hardwareSize;
        base["protocolSize"] = protocolSize;
        base["opcode"] = opcode;
        return base;
    }

    // Override DeConvert
    static ARPFilter DeConvert(const json& j) {
        return ARPFilter(
            j.at("name").get<std::string>(),
            j.at("enabled").get<bool>(),
            j.at("sourceIP").get<std::string>(),
            j.at("destinationIP").get<std::string>(),
            j.at("sourceMAC").get<std::string>(),
            j.at("destinationMAC").get<std::string>(),
            j.at("hardwareType").get<uint16_t>(),
            j.at("protocolType").get<uint16_t>(),
            j.at("hardwareSize").get<uint8_t>(),
            j.at("protocolSize").get<uint8_t>(),
            j.at("opcode").get<uint16_t>()
        );
    }

public:
    ARPFilter(std::string n, bool e,std::string sp, std::string dp, std::string sm, std::string dm, uint16_t ht, uint16_t pt, uint8_t hs, uint8_t ps, uint16_t op) : Filter(n, e, sp, dp, sm, dm), hardwareType(ht), protocolType(pt), hardwareSize(hs), protocolSize(ps), opcode(op) {}

    // Load filter from JSON (with exception handling)
    static ARPFilter Load(ARPFilter& filter) {
        fs::path dir = fs::current_path() / "filters";
        fs::path filePath = dir / (filter.GetName() + ".json");
        std::ifstream file(filePath);
        if (!file.is_open()) {
            std::cerr << "Error: Unable to open file for loading." << std::endl;
            return filter;
        }
        json j;
        try {
            file >> j;
        } catch (const std::exception& e) {
            std::cerr << "Error: Invalid JSON format in " << filePath.string() << std::endl;
            file.close();
            return filter;
        }
        file.close();
        std::cout << "Loaded: " << filePath.string() << std::endl;
        return DeConvert(j);
    }

    // SETTERS and GETTERS
    uint16_t GetHardwareType() const { return hardwareType; }
    void SetHardwareType(uint16_t ht) { hardwareType = ht; }

    uint16_t GetProtocolType() const { return protocolType; }
    void SetProtocolType(uint16_t pt) { protocolType = pt; }

    uint8_t GetHardwareSize() const { return hardwareSize; }
    void SetHardwareSize(uint8_t hs) { hardwareSize = hs; }

    uint8_t GetProtocolSize() const { return protocolSize; }
    void SetProtocolSize(uint8_t ps) { protocolSize = ps; }

    uint16_t GetOpcode() const { return opcode; }
    void SetOpcode(uint16_t op) { opcode = op; }
};