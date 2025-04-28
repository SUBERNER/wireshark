#include "Filter.h"
#include <filesystem>
using namespace std;
namespace fs = std::filesystem;

class DHCPFilter : public Filter {
private:
    int packetRate;  // requests per second
    uint16_t payloadSize; // payload size
    int dhcpType;  // DHCP message type
    int dhcpCode;  // DHCP message code
    bool isBroadcast;  // broadcast address?

    // Override Convert
    json Convert() const override {
        json base = Filter::Convert();
        base["dhcpType"] = dhcpType;
        base["dhcpCode"] = dhcpCode;
        base["packetRate"] = packetRate;
        base["payloadSize"] = payloadSize;
        base["isBroadcast"] = isBroadcast;
        return base;
    }

    // Override DeConvert (fixed field order: payloadSize, isBroadcast)
    static DHCPFilter DeConvert(const json& j) {
        return DHCPFilter(
            j.at("name").get<std::string>(),
            j.at("enabled").get<bool>(),
            j.at("sourceIP").get<std::string>(),
            j.at("destinationIP").get<std::string>(),
            j.at("sourceMAC").get<std::string>(),
            j.at("destinationMAC").get<std::string>(),
            j.at("dhcpType").get<int>(),
            j.at("dhcpCode").get<int>(),
            j.at("packetRate").get<int>(),
            j.at("payloadSize").get<uint16_t>(),
            j.at("isBroadcast").get<bool>()
        );
    }

public:
    DHCPFilter(std::string n, bool e, std::string sp, std::string dp, std::string sm, std::string dm, int t, int c, int pr, uint16_t ps, bool b): Filter(n, e, sp, dp, sm, dm), dhcpType(t), dhcpCode(c), packetRate(pr), payloadSize(ps), isBroadcast(b) {}

    // Load filter from JSON
    static DHCPFilter Load(DHCPFilter& filter) {
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

    // SETTERS and GETTERS
    void SetDHCPType(int type) { dhcpType = type; }
    int GetDHCPType() const { return dhcpType; }

    void SetDHCPCode(int code) { dhcpCode = code; }
    int GetDHCPCode() const { return dhcpCode; }

    void SetPacketRate(int rate) { packetRate = rate; }
    int GetPacketRate() const { return packetRate; }

    void SetPayloadSize(uint16_t size) { payloadSize = size; }
    uint16_t GetPayloadSize() const { return payloadSize; }

    void SetBroadcast(bool broadcast) { isBroadcast = broadcast; }
    bool GetBroadcast() const { return isBroadcast; }
};