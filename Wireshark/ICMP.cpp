#include "Filter.h"
#include <filesystem>
using namespace std;
namespace fs = std::filesystem;

class ICMPFilter : public Filter {
private:
    int packetRate;        // allowed ping requests per second
    uint16_t payloadSize;  // payload size
    int icmpType;          // ICMP type
    int icmpCode;          // ICMP code
    bool isBroadcast;      // destination is broadcast?

    // override Convert
    json Convert() const override {
        json base = Filter::Convert();
        base["icmpType"] = icmpType;
        base["icmpCode"] = icmpCode;
        base["packetRate"] = packetRate;
        base["payloadSize"] = payloadSize;
        base["isBroadcast"] = isBroadcast;
        return base;
    }

    // override DeConvert
    static ICMPFilter DeConvert(const json& j) {
        return ICMPFilter(
            j.at("name").get<std::string>(),
            j.at("enabled").get<bool>(),
            j.at("sourceIP").get<std::string>(),
            j.at("destinationIP").get<std::string>(),
            j.at("sourceMAC").get<std::string>(),
            j.at("destinationMAC").get<std::string>(),
            j.at("icmpType").get<int>(),
            j.at("icmpCode").get<int>(),
            j.at("packetRate").get<int>(),
            j.at("payloadSize").get<uint16_t>(),
            j.at("isBroadcast").get<bool>()
        );
    }

public:
    ICMPFilter(std::string n, bool e, std::string sp, std::string dp, std::string sm, std::string dm, int t, int c, int pr, uint16_t ps, bool b) : Filter(n, e, sp, dp, sm, dm), icmpType(t), icmpCode(c), packetRate(pr), payloadSize(ps), isBroadcast(b) {}

    // load filter from JSON
    static ICMPFilter Load(ICMPFilter& filter) {
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
    void SetICMPType(int type) { icmpType = type; }
    int GetICMPType() const { return icmpType; }

    void SetICMPCode(int code) { icmpCode = code; }
    int GetICMPCode() const { return icmpCode; }

    void SetPacketRate(int rate) { packetRate = rate; }
    int GetPacketRate() const { return packetRate; }

    void SetPayloadSize(uint16_t size) { payloadSize = size; }
    uint16_t GetPayloadSize() const { return payloadSize; }

    void SetBroadcast(bool broadcast) { isBroadcast = broadcast; }
    bool GetBroadcast() const { return isBroadcast; }
};