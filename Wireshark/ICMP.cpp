#include "Filter.h"


class ICMPFilter : public Filter {
private:

    int packetRate;  // maximum allowed ping/packets requests per second
    uint16_t payloadSize; //size of the payload
    int icmpType;  // ICMP message type
    int icmpCode;  // ICMP message code
    bool isBroadcast; // if destination is a boradcast address

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
            j.at("isBroadcast").get<bool>(),
            j.at("payloadSize").get<uint16_t>()
        );
    }

public:
    // Constructor
    ICMPFilter(std::string n, bool e, std::string sp, std::string dp, std::string sm, std::string dm, int t, int c, int pr, uint16_t ps, bool b) : Filter(n, e, sp, dp, sm, dm), icmpType(t), icmpCode(c), packetRate(pr), payloadSize(ps), isBroadcast(b) {}

    // Load filter from json
    static ICMPFilter Load(ICMPFilter& filter) {
        std::ifstream file(filter.GetName() + ".json");
        if (file.is_open()) {
            json j;
            file >> j;
            file.close();
            std::cout << "Loaded: " << filter.GetName() + ".json" << std::endl;
            return DeConvert(j);
        }
        else {
            std::cerr << "Error: Unable to open file for loading." << std::endl;
        }
    }

    //SETTER and GETTERS
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