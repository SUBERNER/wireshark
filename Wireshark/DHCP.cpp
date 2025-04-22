#include "Filter.h"


class DHCPFilter : public Filter {
private:

    int packetRate;  // maximum allowed ping/packets requests per second
    uint16_t payloadSize; //size of the payload
    int dhcpType;  // DHCP message type
    int dhcpCode;  // DHCP message code
    bool isBroadcast; // if destination is a boradcast address

    // override Convert
    json Convert() const override {
        json base = Filter::Convert();
        base["dhcpType"] = dhcpType;
        base["dhcpCode"] = dhcpCode;
        base["packetRate"] = packetRate;
        base["payloadSize"] = payloadSize;
        base["isBroadcast"] = isBroadcast;
        return base;
    }

    // override DeConvert
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
            j.at("isBroadcast").get<bool>(),
            j.at("payloadSize").get<uint16_t>()
        );
    }

public:
    // Constructor
    DHCPFilter(std::string n, bool e, std::string sp, std::string dp, std::string sm, std::string dm, int t, int c, int pr, uint16_t ps, bool b) : Filter(n, e, sp, dp, sm, dm), dhcpType(t), dhcpCode(c), packetRate(pr), payloadSize(ps), isBroadcast(b) {}

    // Load filter from json
    static DHCPFilter Load(DHCPFilter& filter) {
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