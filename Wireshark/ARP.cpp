#include "Filter.h"

class ARPFilter : public Filter {

private:
	uint16_t hardwareType; // Hardware type
	uint16_t protocolType; // Protocol type
	uint8_t hardwareSize; // Hardware size
	uint8_t protocolSize; // Protocol size
	uint16_t opcode; // Opcode

    json Convert() const override {
        json base = Filter::Convert();
        base["hardwareType"] = hardwareType;
        base["protocolSize"] = protocolType;
        base["hardwareSize"] = hardwareSize;
        base["protocolSize"] = protocolSize;
        base["opcode"] = opcode;
        return base;
    }
    
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
	ARPFilter(std::string n, bool e, std::string sp, std::string dp, std::string sm, std::string dm, uint16_t ht, uint16_t pt, uint8_t hs, uint8_t ps, uint16_t op) : Filter(n, e, sp, dp, sm, dm), hardwareType(ht), protocolType(pt), hardwareSize(hs), protocolSize(ps), opcode(op) {}

	static ARPFilter Load(ARPFilter& filter) {
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
	uint16_t GetHardwareType() const { return hardwareType; }
	uint16_t setHardwareType(uint16_t ht) { hardwareType = ht; }

	uint16_t GetProtocolType() const { return protocolType; }
	uint16_t setProtocolType(uint16_t pt) { protocolType = pt; }

	uint8_t GetHardwareSize() const { return hardwareSize; }
	uint8_t setHardwareSize(uint8_t hs) { hardwareSize = hs; }

	uint8_t GetProtocolSize() const { return protocolSize; }
	uint8_t setProtocolSize(uint8_t ps) { protocolSize = ps; }

	uint16_t GetOpcode() const { return opcode; }
	uint16_t setOpcode(uint16_t op) { opcode = op; }


};