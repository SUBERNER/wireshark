#include "Filter.h"

class DNSFilter : public Filter {
private:
    int queryRate;      // Maximum allowed DNS queries per second
    std::string domain; // Domain name filter (e.g., block certain domains)
    int dnsType;        // DNS query type (A, AAAA, MX, etc.)
    bool isRecursive;   // Whether the DNS request is recursive

    // Override Convert method for serialization
    json Convert() const override {
        json base = Filter::Convert();
        base["dnsType"] = dnsType;
        base["queryRate"] = queryRate;
        base["domain"] = domain;
        base["isRecursive"] = isRecursive;
        return base;
    }

    // Override DeConvert method for deserialization
    static DNSFilter DeConvert(const json& j) {
        return DNSFilter(
            j.at("name").get<std::string>(),
            j.at("enabled").get<bool>(),
            j.at("sourceIP").get<std::string>(),
            j.at("destinationIP").get<std::string>(),
            j.at("sourceMAC").get<std::string>(),
            j.at("destinationMAC").get<std::string>(),
            j.at("dnsType").get<int>(),
            j.at("queryRate").get<int>(),
            j.at("domain").get<std::string>(),
            j.at("isRecursive").get<bool>()
        );
    }

public:
    // Constructor
    DNSFilter(std::string n, bool e, std::string sp, std::string dp, std::string sm, std::string dm, int type, int rate, std::string d, bool recursive) 
        : Filter(n, e, sp, dp, sm, dm), dnsType(type), queryRate(rate), domain(d), isRecursive(recursive) {}

    // Load filter from JSON
    static DNSFilter Load(DNSFilter& filter) {
        std::ifstream file(filter.GetName() + ".json");
        if (file.is_open()) {
            json j;
            file >> j;
            file.close();
            std::cout << "Loaded: " << filter.GetName() + ".json" << std::endl;
            return DeConvert(j);
        } else {
            std::cerr << "Error: Unable to open file for loading." << std::endl;
        }
    }

    // GETTERS & SETTERS
    void SetDNSType(int type) { dnsType = type; }
    int GetDNSType() const { return dnsType; }

    void SetQueryRate(int rate) { queryRate = rate; }
    int GetQueryRate() const { return queryRate; }

    void SetDomain(std::string d) { domain = d; }
    std::string GetDomain() const { return domain; }

    void SetRecursive(bool r) { isRecursive = r; }
    bool GetRecursive() const { return isRecursive; }
};