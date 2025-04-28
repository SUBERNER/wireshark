#include "Filter.h"
#include <filesystem>
using namespace std;
namespace fs = std::filesystem;

class DNSFilter : public Filter {
private:
    int queryRate;       // DNS queries per second
    std::string domain;  // Domain name filter
    int dnsType;         // DNS query type
    bool isRecursive;    // Recursive query?

    // Override Convert for serialization
    json Convert() const override {
        json base = Filter::Convert();
        base["dnsType"] = dnsType;
        base["queryRate"] = queryRate;
        base["domain"] = domain;
        base["isRecursive"] = isRecursive;
        return base;
    }

    // Override DeConvert
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
    DNSFilter(std::string n, bool e, std::string sp, std::string dp, std::string sm, std::string dm, int type, int rate, std::string d, bool recursive): Filter(n, e, sp, dp, sm, dm), dnsType(type), queryRate(rate), domain(d), isRecursive(recursive) {}

    // load filter from JSON
    static DNSFilter Load(DNSFilter& filter) {
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