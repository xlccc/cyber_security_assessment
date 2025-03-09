#include "hostDiscovery.h"
#include <sstream>
#include <cstdlib>
#include <stdexcept>
#include <unistd.h>

HostDiscovery::HostDiscovery(const std::string& network)
    :network(network), threadPool(threadCount) {

    //������Ϊ���Σ�����ȡ��������
    if (isValidCIDR(network)) {
        this->subnet = getSubnet(network);

        system_logger->info("Initialized HostDiscovery with network: {}", network);
    }
    else
        system_logger->info("Initialized HostDiscovery with targeted IP: {}", network);
}

bool HostDiscovery::isValidIP(const std::string& ip) {
    // �򵥵�IP��ʽУ��
    std::regex ipRegex(
        R"(^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)"
    );
    return std::regex_match(ip, ipRegex);
}

bool HostDiscovery::isValidCIDR(const std::string& network) {
    // У��CIDR��ʽ����������ַ����������
    std::regex cidrRegex(
        R"(^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/([12]?[0-9]|3[0-2])$)"
    );
    return std::regex_match(network, cidrRegex);
}
std::vector<std::string> HostDiscovery::scan() {
    std::vector<std::string> aliveHosts;
    std::vector<std::future<void>> futures;

    if (isValidIP(network)) {
        // ����IP���
        system_logger->info("Scanning single IP: {}", network);
        if (ping(network)) {
            aliveHosts.push_back(network);
        }
       
        return aliveHosts;
    }
    else if (isValidCIDR(network)) {
        try {
            std::pair<unsigned int, unsigned int> ipRange = calculateIPRange();
            unsigned int startIP = ipRange.first;
            unsigned int endIP = ipRange.second;
            system_logger->info("Calculating IP range from {} to {}", ipToString(startIP), ipToString(endIP));

            for (unsigned int ip = startIP; ip <= endIP; ++ip) {
                std::string ipAddress = ipToString(ip);
                futures.emplace_back(submitPingTask(ipAddress, aliveHosts));
            }

            for (auto& future : futures) {
                future.get();
            }
        }
        catch (const std::exception& e) {
            system_logger->error("Exception during scanning: {}", e.what());
        }
    }
    else {
        system_logger->error("Invalid Network/IP format: {}", network);
    }

    return aliveHosts;
}

std::string HostDiscovery::getSubnet(const std::string& network) {
    size_t slashPos = network.find('/');
    if (slashPos == std::string::npos) {
        throw std::invalid_argument("Invalid network format, missing subnet mask.");
    }
    return network.substr(slashPos + 1);
}

std::pair<unsigned int, unsigned int> HostDiscovery::calculateIPRange() {
    unsigned int startIP = ipToInt(network.substr(0, network.find('/')));
    int subnetMask = std::stoi(subnet);

    if (subnetMask < 16 || subnetMask > 32) {
        throw std::out_of_range("Subnet mask must be between 16 and 32.");
    }

    // �������������Ӧ�Ķ�����ֵ
    unsigned int subnetMaskBinary = (0xFFFFFFFF << (32 - subnetMask)) & 0xFFFFFFFF;

    // ���������ַ�͹㲥��ַ
    unsigned int networkAddress = startIP & subnetMaskBinary;
    unsigned int broadcastAddress = networkAddress | ~subnetMaskBinary;

    // �ų������ַ�͹㲥��ַ
    // �����ַ�� startIP���㲥��ַ�� endIP
    // ��������Ч��ַ��ΧӦ�ô� startIP + 1 �� endIP - 1
    unsigned int validStartIP = networkAddress + 1;
    unsigned int validEndIP = broadcastAddress - 1;


    return { validStartIP, validEndIP };
}

std::future<void> HostDiscovery::submitPingTask(const std::string& ipAddress, std::vector<std::string>& aliveHosts) {
    return threadPool.enqueue([this, &aliveHosts, ipAddress] {
        if (ping(ipAddress)) {
            std::lock_guard<std::mutex> lock(resultMutex);
            aliveHosts.push_back(ipAddress);
            user_logger->info("Host {} is alive.", ipAddress);
        }
        else {
            user_logger->warn("Host {} did not respond to ping.", ipAddress);
        }
        });
}

unsigned int HostDiscovery::ipToInt(const std::string& ip) {
    unsigned int result = 0;
    std::istringstream ss(ip);
    std::string byte;
    int shift = 24;

    while (getline(ss, byte, '.')) {
        try {
            int byteVal = std::stoi(byte);
            if (byteVal < 0 || byteVal > 255) {
                throw std::out_of_range("IP byte value out of range (0-255).");
            }
            result |= (byteVal << shift);
            shift -= 8;
        }
        catch (const std::invalid_argument& e) {
            system_logger->error("[ERROR] Invalid IP format: {}", e.what());
            throw;
        }
        catch (const std::out_of_range& e) {
            system_logger->error("[ERROR] {}", e.what());
            throw;
        }
    }

    return result;
}

std::string HostDiscovery::ipToString(unsigned int ip) {
    std::ostringstream ss;
    ss << ((ip >> 24) & 0xFF) << "."
        << ((ip >> 16) & 0xFF) << "."
        << ((ip >> 8) & 0xFF) << "."
        << (ip & 0xFF);
    return ss.str();
}

bool HostDiscovery::ping(const std::string& ipAddress) {
    std::string command = "ping -c 1 -W 1 " + ipAddress + " > /dev/null 2>&1";  // Linux ping ����
    int result = system(command.c_str());

    if (result == 0) {
        return true;
    }
    else {
        return false;  // ����û����Ӧ�������׳��쳣
    }
}
