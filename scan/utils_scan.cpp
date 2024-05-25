#include "utils_scan.h"
#include <rapidxml.hpp>
#include <rapidxml_utils.hpp>
#include <stdexcept>

// 解析XML文件以获取扫描结果
std::vector<ScanHostResult> parseXmlFile(const std::string& xmlFilePath) {
    std::vector<ScanHostResult> scanHostResults;

    // 尝试打开XML文件
    std::ifstream file(xmlFilePath);
    if (!file) {
        std::cerr << "Failed to open XML file: " << xmlFilePath << std::endl;
        return scanHostResults; // 返回空的结果
    }

    // 将XML文件内容读取到字符串中
    std::string xmlContent((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    // 创建RapidXML解析器
    rapidxml::xml_document<> xmlDoc;
    try {
        xmlDoc.parse<0>(&xmlContent[0]);
    }
    catch (rapidxml::parse_error& e) {
        std::cerr << "Failed to parse XML file: " << e.what() << std::endl;
        return scanHostResults; // 返回空的结果
    }

    // 获取根节点 "nmaprun"
    rapidxml::xml_node<>* rootNode = xmlDoc.first_node("nmaprun");
    if (!rootNode) {
        std::cerr << "No 'nmaprun' node found in XML file." << std::endl;
        return scanHostResults; // 返回空的结果
    }

    // 遍历每个主机节点 "host"
    for (rapidxml::xml_node<>* hostNode = rootNode->first_node("host"); hostNode; hostNode = hostNode->next_sibling("host")) {
        ScanHostResult hostResult;

        // 提取IP地址
        rapidxml::xml_node<>* addressNode = hostNode->first_node("address");
        if (addressNode) {
            rapidxml::xml_attribute<>* ipAttr = addressNode->first_attribute("addr");
            if (ipAttr) {
                hostResult.ip = ipAttr->value();
            }
        }

        // 提取操作系统的CPE信息，并初始化为空的CVE数组
        rapidxml::xml_node<>* osNode = hostNode->first_node("os");
        if (osNode) {
            for (rapidxml::xml_node<>* osMatchNode = osNode->first_node("osmatch"); osMatchNode; osMatchNode = osMatchNode->next_sibling("osmatch")) {
                for (rapidxml::xml_node<>* osClassNode = osMatchNode->first_node("osclass"); osClassNode; osClassNode = osClassNode->next_sibling("osclass")) {
                    for (rapidxml::xml_node<>* cpeNode = osClassNode->first_node("cpe"); cpeNode; cpeNode = cpeNode->next_sibling("cpe")) {
                        std::string cpe = cpeNode->value();
                        hostResult.cpes[cpe] = std::vector<CVE>(); // 初始化为空的CVE数组
                    }
                }
            }
        }

        // 提取端口扫描信息
        rapidxml::xml_node<>* portsNode = hostNode->first_node("ports");
        if (portsNode) {
            // 遍历每个端口节点 "port"
            for (rapidxml::xml_node<>* portNode = portsNode->first_node("port"); portNode; portNode = portNode->next_sibling("port")) {
                ScanResult scanResult;

                // 提取端口号
                rapidxml::xml_attribute<>* portIdAttr = portNode->first_attribute("portid");
                if (portIdAttr) {
                    scanResult.portId = portIdAttr->value();
                }

                // 提取协议类型
                rapidxml::xml_attribute<>* protocolAttr = portNode->first_attribute("protocol");
                if (protocolAttr) {
                    scanResult.protocol = protocolAttr->value();
                }

                // 提取端口状态
                rapidxml::xml_node<>* stateNode = portNode->first_node("state");
                if (stateNode) {
                    rapidxml::xml_attribute<>* stateAttr = stateNode->first_attribute("state");
                    if (stateAttr) {
                        scanResult.status = stateAttr->value();
                    }
                }

                // 提取服务信息
                rapidxml::xml_node<>* serviceNode = portNode->first_node("service");
                if (serviceNode) {
                    // 提取服务名称
                    rapidxml::xml_attribute<>* nameAttr = serviceNode->first_attribute("name");
                    if (nameAttr) {
                        scanResult.service_name = nameAttr->value();
                    }
                    // 提取服务版本
                    rapidxml::xml_attribute<>* versionAttr = serviceNode->first_attribute("version");
                    if (versionAttr) {
                        scanResult.version = versionAttr->value();
                    }

                    // 提取CPE信息，并初始化为空的CVE数组
                    for (rapidxml::xml_node<>* cpeNode = serviceNode->first_node("cpe"); cpeNode; cpeNode = cpeNode->next_sibling("cpe")) {
                        std::string cpe = cpeNode->value();
                        scanResult.cpes[cpe] = std::vector<CVE>(); // 初始化为空的CVE数组
                    }
                }

                // 将端口扫描结果添加到主机结果的端口列表中
                hostResult.ports.push_back(scanResult);
            }
        }

        // 将主机扫描结果添加到结果列表中
        scanHostResults.push_back(hostResult);
    }

    return scanHostResults; // 返回解析结果
}
