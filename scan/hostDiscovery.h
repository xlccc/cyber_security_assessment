#ifndef HOST_DISCOVERY_H
#define HOST_DISCOVERY_H

#include "threadPool.h"
#include"utils/config.h"   //线程个数配置
#include <string>
#include <vector>
#include <mutex>
#include <iostream>
#include <regex>
#include"log/log.h"
#include"utils/CommonDefs.h"

//主机发现类
class HostDiscovery {
public:
    // 构造函数，接受网络网段
    HostDiscovery(const std::string& network);

    // 扫描网络中存活的主机，返回 IP 列表
    std::vector<std::string> scan();

private:
    std::string network;
    std::string subnet;
    ThreadPool threadPool;
    std::mutex resultMutex;

    //判断是否为单个IP
    bool isValidIP(const std::string& ip);
    //判断是否为有效网段
    bool isValidCIDR(const std::string& network);

    // 根据网段获取子网掩码
    std::string getSubnet(const std::string& network);

    // 计算网段的起始和结束 IP 地址
    std::pair<unsigned int, unsigned int> calculateIPRange();

    //提交ping任务，
    std::future<void> submitPingTask(const std::string& ipAddress, std::vector<std::string>& aliveHosts);

    // 将 IP 地址字符串转换为整数
    unsigned int ipToInt(const std::string& ip);

    // 将整数转换为 IP 地址字符串
    std::string ipToString(unsigned int ip);

    // 使用系统的 ping 命令检测主机是否存活
    bool ping(const std::string& ipAddress);

};



#endif // HOST_DISCOVERY_H

