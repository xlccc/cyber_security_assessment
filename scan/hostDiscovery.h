#ifndef HOST_DISCOVERY_H
#define HOST_DISCOVERY_H

#include "threadPool.h"
#include"utils/config.h"   //�̸߳�������
#include <string>
#include <vector>
#include <mutex>
#include <iostream>
#include <regex>
#include"log/log.h"
#include"utils/CommonDefs.h"

//����������
class HostDiscovery {
public:
    // ���캯����������������
    HostDiscovery(const std::string& network);

    // ɨ�������д������������� IP �б�
    std::vector<std::string> scan();

private:
    std::string network;
    std::string subnet;
    ThreadPool threadPool;
    std::mutex resultMutex;

    //�ж��Ƿ�Ϊ����IP
    bool isValidIP(const std::string& ip);
    //�ж��Ƿ�Ϊ��Ч����
    bool isValidCIDR(const std::string& network);

    // �������λ�ȡ��������
    std::string getSubnet(const std::string& network);

    // �������ε���ʼ�ͽ��� IP ��ַ
    std::pair<unsigned int, unsigned int> calculateIPRange();

    //�ύping����
    std::future<void> submitPingTask(const std::string& ipAddress, std::vector<std::string>& aliveHosts);

    // �� IP ��ַ�ַ���ת��Ϊ����
    unsigned int ipToInt(const std::string& ip);

    // ������ת��Ϊ IP ��ַ�ַ���
    std::string ipToString(unsigned int ip);

    // ʹ��ϵͳ�� ping �����������Ƿ���
    bool ping(const std::string& ipAddress);

};



#endif // HOST_DISCOVERY_H

