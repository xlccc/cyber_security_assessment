// DatabaseHandler.h
#ifndef DATABASEHANDLER_H
#define DATABASEHANDLER_H
#include <mysqlx/xdevapi.h>
#include <vector>
#include <string>
#include<set>
#include <iostream>
#include"mysql_connection_pool.h"
#include "scan_struct.h"
using namespace std;
class DatabaseHandler {
public:
    DatabaseHandler(){}

    void executeInsert(const std::string& sql, ConnectionPool& pool); // 执行插入操作的方法
    void executeUpdateOrInsert(const ScanHostResult  &scanHostResult, ConnectionPool& pool);
    void processVulns(const ScanHostResult& hostResult, ConnectionPool& pool);
    void processHostVulns(const ScanHostResult& hostResult, const int shr_id, ConnectionPool& pool);
    void processPortVulns(const ScanHostResult& hostResult, const int shr_id, ConnectionPool& pool);
    void alterVulnsAfterPocSearch(ConnectionPool& pool, const Vuln& vuln); //pocsearch中找到的脚本名称和漏洞名称补充到数据库中
    void alterHostVulnResultAfterPocVerify(ConnectionPool& pool, const Vuln& vuln, std::string ip);//更新操作类型的漏洞是否存在
    void alterPortVulnResultAfterPocVerify(ConnectionPool& pool, const Vuln& vuln, std::string ip, std::string portId);//更新端口的漏洞是否存在
    void alterVulnAfterPocTask(ConnectionPool& pool, const POCTask& task);
    std::vector<IpVulnerabilities> getVulnerabilities(ConnectionPool& pool);
    //目标ip下的所有cpe, 用于增量扫描
    void processHostCpe(const ScanHostResult& hostResult, const int shr_id, ConnectionPool& pool);
    // 插入漏洞数据到 vuln 表
    void insertVulns(const std::vector<Vuln>& vulns, ConnectionPool& pool);
    // 插入漏洞数据到host_vuln_result表
    void insertHostVulnResult(const std::vector<Vuln>& vulns, const int shr_id, ConnectionPool& pool);
    //插入漏洞数据到port_vuln_result 表
    void insertPortVulnResult(const std::vector<Vuln>& vulns, const int shr_id, const std::string port, ConnectionPool& pool);
    //提取 ScanHostResult 中的所有 CPE
    std::set<std::string> extractAllCPEs(const ScanHostResult& hostResult);
    //将提取出的所有 CPE 插入到 host_cpe 表
    void insertHostCPEs(int shr_id, const std::set<std::string>& cpes, ConnectionPool& pool);
    
};

#endif // DATABASEHANDLER_H