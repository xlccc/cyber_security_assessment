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
#include "../Event.h"
#include <cmath> // 添加这个标准库头文件
#include"database/poc.h"
#include"log/log.h"
using namespace std;
class DatabaseHandler {
public:
    DatabaseHandler(){}

	void executeInsert(const ScanHostResult& scanHostResult, ConnectionPool& pool); // 执行插入操作的方法,专门插入scan_host_result表，在getNmap中
    void executeUpdateOrInsert(const ScanHostResult  &scanHostResult, ConnectionPool& pool);
    //void processVulns(const ScanHostResult& hostResult, ConnectionPool& pool);
    //void processHostVulns(const ScanHostResult& hostResult, const int shr_id, ConnectionPool& pool);
    void processPortVulns(const ScanHostResult& hostResult, const int shr_id, ConnectionPool& pool);
    void alterVulnsAfterPocSearch(ConnectionPool& pool, const Vuln& vuln); //pocsearch中找到的脚本名称和漏洞名称补充到数据库中
    void alterHostVulnResultAfterPocVerify(ConnectionPool& pool, const Vuln& vuln, std::string ip);//更新操作类型的漏洞是否存在
    void alterPortVulnResultAfterPocVerify(ConnectionPool& pool, const Vuln& vuln, std::string ip, std::string portId);//更新端口的漏洞是否存在
    void alterVulnAfterPocTask(ConnectionPool& pool, const POCTask& task);

    //获得资产信息
    std::vector<IpVulnerabilities> getVulnerabilities(ConnectionPool& pool, std::vector<std::string> alive_hosts);

    //目标ip下的所有cpe, 用于增量扫描
    void processHostCpe(const ScanHostResult& hostResult, const int shr_id, ConnectionPool& pool);
    //插入漏洞数据到port_vuln_result 表
    void insertPortVulnResult(const std::vector<Vuln>& vulns, const int shr_id, const std::string port, ConnectionPool& pool);
    //提取 ScanHostResult 中的所有 CPE
    std::set<std::string> extractAllCPEs(const ScanHostResult& hostResult);
    //将提取出的所有 CPE 插入到 host_cpe 表
    void insertHostCPEs(int shr_id, const std::set<std::string>& cpes, ConnectionPool& pool);
    
    //将主机发现的存活主机存到alive_hosts表中
    void insertAliveHosts(const std::vector<std::string>& aliveHosts, ConnectionPool& pool);
	//将主机发现的存活主机存到scan_host_result表中
    void insertAliveHosts2scanHostResult(const std::vector<std::string>& aliveHosts, ConnectionPool& pool);
    //读取scan_host_result表。未到达过期时间的作为存活主机返回
    void readAliveHosts(std::vector<std::string>& aliveHosts, ConnectionPool& pool);
	//将存活的主机改为不存活
	void updateAliveHosts(std::string aliveHost, ConnectionPool& pool);

    void processVulns(const ScanHostResult& hostResult, ConnectionPool& pool);
    int getCpeId(int shr_id, const std::string& cpe, ConnectionPool& pool);
    void insertVulns(const std::vector<Vuln>& vulns, ConnectionPool& pool, int cpe_id = 0);

    // 根据漏洞ID获取关联的CPE ID
    int getCpeIdFromVuln(int vuln_id, ConnectionPool& pool);

    // 根据漏洞ID字符串获取数据库中的记录ID
    int getVulnIdByVulnId(const std::string& vuln_id_str, ConnectionPool& pool);

    // 插入单条host_vuln_result记录
    void insertHostVulnResult(const Vuln& vuln, int shr_id, int vuln_id, int cpe_id, ConnectionPool& pool);

    std::vector<PortInfo> getAllPortInfoByIp(const std::string &ip, ConnectionPool& pool);
    // 处理主机漏洞
    void processHostVulns(const ScanHostResult& hostResult, const int shr_id, ConnectionPool& pool);
    ScanHostResult getScanHostResult(const std::string& ip, ConnectionPool& pool);

    // 获取指定IP的完整资产信息
    AssetInfo getCompleteAssetInfo(const std::string& ip, ConnectionPool& pool);

    // 获取所有存活主机的完整资产信息
    std::vector<AssetInfo> getAllAssetsInfo(ConnectionPool& pool);

    //获取特定主机ip的所有service_name信息
	std::vector<std::string> getServiceNameByIp(const std::string& ip, ConnectionPool& pool);

	std::string saveWeakPasswordResult(const std::string& ip, int port, const std::string& service, const std::string& login, const std::string& password, ConnectionPool& pool);
    // 在DatabaseHandler类的公共成员函数中添加这个声明
    void saveSecurityCheckResult(const std::string& ip, const event& checkEvent, ConnectionPool& pool);

    //
    // 根据IP地址获取安全检查结果
    std::vector<event> getSecurityCheckResults(const std::string& ip, ConnectionPool& pool);

    // 在DatabaseHandler类的public部分添加以下声明
    std::vector<event> getSecurityCheckResultsByIds(const std::string& ip, const std::vector<int>& ids, ConnectionPool& pool);
    // 根据IP获取未完成的基线检查项
    std::vector<event> getUncheckedBaselineItems(const std::string& ip, ConnectionPool& pool);
    // 辅助函数：获取指定IP已完成的检查项ID列表
    std::vector<int> getCheckedItemIds(const std::string& ip, ConnectionPool& pool);
    // 辅助函数：获取所有基线检查项ID列表
    std::vector<int> getAllBaselineItemIds(ConnectionPool& pool);

    // 根据IP获取未完成的Level3安全检查项
    std::vector<event> getUncheckedLevel3Items(const std::string& ip, ConnectionPool& pool);
    // 辅助函数：获取指定IP已完成的Level3检查项ID列表
    std::vector<int> getCheckedLevel3ItemIds(const std::string& ip, ConnectionPool& pool);
    // 辅助函数：获取所有Level3检查项ID列表
    std::vector<int> getAllLevel3ItemIds(ConnectionPool& pool);
    //根据ip地址以及ids获取安全检查结果
    // 计算基线检测摘要
    BaselineCheckSummary calculateBaselineSummary(const std::vector<event>& check_results, int count);

    // 在DatabaseHandler类中添加
    void insertServerInfo(const ServerInfo& info, const std::string& ip, ConnectionPool& pool);

    ServerInfo getServerInfoByIp(const std::string& ip, ConnectionPool& pool);

    void saveLevel3SecurityCheckResult(const std::string& ip, const event& checkEvent, ConnectionPool& pool);
    void updateLevel3SecurityCheckResult(const std::string& ip, ConnectionPool& pool, std::vector<scoreMeasure>vec_score);
    std::vector<event> getLevel3SecurityCheckResults(const std::string& ip, ConnectionPool& pool);

    // 在DatabaseHandler类的public部分添加以下声明
    std::vector<event> getLevel3SecurityCheckResultsByIds(const std::string& ip, const std::vector<int>& ids, ConnectionPool& pool);

    //获取所有支持的漏洞类型
    std::vector<std::string> getAllVulnTypes(ConnectionPool& pool);

    // 添加/删除漏洞类型（统一入口）
    bool editVulnType(const std::string& type, const std::string& action, ConnectionPool& pool);

    // ------  POC表 相关的操作 --------
    //插入POC
    bool insertData(const POC& poc, ConnectionPool& pool);
    //删除POC
    bool deleteDataById(int id, ConnectionPool& pool);
    //更新POC
    bool updateDataById(int id, const POC& poc, ConnectionPool& pool);
    // 根据关键字搜索数据
    std::vector<POC> searchData(const std::string& keyword, ConnectionPool& pool);

    //根据CVE搜索对应POC
    std::vector<POC> searchDataByCVE(const std::string& vuln_id, ConnectionPool& pool);
    ////按id搜索POC数据，若没有，返回无对应POC
    std::vector<POC> searchDataByIds(const std::vector<int>& ids, ConnectionPool& pool);

    //搜索是否存在CVE编号的记录
    bool isExistCVE(const std::string& vuln_id, ConnectionPool& pool);

    //依据id搜索POC名称，用于删除对应POC
    std::string searchPOCById(const int& id, ConnectionPool& pool);
    //依据vuln_id搜索POC名称，用于删除对应POC
    std::string searchPOCById(const std::string& vuln_id, ConnectionPool& pool);

    //依据id搜索POC数据
    bool searchDataById(const int& id, POC& poc, ConnectionPool& pool);

    //获取所有数据
    std::vector<POC> getAllData(ConnectionPool& pool);

    // (新增）获取有效POC，即搜索 Script 字段不为空的记录
    std::vector<POC> getVaildPOCData(ConnectionPool& pool);
    //更新基线检测结果
    void updateBaseLineSecurityCheckResult(const std::string& ip, ConnectionPool& pool, std::vector<scoreMeasure>vec_score);

    // ------  POC表 相关的操作 --------

    //获取所有资产信息（包括不存活的）
    std::vector<AssetInfo> getAllAssetsFullInfo(ConnectionPool& pool);

    // ------  资产组 相关的操作 --------
    
    //判断资产组是否存在
    bool isAssetGroupExists(const std::string& group_name, ConnectionPool& pool);
    //创建资产组
    int createAssetGroup(const std::string& group_name, const std::string& description, ConnectionPool& pool);
    //获取资产组列表
    std::vector<std::pair<int, std::string>> getAllAssetGroups(ConnectionPool& pool);
    //归入当前组或移出资产
    bool updateAssetGroup(const std::string& ip, int group_id, bool is_null, ConnectionPool& pool);
    //资产组改名
    bool renameAssetGroup(int group_id, const std::string& new_name, ConnectionPool& pool);
    //删除资产组（支持是否删除组内资产）
    bool deleteAssetGroup(int group_id, bool deleteAssets, ConnectionPool& pool);


    // ------  资产组 相关的操作 --------
    //更新基线检测更新时间
    void updateBaselineCheckTime(const std::string& ip, ConnectionPool& pool);
    //更新等保检测更新时间
    void updateLevel3CheckTime(const std::string& ip, ConnectionPool& pool);
    //获取基线检测更新时间
    std::string getBaselineCheckTime(const std::string& ip, ConnectionPool& pool);
    // 根据IP获取三级等保检测时间
    std::string getLevel3CheckTime(const std::string& ip, ConnectionPool& pool);
};

#endif // DATABASEHANDLER_H