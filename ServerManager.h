#ifndef SERVERMANAGER_H
#define SERVERMANAGER_H
#define _TURN_OFF_PLATFORM_STRING  // 禁用cpprest的U宏
#include <cpprest/http_listener.h>
#include <cpprest/json.h>
#include <cpprest/uri.h>
#include <cpprest/uri_builder.h>
#include <cpprest/filestream.h>
#include <cpprest/containerstream.h>
#include <cpprest/producerconsumerstream.h>
#include <map>
#include <vector>
#include <string>
#include "db_config.h"
#include "poc.h"
#include <libssh/libssh.h>
#include <fstream>
#include <vector>
#include <sstream>
#include <iostream>
#include <cpprest/http_client.h>
#include <cpprest/filestream.h>
#include "Login.h"
#include "Command_Excute.h"
#include "Padding2.h"
#include "scan/portScan.h"
#include "utils_scan.h"
#include "convert_string_t.h"
#include "poc_check.h"
#include <sys/stat.h>
#include"DatabaseHandler.h"
#include"multipart_form_data.h"
#include"utils.h"
#include"utils/config.h"
#include"mysql_connection_pool.h"
#include"hostDiscovery.h"
#include<regex>
#include "run/mysql_scan.h"
#include <spdlog/spdlog.h>
#include "ssh_win.h"
#include "windowsbaseline.h"
#include "execute_win.h"

#include"SSHConnectionPool.h"
#include"redis_scan.h"
#include"pgsql_scan.h"
#include"DatabaseWrapper.h"
#include <System_UserManage/EmailService.h>
#include <System_UserManage/SecurityUtils.h>
#include "../utils/jwtUtil/token_generator.h"


using namespace web;
using namespace web::http;
using namespace web::http::experimental::listener;
using namespace utility;
using namespace web::http::client;
using namespace concurrency::streams;
using namespace std;

class ServerManager {
public:
    ServerManager();
    void open_listener();
    void start();
    void stop();
    std::string GetDb(http_request request);
   /* std::string GetRole(http_request request);*/
    static ServerManager& instance() {
        static ServerManager instance; // 在第一次调用时创建
        return instance;
    }
    //创建管理员数据库admin_db
    bool InitializeAdminDatabase();
private:

    // 创建用于连接本地服务器的配置
    DatabaseConfig localConfig;
    SmtpConfig smtpConfig_;
    // ´æ´¢portIdºÍservice_nameµÄmap
    std::map<std::string, std::string> port_services;
    //缓存 ip 和上次检测的临时ids的映射
    std::map<std::string, std::vector<int>> lastCheckedIds;

    std::map<std::string, std::vector<int>> lastLevel3CheckedIds;
    std::unique_ptr<http_listener> listener;
    void handle_options(http_request request);
    void handle_request(http_request request);

  

    void handle_post_login(http_request request);
    void handle_get_cve_scan(http_request request);

  
    //新版：从数据库中获取扫描结果
    void handle_get_ScanHostResult(http_request request);

    //void handle_get_all_data(http_request request);
    void handle_get_vaild_poc_data(http_request request);   

    void handle_get_poc_table(http_request request);
    void handle_get_with_poc_condition(http_request request);
    void handle_get_with_tran_poc_condition(http_request request);
    void handle_get_without_poc_condition(http_request request);


    void handle_search_data(http_request request);
    void handle_post_insert_data(http_request request);
    void  handle_put_update_data_by_id(http_request request);
    void handle_delete_data_by_id(http_request request);
    void handle_post_get_Nmap(http_request request);
    void handle_post_hydra(http_request request);
    void handle_post_testWeak(http_request request);
    void handle_post_classify_protect(http_request request);
    void handle_get_classify_protect(http_request request);
    json::value Vuln_to_json(const Vuln& vuln);
    json::value ScanResult_to_json(const ScanResult& scan_result);
    json::value ScanHostResult_to_json(const ScanHostResult& scan_host_result);
    //将资产查询结果转成Json
    json::value convertToJson(const std::vector<IpVulnerabilities>& vulns);
    //POC列表转json（新增）
    json::value poc_list_to_json(const std::vector<POC>& poc_list);


   

    //检验文件是否存在，并获取文件名
    bool check_and_get_filename(const std::string& body, const std::string& content_type, std::string& filename, std::string& data, std::string& error_message);
    // 从内存中处理POC文件上传
    void upload_file(const std::string& filename, const std::string& data);
    // 将请求体保存到临时文件
    void save_request_to_temp_file(http_request request);
    //查看POC内容
    void handle_get_poc_content(http_request request);

    //POC搜索
    void handle_post_poc_search(http_request request);

    //调试
    void handle_post_poc_verify(http_request request);
    //POC验证
    void handle_post_poc_verify_new(http_request request);
    //设置需要执行POC验证的CVE条目
    void setIfCheckByIds(ScanHostResult& hostResult, const std::vector<std::string>& cve_ids, bool value);
    //执行并回显poc代码
    void handle_post_poc_excute(http_request request);
    //根据CVE编号添加POC代码、或更新已有的POC代码
    void update_poc_by_cve(http_request request);
    // 记录 /poc_callback 路径的请求（待修改）
    void log_poc_callback(const http_request& request);

	void handle_get_alive_hosts(http_request request);

    //插件化扫描
    void handle_post_poc_scan(http_request request);
    //合并两种漏洞扫描方法的结果
    void handle_merge_vuln_results(http_request request);
    //自动选择POC
    void handle_auto_select_poc(http_request request);

    //首页获取数据库中的资产数据
    void handle_get_all_assets_vuln_data(http_request request);
    
    //数据库弱口令检测扫描
    void handle_post_mysql_scan(http_request request);
    //scan_struct的相关结构体与数据库的交互

    //主机发现
    void handle_host_discovery(http_request request);

    // 校验输入是否为有效的IP地址或CIDR网段
    bool isValidIPOrCIDR(const std::string& input);
    // 校验IP地址格式
    bool isValidIP(const std::string& ip);
    // 校验CIDR网段格式
    bool isValidCIDR(const std::string& network);
    //返回主机发现的响应
    /*void sendHostDiscoveryResponse(http_request& request, const std::vector<std::string>& aliveHosts);*/
    //返回主机发现的响应
    void sendHostDiscoveryResponse(http_request& request, const std::vector<std::string>& aliveHosts, DatabaseHandler& dbHandler, ConnectionPool& pool);

	//探测主机是否存活
	bool pingIsAlive(const std::string& network);
    void redis_get_scan(http_request request);

	void handle_get_test(http_request request);
    // 辅助函数：打印扫描结果详情
    void printScanHostResult(const ScanHostResult& result);

    // 将资产信息转换为JSON格式
    web::json::value convertAssetInfoToJson(const AssetInfo& assetInfo);
    // 将ports信息转换为JSON格式
    web::json::value convertPortsToJson(const std::vector<PortInfo>& ports);
    // 处理获取所有资产信息的HTTP请求
    void handle_get_all_assets_info(http_request request);

    // 处理获取单个IP资产信息的HTTP请求
    void handle_get_asset_info(http_request request);

    //判断特定ip的服务是否存在
    bool isServiceExistByIp(const std::string& ip, const std::string& service_name, ConnectionPool& pool);

    // 在 ServerManager.h 中添加新的处理函数
    void handle_get_security_check_by_ip(http_request request);

    void handle_get_userInfo(http_request request);
    void handle_get_tmpUserInfo(http_request request);

    void handle_post_level3(http_request request);
    void handle_get_level3UserInfo(http_request request);
    void handle_get_level3TmpUserInfo(http_request request);
    void handle_get_weak_password_by_ip(http_request request);
    void handle_get_all_weak_passwords(http_request request);

    //获取所有支持的漏洞类型
    void handle_get_vuln_types(http_request request);

    //增删支持的漏洞类型
    void handle_edit_vuln_type(http_request request);
    //等保：从历史数据中取出来评估
    void handle_get_level3Result(http_request request);

    void handle_post_updateLevel3_protect(http_request request);
    //基线：从历史数据中取出来评估
    void handle_get_baseLineResult(http_request  request);
    void handle_post_updateBaseLine_protect(http_request request);

    //获取所有资产信息（包括不存活的）
    void handle_get_all_assets_full_info(http_request request);

    //资产组相关接口
    void handle_post_create_asset_group(http_request request);
    //获取资产组列表
    void handle_get_asset_group_list(http_request request);
    //归入当前组或移出资产
    void handle_change_asset_group(http_request request);
    
    //重命名资产组
    void handle_asset_group_rename(http_request request);

    //删除资产组（支持是否删除组内资产）
    void handle_delete_asset_group(http_request request);

    //windows基线检测
    void handle_get_win_userinfo(http_request request);
    void handle_post_win_login(http_request request);
    void handle_get_baseline_scripts(http_request request);



    //-------------用户管理-----------

  //用户注册
    void handle_post_register(http_request request);
   //验证码验证处理（第二步）
    void handle_post_verify(http_request request);
    //用户登录
    void handle_post_userLogin(http_request request);
    //管理员对用户的增删改查
    void handle_post_create_user(http_request request);
    void handle_put_update_user(http_request request);
    void handle_delete_user(http_request request);
    void handle_recover_user(http_request request);
    void handle_get_user(http_request request);
    void handle_get_all_users(http_request request);

  

    ConnectionPool pool;
    DatabaseHandler dbHandler_;
    //旧版
    //DatabaseManager dbManager;
    DatabaseWrapper dbManager;
   
    std::vector<POC> poc_list;

    // Additional member variables
    std::string global_ip;
    std::string global_pd;
    std::string global_hostname; //win基线检测
    vector<scoreMeasure> vecScoreMeasure;


    //win基线检测
    ServerInfo_t info_new;
    vector<event_t>Event_win;
    map<int, event_t>allBaseline;


    //线程池
    std::shared_ptr<ThreadPool> globalThreadPool;
    //当前扫描结果
    vector<ScanHostResult> scan_host_result;
    //历史扫描结果
    HistoricalScanData historicalData;
};

#endif // SERVERMANAGER_H
