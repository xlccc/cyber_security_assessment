#pragma once
#define _TURN_OFF_PLATFORM_STRING  // 禁用cpprest的U宏
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include "rapidxml.hpp" // 使用 RapidXML 库进行 XML 解析
#include"scan_struct.h"
#include <Python.h>
#include"utils.h"
#include <cpprest/http_client.h>//用于处理 HTTP 请求的库。
#include <cpprest/json.h>//用于处理 JSON 数据的库。
#include <cpprest/uri_builder.h>//用于构建 URI 的库
#include <unordered_set>
#include"scan_struct.h"
#include"database/poc.h"
#include <future>
#include <thread>
#include <algorithm>
#include "utils/config.h"
#include"DatabaseHandler.h"
#include"mysql_connection_pool.h"
using namespace std;


//解析nmap端口扫描结果的xml文件
std::vector<ScanHostResult> parseXmlFile(const std::string& xmlFilePath);


//运行python脚本
std::string runPythonScript(const std::string& scriptPath_extension, const std::string& url, const std::string& ip, int port);


std::string runPythonWithOutput(const std::string& scriptPath_extension, const std::string& url, const std::string& ip, int port);

std::string findScriptByCveId(std::vector<ScanHostResult>& scan_host_result, const std::string& cve_id);

std::string findPortIdByCveId(std::vector<ScanHostResult>& scan_host_result, const std::string& cve_id);

// 判断 CPE 是否一致，返回不一致的 CPE
std::vector<std::string> compareCPEs(const std::map<std::string, std::vector<Vuln>>& newCPEs, const std::map<std::string, std::vector<Vuln>>& oldCPEs);

// 比对并更新结果，根据端口信息和 CPE 信息来决定查询策略
void compareAndUpdateResults(const ScanHostResult& oldResult, ScanHostResult& newResult, int limit = 0);

// CVE 查询函数
void fetch_and_padding_cves(std::map<std::string, std::vector<Vuln>>& cpes, const std::vector<std::string>& cpes_to_query, int limit = 20);

//创建POC任务
std::map<std::string, std::vector<POCTask>> create_poc_task(const std::vector<POC>& poc_list, const ScanHostResult& scan_host_result);

//创建POC任务
//POC扫描所有开放端口，不进行基础设施匹配的版本（使用两个参数）
std::map<std::string, std::vector<POCTask>> create_poc_task(const std::vector<POC>& poc_list, const ScanHostResult& scan_host_result, bool match_infra);

//执行POC任务
void execute_poc_tasks(std::map<std::string, std::vector<POCTask>>& poc_tasks_by_port, ScanHostResult& scan_host_result,ConnectionPool &pool, DatabaseHandler &dbHandler);

//合并 漏洞库匹配、插件化扫描两种方式的扫描结果
void merge_vuln_results(ScanHostResult& scan_host_result);
