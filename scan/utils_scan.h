#pragma once
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


//解析nmap端口扫描结果的xml文件
std::vector<ScanHostResult> parseXmlFile(const std::string& xmlFilePath);


//运行python脚本
std::string runPythonScript(const std::string& scriptPath_extension, const std::string& url, const std::string& ip, int port);


std::string runPythonWithOutput(const std::string& scriptPath_extension, const std::string& url, const std::string& ip, int port);

std::string findScriptByCveId(std::vector<ScanHostResult>& scan_host_result, const std::string& cve_id);

std::string findPortIdByCveId(std::vector<ScanHostResult>& scan_host_result, const std::string& cve_id);

// 判断 CPE 是否一致，返回不一致的 CPE
std::vector<std::string> compareCPEs(const std::map<std::string, std::vector<CVE>>& newCPEs, const std::map<std::string, std::vector<CVE>>& oldCPEs);

// 比对并更新结果，根据端口信息和 CPE 信息来决定查询策略
void compareAndUpdateResults(const ScanHostResult& oldResult, ScanHostResult& newResult, int limit = 0);

// CVE 查询函数
void fetch_and_padding_cves(std::map<std::string, std::vector<CVE>>& cpes, const std::vector<std::string>& cpes_to_query, int limit = 20);