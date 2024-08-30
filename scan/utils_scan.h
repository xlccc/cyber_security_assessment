#pragma once
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include "rapidxml.hpp" // 使用 RapidXML 库进行 XML 解析
#include"scan_struct.h"
#include <Python.h>
#include"utils.h"


//解析nmap端口扫描结果的xml文件
std::vector<ScanHostResult> parseXmlFile(const std::string& xmlFilePath);


//运行python脚本
std::string runPythonScript(const std::string& scriptPath_extension, const std::string& url, const std::string& ip, int port);


std::string runPythonWithOutput(const std::string& scriptPath_extension, const std::string& url, const std::string& ip, int port);

std::string findScriptByCveId(std::vector<ScanHostResult>& scan_host_result, const std::string& cve_id);

std::string findPortIdByCveId(std::vector<ScanHostResult>& scan_host_result, const std::string& cve_id);