#pragma once
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include "rapidxml.hpp" // 使用 RapidXML 库进行 XML 解析
#include"scan_struct.h"

//解析nmap端口扫描结果的xml文件
std::vector<ScanHostResult> parseXmlFile(const std::string& xmlFilePath);

