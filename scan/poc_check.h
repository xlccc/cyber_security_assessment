#pragma once
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include "DatabaseManager.h"
#include "scan_struct.h"
#include "utils_scan.h"


//搜索POC是否存在、并加载POC插件路径
void searchPOCs(ScanHostResult& hostResult, DatabaseManager& dbManager);

//执行选中的POC脚本进行漏洞验证
void verifyPOCs(std::vector<ScanHostResult>& scanHostResults);