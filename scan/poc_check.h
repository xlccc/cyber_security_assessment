#pragma once
#define _TURN_OFF_PLATFORM_STRING  // 禁用cpprest的U宏
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include "DatabaseWrapper.h"
#include "scan_struct.h"
#include "utils_scan.h"
#include"DatabaseHandler.h"
#include"mysql_connection_pool.h"
#include <cpprest/http_listener.h>
#include<ServerManager.h>
//搜索POC是否存在、并加载POC插件路径
void searchPOCs(ScanHostResult& hostResult, DatabaseWrapper& dbManager, DatabaseHandler& dbHandler, ConnectionPool& pool, const web::http::http_request& req);

//执行选中的POC脚本进行漏洞验证
void verifyPOCs(std::vector<ScanHostResult>& scanHostResults, DatabaseHandler& dbHandler, ConnectionPool& pool, const web::http::http_request& req);