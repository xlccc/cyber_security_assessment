#pragma once
#define _TURN_OFF_PLATFORM_STRING  // ����cpprest��U��
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include "DatabaseManager.h"
#include "scan_struct.h"
#include "utils_scan.h"
#include"DatabaseHandler.h"
#include"mysql_connection_pool.h"

//����POC�Ƿ���ڡ�������POC���·��
void searchPOCs(ScanHostResult& hostResult, DatabaseManager& dbManager, DatabaseHandler& dbHandler, ConnectionPool& pool);

//ִ��ѡ�е�POC�ű�����©����֤
void verifyPOCs(std::vector<ScanHostResult>& scanHostResults, DatabaseHandler& dbHandler, ConnectionPool& pool);