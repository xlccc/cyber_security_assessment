#pragma once
#include <iostream>
#include <string>
#include <map>
#include <vector>
#include "DatabaseManager.h"
#include "scan_struct.h"
#include "utils_scan.h"


//����POC�Ƿ���ڡ�������POC���·��
void searchPOCs(ScanHostResult& hostResult, DatabaseManager& dbManager);

//ִ��ѡ�е�POC�ű�����©����֤
void verifyPOCs(std::vector<ScanHostResult>& scanHostResults);