#pragma once
#include"Event.h"
#include<unordered_map>
#include<config.h>
#include<libssh/libssh.h>
#include "ssh_win.h"
#include <iostream>
#include <vector>
#include <map>
#include <cstdlib>
#include <string>
#include <sstream>
#include <iomanip>
#include<stdlib.h>
#include<algorithm>
#include"Event.h"
//左右结构提取字符串
//string parseValueFromOutput(const std::string& output, const std::string& keyword);
//上下结构提取字符串
string parseCommandOutput(const std::string& output);
//// 提取冒号之后的子串
//string getEcho(const std::string& input);
////提取冒号之前的子串并转换为整数
//int getExitCode(const std::string& input);
//获取windows操作系统版本
std::string getWindowsVersion(SSHClient& sshClient);
//57条命令初始化
void initialize_basline(vector<event_t>& Event, map<int, event_t>& allBaseline, SSHClient& sshClient);
//获取windows操作系统信息
void ServerInfo_win(ServerInfo& info, SSHClient& sshClient);
