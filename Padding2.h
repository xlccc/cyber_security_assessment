#pragma once
#include"Event.h"
#include<unordered_map>
#include<libssh/libssh.h>
#include "SSHConnectionPool.h"

void fun2(vector<event>& Event, const string& host, const string& username, const string& password,
    const vector<int>& ids = std::vector<int>());
void ServerInfo_Padding2(ServerInfo& info, SSHConnectionPool& pool);