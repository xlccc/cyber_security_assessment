#pragma once
#include"Event.h"
#include<unordered_map>
#include<libssh/libssh.h>
#include "SSHConnectionPool.h"
#include "database/DatabaseHandler.h"
#include "database/mysql_connection_pool.h"
void fun2(vector<event>& Event, const string& host, const string& username, const string& password,
      ConnectionPool& pool, DatabaseHandler& dbHandler, const vector<int>& ids = std::vector<int>());
void ServerInfo_Padding2(ServerInfo& info, const std::string ip, SSHConnectionPool& pool, ConnectionPool& mysqlPool, DatabaseHandler& dbHandler);