#pragma once
#include"Event.h"
#include<unordered_map>
#include<libssh/libssh.h>
#include "SSHConnectionPool.h"
#include "database/DatabaseHandler.h"
#include "database/mysql_connection_pool.h"
#include <cpprest/http_listener.h>
#include<ServerManager.h>
void fun2(const string& host, const string& username, const string& password,
      ConnectionPool& pool, DatabaseHandler& dbHandler,const web::http::http_request& req, const vector<int>& ids = std::vector<int>());
void ServerInfo_Padding2(ServerInfo& info, const std::string ip, SSHConnectionPool& pool, ConnectionPool& mysqlPool, DatabaseHandler& dbHandler, const web::http::http_request& req);

void level3Fun(const string& host, const string& username, const string& password,
	ConnectionPool& mysqlPool, DatabaseHandler& dbHandler, const vector<int>& ids, const web::http::http_request& req);