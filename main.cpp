#include<iostream>
#include<libssh/libssh.h>
#include<vector>
#include"Login.h"
#include"Padding.h"
#include<stdio.h>
#include<string>
#include"database/db.h"
#include"scan/portScan.h"	
#include"utils_scan.h"
#include <cpprest/http_client.h>
#include <cpprest/filestream.h>   // 文件流库
#include <cpprest/json.h>         // JSON 库
#include <iostream>
#include"utils/utils.h"
#include"ServerManager.h"
using namespace utility;          // Common utilities like string conversions
using namespace web;              // Common features like URIs.
using namespace web::http;        // Common HTTP functionality
using namespace web::http::client;// HTTP client features
using namespace concurrency::streams; // Asynchronous streams
using namespace std;


int main()
{
    ServerManager serverManager;

    serverManager.open_listener();

    std::string line;
    std::cout << "Press Enter to close the server." << std::endl;
    std::getline(std::cin, line);
	return 0;
}