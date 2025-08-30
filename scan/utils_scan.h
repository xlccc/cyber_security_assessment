#pragma once
// utils_scan.h
#ifndef UTILS_SCAN_H
#define UTILS_SCAN_H

#define _TURN_OFF_PLATFORM_STRING  // 禁用cpprest的U宏#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include "rapidxml.hpp" // 使用 RapidXML 库进行 XML 解析
#include"scan_struct.h"
#include <Python.h>
#include"utils.h"
#include <cpprest/http_client.h>	//用于处理 HTTP 请求的库。
#include <cpprest/json.h>			//用于处理 JSON 数据的库。
#include <cpprest/uri_builder.h>	//用于构建 URI 的库
#include <unordered_set>
#include"scan_struct.h"
#include"database/poc.h"
#include <future>
#include <thread>
#include <algorithm>
#include "utils/config.h"
#include <sstream>
#include <unistd.h>    // 用于 fork、pipe、read、write
#include <sys/types.h> // 用于 pid_t
#include <sys/wait.h>  // 用于 waitpid
#include <nlohmann/json.hpp>	//用于解析
#include <mutex>	//锁
#include <condition_variable>	//条件变量，用于控制执行
#include <hiredis/hiredis.h> // Redis C++ 库
#include "log/log.h"
#include <cpprest/http_listener.h>
#include"DatabaseHandler.h"
#include"mysql_connection_pool.h"
using namespace std;
#include<ServerManager.h>


//解析nmap端口扫描结果的xml文件
std::vector<ScanHostResult> parseXmlFile(const std::string& xmlFilePath);


//运行python脚本
std::string runPythonScript(const std::string& scriptPath_extension, const std::string& url, const std::string& ip, int port);


std::string runPythonWithOutput(const std::string& scriptPath_extension, const std::string& url, const std::string& ip, int port);

std::string findScriptByCveId(std::vector<ScanHostResult>& scan_host_result, const std::string& cve_id);

std::string findPortIdByCveId(std::vector<ScanHostResult>& scan_host_result, const std::string& cve_id);

Vuln& findCveByCveId(std::vector<ScanHostResult>& scan_host_result, const std::string& cve_id);

// 判断 CPE 是否一致，返回不一致的 CPE
std::vector<std::string> compareCPEs(const std::map<std::string, std::vector<Vuln>>& newCPEs, const std::map<std::string, std::vector<Vuln>>& oldCPEs);

// 比对并更新结果，根据端口信息和 CPE 信息来决定查询策略
void compareAndUpdateResults(const ScanHostResult& oldResult, ScanHostResult& newResult, int limit = 0);

// CVE 查询函数
void fetch_and_padding_cves(std::map<std::string, std::vector<Vuln>>& cpes, const std::vector<std::string>& cpes_to_query, int limit = 20);

//创建POC任务
std::map<std::string, std::vector<POCTask>> create_poc_task(const std::vector<POC>& poc_list, const ScanHostResult& scan_host_result);

//创建POC任务
//POC扫描所有开放端口，不进行基础设施匹配的版本（使用两个参数）
std::map<std::string, std::vector<POCTask>> create_poc_task(const std::vector<POC>& poc_list, const ScanHostResult& scan_host_result, bool match_infra);

//多进程执行POC任务

void execute_poc_tasks_parallel(std::map<std::string, std::vector<POCTask>>& poc_tasks_by_port, ScanHostResult& scan_host_result, DatabaseHandler& dbHandler, ConnectionPool& pool, const web::http::http_request& req);


//多进程版本的单个POC任务执行
void execute_poc_task(const std::string& key, POCTask& task, redisContext* redis_client, DatabaseHandler& dbHandler, ConnectionPool& pool);


////执行POC任务（非多进程版本）
//void execute_poc_tasks(std::map<std::string, std::vector<POCTask>>& poc_tasks_by_port, ScanHostResult& scan_host_result);

//合并 漏洞库匹配、插件化扫描两种方式的扫描结果
void merge_vuln_results(ScanHostResult& scan_host_result);

// 序列化 POCTask 数据
std::string serialize_task_data(const std::string& key, const POCTask& task);

// 反序列化 POCTask 数据
std::pair<std::string, POCTask> deserialize_task_data(const std::string& task_data);

//将 Vuln 对象序列化为字符串，包含完整字段和端口标识（新增）
std::string serialize_task_result(const Vuln& vuln, const std::string& portId);

// 从字符串反序列化为 Vuln 对象，包含完整字段和端口标识
std::pair<std::string, Vuln> deserialize_task_result(const std::string& data);

// 发布任务到 Redis 队列
void push_task_to_redis(redisContext* c, const std::string& task_data);

// 从 Redis 队列获取任务
//std::string pop_task_from_redis(redisContext* c);
//std::string pop_task_from_redis(redisContext* redis_client, std::string unique_key);//半成品
std::string pop_task_from_redis(redisContext* redis_client, const std::string& unique_key);

// 将任务结果推送到 Redis 结果队列
void push_result_to_redis(redisContext* c, const std::string& result_data);

// 从 Redis 获取任务结果
std::string pop_result_from_redis(redisContext* c);


// 获取 Redis 客户端连接（如果已经创建过，则复用）
redisContext* get_redis_client();

#endif // UTILS_SCAN_H
