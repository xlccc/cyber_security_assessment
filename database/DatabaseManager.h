#ifndef DATABASEMANAGER_H
#define DATABASEMANAGER_H

#include <string>
#include <sqlite3.h>
#include<vector>
#include<iostream>
#include"poc.h"
#include"../utils/utils.h"

// DatabaseManager类，封装数据库操作
class DatabaseManager {
public:
    // 构造函数，指定数据库路径
    DatabaseManager(const std::string& dbPath);
    // 析构函数，关闭数据库连接
    ~DatabaseManager();

    // 打开数据库
    bool openDb();
    // 关闭数据库
    void closeDb();
    // 创建表
    bool createTable();
    // 插入数据
    bool insertData(const std::string& vuln_id, const std::string& vul_name, const std::string& type, const std::string& description, const std::string affected_infra, const std::string& script_type, const std::string& script);
    // 删除数据
    bool deleteDataById(int id);
    // 更新数据
    bool updateDataById(int id, const POC& poc);
    // 根据关键字搜索数据
    std::vector<POC> searchData(const std::string& keyword);

    //根据CVE搜索对应POC
    std::vector<POC> searchDataByCVE(const std::string& vuln_id);
    ////按id搜索POC数据，若没有，返回无对应POC
    std::vector<POC> searchDataByIds(const std::vector<int>& ids);

    //搜索是否存在CVE编号的记录
    bool isExistCVE(const std::string& vuln_id);
    
    //依据id搜索POC名称，用于删除对应POC
    std::string searchPOCById(const int& id);
    //依据id搜索POC名称，用于删除对应POC
    std::string searchPOCById(const std::string& vuln_id);

    //依据id搜索POC数据
    bool searchDataById(const int& id, POC& poc);

    //获取所有数据
    std::vector<POC> getAllData();

private:
    sqlite3* db; // SQLite数据库连接对象 
    int size;    //记录个数
    // 静态回调函数用于处理查询结果
    static int callback(void* NotUsed, int argc, char** argv, char** azColName);
};


#endif
