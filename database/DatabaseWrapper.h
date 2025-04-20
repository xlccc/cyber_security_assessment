#pragma once
#pragma once
#include "DatabaseHandler.h"
#include "mysql_connection_pool.h"
#include "scan_struct.h"

// 包装类，用于对接旧 DatabaseManager 接口，转发到新的 DatabaseHandler 实现
class DatabaseWrapper {
public:
    DatabaseWrapper(ConnectionPool& pool, DatabaseHandler& handler)
        : handler(handler), pool(pool) {}

    // ---- 兼容旧 DatabaseManager 接口定义 ----

    bool insertData(const std::string& vuln_id, const std::string& vul_name, const std::string& type,
        const std::string& description, const std::string affected_infra,
        const std::string& script_type, const std::string& script) {
        POC poc;
        poc.vuln_id = vuln_id;
        poc.vul_name = vul_name;
        poc.type = type;
        poc.description = description;
        poc.affected_infra = affected_infra;
        poc.script_type = script_type;
        poc.script = script;
        return handler.insertData(poc, pool);
    }

    bool deleteDataById(int id) {
        return handler.deleteDataById(id, pool);
    }

    bool updateDataById(int id, const POC& poc) {
        return handler.updateDataById(id, poc, pool);
    }

    std::vector<POC> searchData(const std::string& keyword) {
        return handler.searchData(keyword, pool);
    }

    std::vector<POC> searchDataByCVE(const std::string& vuln_id) {
        return handler.searchDataByCVE(vuln_id, pool);
    }

    std::vector<POC> searchDataByIds(const std::vector<int>& ids) {
        return handler.searchDataByIds(ids, pool);
    }

    bool isExistCVE(const std::string& vuln_id) {
        return handler.isExistCVE(vuln_id, pool);
    }

    std::string searchPOCById(const int& id) {
        return handler.searchPOCById(id, pool);
    }

    std::string searchPOCById(const std::string& vuln_id) {
        return handler.searchPOCById(vuln_id, pool);
    }

    bool searchDataById(const int& id, POC& poc) {
        return handler.searchDataById(id, poc, pool);
    }

    std::vector<POC> getAllData() {
        return handler.getAllData(pool);
    }

    std::vector<POC> getVaildPOCData() {
        return handler.getVaildPOCData(pool);
    }

private:
    DatabaseHandler& handler;
    ConnectionPool& pool;
};
