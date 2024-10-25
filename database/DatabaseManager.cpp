#include "DatabaseManager.h"
#include <iostream>


DatabaseManager::DatabaseManager(const std::string& dbPath) {

    // 打开数据库，如果不存在则创建，参数1：db的文件路径，参数2：返回的sqlite3*对象
    db = nullptr;
    std::cout << "SQLite database Path: " << dbPath << std::endl;
    if (sqlite3_open(dbPath.c_str(), &db) != SQLITE_OK) {
        std::cerr << "Error opening SQLite database: " << sqlite3_errmsg(db) << std::endl;
    }
    else
    {
        std::cout << "open SQLite database " << std::endl;
    }
}

DatabaseManager::~DatabaseManager() {
    // 关闭数据库连接
    closeDb();
}

void DatabaseManager::closeDb() {
    if (db != nullptr) {
        sqlite3_close(db);
        db = nullptr;
    }
}

bool DatabaseManager::openDb() {
    return db != nullptr;
}

bool DatabaseManager::createTable() {
    // SQL语句创建表，包含字段描述
    std::string sql = R"(
    CREATE TABLE IF NOT EXISTS POC (
        ID INTEGER PRIMARY KEY AUTOINCREMENT, -- 主键ID，自动增长的整数
        CVE_id TEXT NOT NULL,                 -- CVE编号，可能会有重复
        Vul_name TEXT,                        -- 漏洞名称（补充）
        Type TEXT,                            -- 漏洞类型，描述漏洞的类别
        Description TEXT,                     -- 漏洞描述，详细说明漏洞的细节
        Script_type TEXT NOT NULL DEFAULT 'python' CHECK( Script_type IN ('python', 'c/c++', 'yaml') ),     
                                              -- POC类型，只可在这三种类型中选
        Script TEXT,                          -- POC脚本代码，存储Python脚本的文本
        Timestamp TEXT NOT NULL               -- 添加时间，格式为"YYYY-MM-DD HH:MM:SS" 
    );
    )";
    char* errMsg = nullptr;
    // 执行SQL语句
    //参数3：sqlite_callback 是一个回调，参数4：data 作为3的其第一个参数
    //成功返回SQLITE_OK
    int rc = sqlite3_exec(db, sql.c_str(), nullptr, 0, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}

//添加POC数据
bool DatabaseManager::insertData(const std::string& cve_id, const std::string& vul_name, const std::string& type, const std::string& description, const std::string& script_type, const std::string& script) {
    std::string timestamp = getCurrentTimestamp();
    std::string sql = "INSERT INTO POC (CVE_id, Vul_name, Type, Description, Script_type, Script, Timestamp) VALUES (?, ?, ?, ?, ?, ?, ?);";
    //表示一个编译好的SQL语句
    sqlite3_stmt* stmt;
    //编译SQL语句,-1表示读取到第一个终止符停止。
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "SQL error: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    //将值绑定到参数
    sqlite3_bind_text(stmt, 1, cve_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, vul_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, script_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, script.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, timestamp.c_str(), -1, SQLITE_TRANSIENT);
    //执行SQL语句
    int rc = sqlite3_step(stmt);
    //sqlite3_finalize() 函数来删除准备好的语句。
    //如果语句的最近评估没有遇到错误，或者从未评估过语句，则 sqlite3_finalize() 返回 SQLITE_OK。
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "SQL error: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    return true;
}

//根据ID号删除对应POC记录
bool DatabaseManager::deleteDataById(int id) {
    std::string sql = "DELETE FROM POC WHERE ID = " + std::to_string(id) + ";";
    char* errMsg = nullptr;
    int rc = sqlite3_exec(db, sql.c_str(), nullptr, 0, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        return false;
    }
    return true;
}

//根据选中POC记录对应的id，修改POC数据
bool DatabaseManager::updateDataById(int id, const POC& poc) {
    //首先检查ID是否存在
    std::string checkSql = "SELECT COUNT(*) FROM POC WHERE ID = ?;";
    sqlite3_stmt* checkStmt;
    if (sqlite3_prepare_v2(db, checkSql.c_str(), -1, &checkStmt, nullptr) != SQLITE_OK) {
        std::cerr << "SQL error: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    sqlite3_bind_int(checkStmt, 1, id);
    int rc = sqlite3_step(checkStmt);
    bool idExists = false;
    if (rc == SQLITE_ROW) {
        idExists = sqlite3_column_int(checkStmt, 0) > 0;
    }
    sqlite3_finalize(checkStmt);

    if (!idExists) {
        std::cerr << "SQL error: ID does not exist." << std::endl;
        return false;
    }

    //更新操作
    std::string timestamp = getCurrentTimestamp();
    std::string sql = "UPDATE POC SET CVE_id = ?, Vul_name = ?, Type = ?, Description = ?, Script_type = ?, Script = ?, Timestamp = ? WHERE ID = ?;";

    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "SQL error: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    //将值绑定到参数
    sqlite3_bind_text(stmt, 1, poc.cve_id.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, poc.vul_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, poc.type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, poc.description.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, poc.script_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, poc.script.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, timestamp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 8, id);

    //执行SQL语句
    rc = sqlite3_step(stmt);
    //sqlite3_finalize() 函数来删除准备好的语句。
    //如果语句的最近评估没有遇到错误，或者从未评估过语句，则 sqlite3_finalize() 返回 SQLITE_OK。
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        std::cerr << "SQL error: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }
    std::cout << "修改成功" << std::endl;
    return true;
}


// 搜索POC数据，关键字可以匹配除id、script以外的任何字段
std::vector<POC> DatabaseManager::searchData(const std::string& keyword) {
    std::vector<POC> records;

    // 使用通配符%构建LIKE模式
    //std::string pattern = "%" + convertToUTF8(keyword, "GBK") + "%";
    std::string pattern = "%" + keyword + "%";
    std::string sql = "SELECT * FROM POC WHERE "
        "CVE_id LIKE '" + pattern + "' OR "
        "Vul_name LIKE '" + pattern + "' OR "
        "Type LIKE '" + pattern + "' OR "
        "Description LIKE '" + pattern + "' OR "
        "Script_type LIKE '" + pattern + "' OR "
        "Timestamp LIKE '" + pattern + "';";

    std::cout << sql << std::endl;

    char* errMsg = nullptr;
    int rc = sqlite3_exec(db, sql.c_str(), callback, &records, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    }
    return records;
}


//按CVE编号搜索POC数据，若没有，返回无对应POC
//根据返回的vector数组的empty()来判断是否存在POC
std::vector<POC> DatabaseManager::searchDataByCVE(const std::string& cve_id) {
    std::vector<POC> records;
    // SQL语句搜索数据
    std::string sql = "SELECT * FROM POC WHERE CVE_id='" + cve_id + "';";
    char* errMsg = nullptr;
    ;
    // 执行SQL语句，并处理结果
    int rc = sqlite3_exec(db, sql.c_str(), callback, &records, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    }
    return records;
}

//根据CVE搜索对应POC
bool DatabaseManager::isExistCVE(const std::string& cve_id)
{
    std::vector<POC> records;
    // SQL语句搜索数据
    std::string sql = "SELECT * FROM POC WHERE CVE_id='" + cve_id + "';";
    char* errMsg = nullptr;
    ;
    // 执行SQL语句，并处理结果
    int rc = sqlite3_exec(db, sql.c_str(), callback, &records, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    }
    if (!records.empty())
        return true;
    return false;
}

//依据id搜索POC路径，用于删除对应POC
std::string DatabaseManager::searchPOCById(const int & id) {
    std::vector<POC> records;
    std::string POC_filename = "";
    // SQL语句搜索数据
    std::string sql = "SELECT * FROM POC WHERE ID='" + std::to_string(id) + "';";
    char* errMsg = nullptr;

    // 执行SQL语句，并处理结果
    int rc = sqlite3_exec(db, sql.c_str(), callback, &records, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    }
    if (records.empty())
        return POC_filename;
    POC_filename = records[0].script;
    POC_filename = "../../../src/scan/scripts/" + POC_filename;
    return POC_filename;
}


//依据id搜索POC数据
bool DatabaseManager::searchDataById(const int& id, POC& poc) {
    std::vector<POC> records;
    // SQL语句搜索数据
    std::string sql = "SELECT * FROM POC WHERE ID='" + std::to_string(id) + "';";
    char* errMsg = nullptr;
    ;
    // 执行SQL语句，并处理结果
    int rc = sqlite3_exec(db, sql.c_str(), callback, &records, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    }
    if (records.empty())    //没有ID对应的POC数据
    {
        std::cerr << "SQL error: ID does not exist." << std::endl;
        return false;
    }
    poc = records[0];
    return true;
}

//回调函数，sql功能命令执行结果的进一步处理，按行循环调用回调函数处理。
//第二个参数是结果中的列数
//第三个参数是一个指向字符串的指针数组,每列一个。如果结果行的元素为 NULL，则回调的相应字符串指针为 NULL 指针
//第四个参数是指向字符串的指针数组，其中每个条目代表列的名称
int DatabaseManager::callback(void* data, int argc, char** argv, char** azColName) {
    std::vector<POC>* records = static_cast<std::vector<POC>*>(data);
    POC poc;
    for (int i = 0; i < argc; i++) {
        std::string column(azColName[i]);
        if (column == "ID") {
            poc.id = std::stoi(argv[i]);       //获取数据库中的id
        }
        else if (column == "CVE_id") {
            poc.cve_id = argv[i] ? argv[i] : "";
        }
        else if (column == "Vul_name") {
            poc.vul_name = argv[i] ? argv[i] : "";
        }
        else if (column == "Type") {
            poc.type = argv[i] ? argv[i] : "";
        }
        else if (column == "Description") {
            poc.description = argv[i] ? argv[i] : "";
        }
        else if (column == "Script_type") {
            poc.script_type = argv[i] ? argv[i] : "";
        }
        else if (column == "Script") {
            poc.script = argv[i] ? argv[i] : "";
        }
        else if (column == "Timestamp") {
            poc.timestamp = argv[i] ? argv[i] : "";
        }
    }
    records->push_back(poc);
    return 0;
}

// 获取所有POC记录，并且每个POC的结构体的id成员会被赋值。(必须先执行）
//刷新页面时也调用它。
std::vector<POC> DatabaseManager::getAllData() {
    std::vector<POC> records;
    std::string sql = "SELECT * FROM POC;";
    char* errMsg = nullptr;
    int rc = sqlite3_exec(db, sql.c_str(), callback, &records, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        exit(1);            //执行失败必须退出，其他功能依赖于此函数的成功调用
    }
    return records;
}

