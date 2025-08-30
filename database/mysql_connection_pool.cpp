#include "mysql_connection_pool.h"

// 线程局部存储定义
namespace ConnectionPoolInternal {
    thread_local std::string current_thread_db;
}