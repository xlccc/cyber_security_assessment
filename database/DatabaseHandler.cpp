// DatabaseHandler.cpp
#include "DatabaseHandler.h"
using namespace mysqlx;
// 插入执行函数的实现
void DatabaseHandler::executeInsert(const std::string& sql, ConnectionPool& pool) {
    try {
        auto conn = pool.getConnection();  // 获取连接

        // 执行一些SQL操作
        conn->sql(sql).execute();
        // 使用固定的数据库连接信息
        std::cout << "Data inserted successfully." << std::endl;

    }
    catch (const mysqlx::Error& err) {
        std::cout << "ERROR: " << err.what() << std::endl;
    }
}

void DatabaseHandler::executeUpdateOrInsert(const ScanHostResult& scanHostResult, ConnectionPool& pool)
{
    try {
        auto conn = pool.getConnection();  // 获取连接

        // 执行一些SQL操作
        std::string ip = scanHostResult.ip;

        //(1). 插入os_info表
        std::vector<std::string> os_matches = scanHostResult.os_matches;
        // 1. 查询对应 IP 的 shr_id
        mysqlx::SqlResult result = conn->sql("SELECT id FROM scan_host_result WHERE ip = ?")
            .bind(ip).execute();
        // 2. 获取查询结果
        mysqlx::Row row = result.fetchOne();
        if (!row) {
            std::cerr << "未找到对应 IP 的主机记录：" << ip << std::endl;
            return;
        }
        int shr_id = row[0];  // 获取主机ID

        // 3. 遍历 os_matches，插入每个操作系统版本
        for (const std::string& os_version : os_matches) {
            conn->sql(
                "INSERT INTO os_info (shr_id, os_version) VALUES (?, ?) "
                "ON DUPLICATE KEY UPDATE os_version = os_version"
            ).bind(shr_id, os_version).execute();
            std::cout << "尝试插入或更新操作系统信息: " << os_version << std::endl;
        }

        //(2). 插入open_ports表
        // 遍历 ScanHostResult 中的 ports 成员，并插入到 open_ports 表
        for (const auto& port : scanHostResult.ports) {
            conn->sql(
                "INSERT INTO open_ports (shr_id, port, protocol, status, service_name, product, version) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON DUPLICATE KEY UPDATE status = VALUES(status), "
                "service_name = VALUES(service_name), product = VALUES(product), version = VALUES(version)"
            )
                .bind(
                    shr_id, std::stoi(port.portId), port.protocol, port.status,
                    port.service_name, port.product.empty() ? "" : port.product,
                    port.version.empty() ? "" : port.version
                )
                .execute();

            std::cout << "成功插入或更新端口信息: 端口 " << port.portId
                << ", 协议 " << port.protocol << std::endl;
        }
        //(3)插入vuln表
        processVulns(scanHostResult,  pool);
        //(4)插入host_vuln_result表
        //目前已有shr_id
        processHostVulns(scanHostResult, shr_id,  pool);
        //(5)插入port_vuln_result表
        processPortVulns(scanHostResult, shr_id,  pool);
        //(6)插入cpe表
        processHostCpe(scanHostResult, shr_id,  pool);
        

    }
    catch (const mysqlx::Error& err) {
        std::cerr << "数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }

}

void DatabaseHandler::processVulns(const ScanHostResult& hostResult, ConnectionPool& pool)
{
    // 遍历主机级别的 cpes，并插入其中的漏洞
    for (const auto& [cpe, vulns] : hostResult.cpes) {
        std::cout << "处理 CPE: " << cpe << std::endl;
        insertVulns(vulns, pool);
    }

    // 遍历每个端口，并从端口的 cpes 中提取漏洞
    for (const auto& port : hostResult.ports) {
        std::cout << "处理端口: " << port.portId << std::endl;
        for (const auto& [cpe, vulns] : port.cpes) {
            std::cout << "处理 CPE: " << cpe << " (端口 " << port.portId << ")" << std::endl;
            insertVulns(vulns, pool);
        }
    }
}

void DatabaseHandler::processHostVulns(const ScanHostResult& hostResult, const int shr_id, ConnectionPool& pool)
{    

    // 遍历主机级别的 cpes，并插入其中的漏洞
    for (const auto& [cpe, vulns] : hostResult.cpes) {
         //获取vector<Vuln> vulns
        std::cout << "处理 CPE: " << cpe << std::endl;
        insertHostVulnResult(vulns, shr_id, pool);
    }

}

void DatabaseHandler::processPortVulns(const ScanHostResult& hostResult, const int shr_id, ConnectionPool& pool)
{
    // 遍历每个端口，并从端口的 cpes 中提取漏洞
    for (const auto& port : hostResult.ports) {
        std::cout << "处理端口: " << port.portId << std::endl;
        for (const auto& [cpe, vulns] : port.cpes) {
            std::cout << "处理 CPE: " << cpe << " (端口 " << port.portId << ")" << std::endl;

            //由端口号去得到open_port的主键
            insertPortVulnResult(vulns, shr_id, port.portId, pool);
        }
    }

}

void DatabaseHandler::alterVulnsAfterPocSearch(ConnectionPool& pool, const Vuln & vuln)
{
    try {
        auto conn = pool.getConnection();  // 获取连接

        // 执行一些SQL操作
        conn->sql("UPDATE vuln SET "
            "vul_name = ?, "
            "script = ? "
            "WHERE vuln_id = ?"
        ).bind(
            vuln.vul_name,
            vuln.script.empty() ? "" : vuln.script,  // 插入 NULL 或脚本名称
            vuln.Vuln_id
        )
        .execute();
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
    }
}

void DatabaseHandler::alterHostVulnResultAfterPocVerify(ConnectionPool& pool, const Vuln& vuln, std::string ip)
{
    try {
        auto conn = pool.getConnection();
        std::string vulExist = vuln.vulExist;
        std::string vuln_id = vuln.Vuln_id;
        // 假设 conn 是 MySQL X DevAPI 连接对象
        auto result = conn->sql("SELECT hvr.shr_id, v.id AS vuln_id "
            "FROM host_vuln_result hvr "
            "JOIN scan_host_result shr ON hvr.shr_id = shr.id "
            "JOIN vuln v ON hvr.vuln_id = v.id "
            "WHERE shr.ip = ? AND v.vuln_id = ?"
        ).bind(ip, vuln_id).execute();

        // 获取查询结果
        for (auto row : result) {
            int shr_id = row[0].get<int>();  // host_vuln_result 表中的 shr_id
            int vuln_id_primary = row[1].get<int>();  // vuln 表中的主键 id

            // 更新 host_vuln_result 表中的 vulExist 字段
            conn->sql("UPDATE host_vuln_result SET "
                "vulExist = ? "
                "WHERE shr_id = ? AND vuln_id = ?"
            ).bind(vulExist, shr_id, vuln_id_primary).execute();
        }
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
    }

}

void DatabaseHandler::alterPortVulnResultAfterPocVerify(ConnectionPool& pool, const Vuln& vuln, std::string ip, std::string portId)
{
    try {
        auto conn = pool.getConnection();
        std::string vulExist = vuln.vulExist;
        std::string vuln_id = vuln.Vuln_id;

        // 修改查询语句,添加 open_ports 表中 shr_id 的匹配条件
        auto result = conn->sql("SELECT pvr.shr_id, op.id AS port_id, v.id AS vuln_id "
            "FROM port_vuln_result pvr "
            "JOIN scan_host_result shr ON pvr.shr_id = shr.id "
            "JOIN open_ports op ON pvr.port_id = op.id AND op.shr_id = pvr.shr_id "  // 增加 shr_id 匹配
            "JOIN vuln v ON pvr.vuln_id = v.id "
            "WHERE shr.ip = ? AND v.vuln_id = ? AND op.id = ?"
        ).bind(ip, vuln_id, portId).execute();

        // 获取查询结果
        for (auto row : result) {
            int shr_id = row[0].get<int>();          // port_vuln_result 表中的 shr_id
            int port_id_primary = row[1].get<int>();  // open_ports 表中的主键 id
            int vuln_id_primary = row[2].get<int>();  // vuln 表中的主键 id

            // 更新 port_vuln_result 表中的 vulExist 字段
            conn->sql("UPDATE port_vuln_result SET "
                "vulExist = ? "
                "WHERE shr_id = ? AND port_id = ? AND vuln_id = ?"
            ).bind(vulExist, shr_id, port_id_primary, vuln_id_primary).execute();
        }
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
    }
}

void DatabaseHandler::alterVulnAfterPocTask(ConnectionPool& pool, const POCTask& task)
{
    try {
        auto conn = pool.getConnection();
        std::string ip = task.ip;
        std::string portId = task.port;
        std::string vulExist = task.vuln.vulExist;
        std::string vuln_id = task.vuln.Vuln_id;
        if (portId != "") {
            // 修改查询语句,添加 open_ports 表中 shr_id 的匹配条件
            auto result = conn->sql("SELECT pvr.shr_id, op.id AS port_id, v.id AS vuln_id "
                "FROM port_vuln_result pvr "
                "JOIN scan_host_result shr ON pvr.shr_id = shr.id "
                "JOIN open_ports op ON pvr.port_id = op.id AND op.shr_id = pvr.shr_id "  // 增加 shr_id 匹配
                "JOIN vuln v ON pvr.vuln_id = v.id "
                "WHERE shr.ip = ? AND v.vuln_id = ? AND op.id = ?"
            ).bind(ip, vuln_id, portId).execute();

            // 获取查询结果
            for (auto row : result) {
                int shr_id = row[0].get<int>();          // port_vuln_result 表中的 shr_id
                int port_id_primary = row[1].get<int>();  // open_ports 表中的主键 id
                int vuln_id_primary = row[2].get<int>();  // vuln 表中的主键 id

                // 更新 port_vuln_result 表中的 vulExist 字段
                conn->sql("UPDATE port_vuln_result SET "
                    "vulExist = ? "
                    "WHERE shr_id = ? AND port_id = ? AND vuln_id = ?"
                ).bind(vulExist, shr_id, port_id_primary, vuln_id_primary).execute();
            }
        }
        else {
            auto result = conn->sql("SELECT hvr.shr_id, v.id AS vuln_id "
                "FROM host_vuln_result hvr "
                "JOIN scan_host_result shr ON hvr.shr_id = shr.id "
                "JOIN vuln v ON hvr.vuln_id = v.id "
                "WHERE shr.ip = ? AND v.vuln_id = ?"
            ).bind(ip, vuln_id).execute();

            // 获取查询结果
            for (auto row : result) {
                int shr_id = row[0].get<int>();  // host_vuln_result 表中的 shr_id
                int vuln_id_primary = row[1].get<int>();  // vuln 表中的主键 id

                // 更新 host_vuln_result 表中的 vulExist 字段
                conn->sql("UPDATE host_vuln_result SET "
                    "vulExist = ? "
                    "WHERE shr_id = ? AND vuln_id = ?"
                ).bind(vulExist, shr_id, vuln_id_primary).execute();
            }
        }
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
    }
}

std::vector<IpVulnerabilities> DatabaseHandler::getVulnerabilities(ConnectionPool& pool)
{
    try {
        auto conn = pool.getConnection();
        // 执行SQL查询
        mysqlx::SqlResult result = conn->sql(R"(
            -- 主机漏洞
            SELECT 
                shr.ip,
                NULL AS port_id,
                v.vuln_id,
                v.vul_name AS vuln_name,
                v.CVSS AS cvss,
                v.summary,
                hvr.vulExist,
                '主机漏洞' AS vuln_type
            FROM scan_host_result shr
            JOIN host_vuln_result hvr ON shr.id = hvr.shr_id
            JOIN vuln v ON v.id = hvr.vuln_id
            WHERE hvr.vulExist IN ('存在', '不存在')
            UNION ALL
            -- 端口漏洞
            SELECT 
                shr.ip,
                op.port AS port_id,
                v.vuln_id,
                v.vul_name AS vuln_name,
                v.CVSS AS cvss,
                v.summary,
                pvr.vulExist,
                '端口漏洞' AS vuln_type
            FROM scan_host_result shr
            JOIN open_ports op ON shr.id = op.shr_id
            JOIN port_vuln_result pvr ON op.id = pvr.port_id AND shr.id = pvr.shr_id
            JOIN vuln v ON v.id = pvr.vuln_id
            WHERE pvr.vulExist IN ('存在', '不存在')
            ORDER BY ip, port_id;
        )").execute();

        // 使用map临时存储结果，key为IP
        std::map<std::string, IpVulnerabilities> ip_vulns_map;

        // 处理查询结果
        for (auto row : result) {
            std::string ip = row[0].get<std::string>();

            // 如果这个IP还没有记录，创建新记录
            if (ip_vulns_map.find(ip) == ip_vulns_map.end()) {
                ip_vulns_map[ip] = IpVulnerabilities{ ip };
            }

            // 创建漏洞信息对象
            std::string vuln_type = row[7].get<std::string>();

            if (vuln_type == "主机漏洞") {
                VulnerabilityInfo vuln;
                vuln.vuln_id = row[2].get<std::string>();
                vuln.vuln_name = row[3].get<std::string>();
                vuln.cvss = row[4].get<std::string>();
                vuln.summary = row[5].get<std::string>();
                vuln.vulExist = row[6].get<std::string>();

                ip_vulns_map[ip].host_vulnerabilities.push_back(vuln);
            }
            else {
                PortVulnerabilityInfo port_vuln;
                port_vuln.port_id = row[1].get<int>();
                port_vuln.vuln_id = row[2].get<std::string>();
                port_vuln.vuln_name = row[3].get<std::string>();
                port_vuln.cvss = row[4].get<std::string>();
                port_vuln.summary = row[5].get<std::string>();
                port_vuln.vulExist = row[6].get<std::string>();

                ip_vulns_map[ip].port_vulnerabilities.push_back(port_vuln);
            }
        }

        // 将map转换为vector返回
        std::vector<IpVulnerabilities> result_vector;
        for (const auto& pair : ip_vulns_map) {
            result_vector.push_back(pair.second);
        }

        return result_vector;
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
    }
}

void DatabaseHandler::processHostCpe(const ScanHostResult& hostResult, const int shr_id, ConnectionPool& pool)
{
    std::set<std::string> all_cpes = extractAllCPEs(hostResult);
    insertHostCPEs(shr_id, all_cpes, pool);
}

void DatabaseHandler::insertVulns(const std::vector<Vuln>& vulns, ConnectionPool& pool)
{
    try {
        auto conn = pool.getConnection();  // 获取连接

        // 执行一些SQL操作



        // 2. 遍历 vuln_result 集合，逐条插入 vuln 表
        for (const auto& vuln : vulns) {
            std::cout << "插入或更新漏洞: " << vuln.vul_name << std::endl;
            conn->sql(
                "INSERT INTO vuln (vuln_id, vul_name, script, CVSS, summary) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON DUPLICATE KEY UPDATE vul_name = VALUES(vul_name), "
                "script = VALUES(script), CVSS = VALUES(CVSS), summary = VALUES(summary)"
            )
                .bind(
                    vuln.Vuln_id,
                    vuln.vul_name,
                    vuln.script.empty() ? "" : vuln.script,  // 插入 NULL 或脚本名称
                    vuln.CVSS,
                    vuln.summary.empty() ? "" : vuln.summary  // 插入 NULL 或漏洞描述
                )
                .execute();

        }

    }
    catch (const mysqlx::Error& err) {
        std::cerr << "数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
    }
}

void DatabaseHandler::insertHostVulnResult(const std::vector<Vuln>& vulns, const int shr_id, ConnectionPool& pool)
{
    try {


        auto conn = pool.getConnection();  // 获取连接

        
        // 2. 遍历 vector<Vuln>，逐个查询主键 ID
        for (const auto& vuln : vulns) {
            //这里的vuln_id是cve编号
            mysqlx::SqlResult result = conn->sql(
                "SELECT id FROM vuln WHERE vuln_id = ? "
            ).bind(vuln.Vuln_id).execute();

            // 如果查询到结果，获取主键 ID
            if (result.count() > 0) {
                mysqlx::Row row = result.fetchOne();
                int vuln_id = row[0].get<int>();


                //有了vuln_id 和shr_id
                conn->sql(
                    "INSERT INTO host_vuln_result (shr_id, vuln_id, vulExist) "
                    "VALUES (?, ?, '未验证') "
                    "ON DUPLICATE KEY UPDATE vulExist = '未验证'"
                )
                .bind(shr_id, vuln_id)
                .execute();
                
            }
            else {
                std::cerr << "未找到漏洞: " << vuln.vul_name << std::endl;
            }
        }

    }
    catch (const mysqlx::Error& err) {
        std::cerr << "数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
    }

}

void DatabaseHandler::insertPortVulnResult(const std::vector<Vuln>& vulns, const int shr_id, const std::string port, ConnectionPool& pool)
{
    try {
        auto conn = pool.getConnection();  // 获取连接



        mysqlx::SqlResult resultPortId = conn->sql(
            "SELECT id FROM open_ports WHERE port = ? "
        ).bind(std::stoi(port)).execute();
        mysqlx::Row row = resultPortId.fetchOne();
        int port_id = row[0].get<int>();

        // 2. 遍历 vector<Vuln>，逐个查询主键 ID
        for (const auto& vuln : vulns) {
            //这里的vuln_id是cve编号
            mysqlx::SqlResult result = conn->sql(
                "SELECT id FROM vuln WHERE vuln_id = ? "
            ).bind(vuln.Vuln_id).execute();

            // 如果查询到结果，获取主键 ID
            if (result.count() > 0) {
                mysqlx::Row row = result.fetchOne();
                int vuln_id = row[0].get<int>();


                //有了vuln_id 和shr_id 和port_id
                conn->sql(
                    "INSERT INTO port_vuln_result (shr_id, port_id, vuln_id, vulExist) "
                    "VALUES (?, ?, ?, '未验证') "
                    "ON DUPLICATE KEY UPDATE vulExist = '未验证'"
                )
                    .bind(shr_id, port_id, vuln_id)
                    .execute();

            }
        }
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
    }
}

std::set<std::string> DatabaseHandler::extractAllCPEs(const ScanHostResult& hostResult)
{

    std::set<std::string> all_cpes;

    // 1. 遍历主机级别的 cpes
    for (const auto& [cpe, vulns] : hostResult.cpes) {
        all_cpes.insert(cpe);
        std::cout << "找到主机级 CPE: " << cpe << std::endl;
    }

    // 2. 遍历每个端口的 cpes
    for (const auto& port : hostResult.ports) {
        for (const auto& [cpe, vulns] : port.cpes) {
            all_cpes.insert(cpe);
            std::cout << "找到端口 " << port.portId << " 的 CPE: " << cpe << std::endl;
        }
    }

    return all_cpes;
}

void DatabaseHandler::insertHostCPEs(int shr_id, const std::set<std::string>& cpes, ConnectionPool& pool)
{
    try {
        auto conn = pool.getConnection();  // 获取连接

        for (const auto& cpe : cpes) {
            conn->sql(
                "INSERT INTO host_cpe (shr_id, cpe) VALUES (?, ?) "
                "ON DUPLICATE KEY UPDATE cpe = VALUES(cpe)"
            )
                .bind(shr_id, cpe)
                .execute();

            std::cout << "成功插入或更新 CPE: " << cpe << std::endl;
        }
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "数据库错误: " << err.what() << std::endl;
    }
}

