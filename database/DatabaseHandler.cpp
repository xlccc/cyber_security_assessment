// DatabaseHandler.cpp
#include "DatabaseHandler.h"
using namespace mysqlx;
// 插入执行函数的实现
void DatabaseHandler::executeInsert(const ScanHostResult& scanHostResult, ConnectionPool& pool) {
    try {
        // 定义插入语句
        std::string sql =
            "INSERT INTO scan_host_result (ip, scan_time, alive, expire_time) VALUES ('" +
            scanHostResult.ip + "', '" +
            scanHostResult.scan_time + "', 'true', " +
            "DATE_ADD('" + scanHostResult.scan_time + "', INTERVAL 7 DAY)" +
            ") ON DUPLICATE KEY UPDATE scan_time = VALUES(scan_time), " +
            "alive = 'true', " +
            "expire_time = DATE_ADD(VALUES(scan_time), INTERVAL 7 DAY)";
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
                "INSERT INTO open_ports (shr_id, port, protocol, status, service_name, product, version, software_type) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
                "ON DUPLICATE KEY UPDATE status = VALUES(status), "
                "service_name = VALUES(service_name), product = VALUES(product), "
                "version = VALUES(version), software_type = VALUES(software_type)"
            )
                .bind(
                    shr_id, std::stoi(port.portId), port.protocol, port.status,
                    port.service_name, port.product.empty() ? "" : port.product,
                    port.version.empty() ? "" : port.version,
                    port.softwareType.empty() ? "" : port.softwareType
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
std::vector<IpVulnerabilities> DatabaseHandler::getVulnerabilities(ConnectionPool& pool, std::vector<std::string> alive_hosts)
{
    std::map<std::string, IpVulnerabilities> ip_vulns_map;
	for (auto ip : alive_hosts) {
		if (ip_vulns_map.find(ip) == ip_vulns_map.end()) {
			ip_vulns_map[ip] = IpVulnerabilities{ ip };
		}
	}

    try {
        auto conn = pool.getConnection();

        // 1. 先查询主机漏洞
        std::cout << "正在查询主机漏洞..." << std::endl;
        mysqlx::SqlResult hostResult = conn->sql(R"(
            SELECT 
                shr.ip,
                NULL AS port_id,
                v.vuln_id,
                v.vul_name AS vuln_name,
                v.CVSS AS cvss,
                v.summary,
                hvr.vulExist,
                '主机漏洞' AS vuln_type,
                '操作系统' AS software_type,
                v.vuln_type AS vulnerability_type,
                NULL AS service_name
            FROM scan_host_result shr
            JOIN host_vuln_result hvr ON shr.id = hvr.shr_id
            JOIN vuln v ON v.id = hvr.vuln_id
            WHERE hvr.vulExist IN ('存在', '不存在')
            AND shr.alive = 'true' AND shr.expire_time > CURRENT_TIMESTAMP
            ORDER BY ip;
        )").execute();

        // 处理主机漏洞结果
        int hostVulnCount = 0;
        for (auto row : hostResult) {
            hostVulnCount++;
            std::string ip = row[0].get<std::string>();
            // 如果这个IP还没有记录，创建新记录
            if (ip_vulns_map.find(ip) == ip_vulns_map.end()) {
                ip_vulns_map[ip] = IpVulnerabilities{ ip };
            }

            VulnerabilityInfo vuln;
            vuln.vuln_id = row[2].get<std::string>();
            vuln.vuln_name = row[3].get<std::string>();
            vuln.cvss = row[4].get<std::string>();
            vuln.summary = row[5].get<std::string>();
            vuln.vulExist = row[6].get<std::string>();
            vuln.softwareType = row[8].get<std::string>();
            vuln.vulType = row[9].get<std::string>();
            ip_vulns_map[ip].host_vulnerabilities.push_back(vuln);
        }
        std::cout << "主机漏洞查询完成，找到 " << hostVulnCount << " 个结果" << std::endl;

        // 2. 再查询端口漏洞
        std::cout << "正在查询端口漏洞..." << std::endl;
        mysqlx::SqlResult portResult = conn->sql(R"(
            SELECT 
                shr.ip,
                op.port AS port_id,
                v.vuln_id,
                v.vul_name AS vuln_name,
                v.CVSS AS cvss,
                v.summary,
                pvr.vulExist,
                '端口漏洞' AS vuln_type,
                op.software_type,
                v.vuln_type AS vulnerability_type,
                op.product
            FROM scan_host_result shr
            JOIN open_ports op ON shr.id = op.shr_id
            JOIN port_vuln_result pvr ON op.id = pvr.port_id AND shr.id = pvr.shr_id
            JOIN vuln v ON v.id = pvr.vuln_id
            WHERE pvr.vulExist IN ('存在', '不存在')
            AND shr.alive = 'true' AND shr.expire_time > CURRENT_TIMESTAMP
            ORDER BY ip, port_id;
        )").execute();

        // 处理端口漏洞结果
        int portVulnCount = 0;
        for (auto row : portResult) {
            portVulnCount++;
            std::string ip = row[0].get<std::string>();
            // 如果这个IP还没有记录，创建新记录
            if (ip_vulns_map.find(ip) == ip_vulns_map.end()) {
                ip_vulns_map[ip] = IpVulnerabilities{ ip };
            }

            PortVulnerabilityInfo port_vuln;
            port_vuln.port_id = row[1].get<int>();
            port_vuln.vuln_id = row[2].get<std::string>();
            port_vuln.vuln_name = row[3].get<std::string>();
            port_vuln.cvss = row[4].get<std::string>();
            port_vuln.summary = row[5].get<std::string>();
            port_vuln.vulExist = row[6].get<std::string>();
            port_vuln.softwareType = row[8].get<std::string>();
            port_vuln.vulType = row[9].get<std::string>();
            port_vuln.service_name = row[10].get<std::string>();
            ip_vulns_map[ip].port_vulnerabilities.push_back(port_vuln);
        }
        std::cout << "端口漏洞查询完成，找到 " << portVulnCount << " 个结果" << std::endl;

        // 统计总结果
        int totalIPs = ip_vulns_map.size();
        int totalHostVulns = 0;
        int totalPortVulns = 0;
        for (const auto& pair : ip_vulns_map) {
            totalHostVulns += pair.second.host_vulnerabilities.size();
            totalPortVulns += pair.second.port_vulnerabilities.size();
        }

        std::cout << "总IP数: " << totalIPs << std::endl;
        std::cout << "总主机漏洞数: " << totalHostVulns << std::endl;
        std::cout << "总端口漏洞数: " << totalPortVulns << std::endl;

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

    // 发生错误时返回空结果
    return std::vector<IpVulnerabilities>{};
}
//std::vector<IpVulnerabilities> DatabaseHandler::getVulnerabilities(ConnectionPool& pool)
//{
//    try {
//        auto conn = pool.getConnection();
//        // 执行SQL查询，添加条件过滤掉已过期的主机
//        mysqlx::SqlResult result = conn->sql(R"(
//    -- 主机漏洞
//    SELECT 
//        shr.ip,
//        NULL AS port_id,
//        v.vuln_id,
//        v.vul_name AS vuln_name,
//        v.CVSS AS cvss,
//        v.summary,
//        hvr.vulExist,
//        '主机漏洞' AS vuln_type,
//        '操作系统' AS software_type, -- 主机漏洞部分写死为"操作系统"
//        v.vuln_type AS vulnerability_type, -- 新增：从vuln表获取漏洞类型
//        NULL AS service_name  -- 添加这一列以匹配端口漏洞查询
//    FROM scan_host_result shr
//    JOIN host_vuln_result hvr ON shr.id = hvr.shr_id
//    JOIN vuln v ON v.id = hvr.vuln_id
//    WHERE hvr.vulExist IN ('存在', '不存在')
//    AND shr.alive = 'true' AND shr.expire_time > CURRENT_TIMESTAMP
//    UNION ALL
//    -- 端口漏洞
//    SELECT 
//        shr.ip,
//        op.port AS port_id,
//        v.vuln_id,
//        v.vul_name AS vuln_name,
//        v.CVSS AS cvss,
//        v.summary,
//        pvr.vulExist,
//        '端口漏洞' AS vuln_type,
//        op.software_type, -- 查询 open_ports 表中的 software_type
//        v.vuln_type AS vulnerability_type, -- 新增：从vuln表获取漏洞类型
//        op.product
//    FROM scan_host_result shr
//    JOIN open_ports op ON shr.id = op.shr_id
//    JOIN port_vuln_result pvr ON op.id = pvr.port_id AND shr.id = pvr.shr_id
//    JOIN vuln v ON v.id = pvr.vuln_id
//    WHERE pvr.vulExist IN ('存在', '不存在')
//    AND shr.alive = 'true' AND shr.expire_time > CURRENT_TIMESTAMP
//    ORDER BY ip, port_id;
//)").execute();
//        // 使用map临时存储结果，key为IP
//        std::map<std::string, IpVulnerabilities> ip_vulns_map;
//        // 处理查询结果
//         // 用于统计结果数量
//        int resultCount = 0;
//        for (auto row : result) {
//			resultCount++;
//            std::string ip = row[0].get<std::string>();
//            // 如果这个IP还没有记录，创建新记录
//            if (ip_vulns_map.find(ip) == ip_vulns_map.end()) {
//                ip_vulns_map[ip] = IpVulnerabilities{ ip };
//            }
//            // 创建漏洞信息对象
//            std::string vuln_type = row[7].get<std::string>();
//			std::cout << vuln_type << std::endl;
//            if (vuln_type == "主机漏洞") {
//                VulnerabilityInfo vuln;
//                vuln.vuln_id = row[2].get<std::string>();
//                vuln.vuln_name = row[3].get<std::string>();
//                vuln.cvss = row[4].get<std::string>();
//                vuln.summary = row[5].get<std::string>();
//                vuln.vulExist = row[6].get<std::string>();
//                vuln.softwareType = row[8].get<std::string>();    // software_type
//                vuln.vulType = row[9].get<std::string>();         // 从vuln表获取的漏洞类型
//                ip_vulns_map[ip].host_vulnerabilities.push_back(vuln);
//            }
//            else {
//                PortVulnerabilityInfo port_vuln;
//                port_vuln.port_id = row[1].get<int>();
//                port_vuln.vuln_id = row[2].get<std::string>();
//                port_vuln.vuln_name = row[3].get<std::string>();
//                port_vuln.cvss = row[4].get<std::string>();
//                port_vuln.summary = row[5].get<std::string>();
//                port_vuln.vulExist = row[6].get<std::string>();
//                port_vuln.softwareType = row[8].get<std::string>(); // software_type
//                port_vuln.vulType = row[9].get<std::string>();      // 从vuln表获取的漏洞类型
//                port_vuln.service_name = row[10].get<std::string>(); // 新增：service_name
//                ip_vulns_map[ip].port_vulnerabilities.push_back(port_vuln);
//            }
//        }
//        // 输出查询结果的总数量
//        std::cout << "查询结果总数量: " << resultCount << std::endl;
//        // 将map转换为vector返回
//        std::vector<IpVulnerabilities> result_vector;
//        for (const auto& pair : ip_vulns_map) {
//            result_vector.push_back(pair.second);
//        }
//        return result_vector;
//    }
//    catch (const mysqlx::Error& err) {
//        std::cerr << "数据库错误: " << err.what() << std::endl;
//    }
//    catch (std::exception& ex) {
//        std::cerr << "异常: " << ex.what() << std::endl;
//    }
//    catch (...) {
//        std::cerr << "未知错误发生" << std::endl;
//    }
//    
//}

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
                "INSERT INTO vuln (vuln_id, vul_name, script, CVSS, summary, vuln_type) "
                "VALUES (?, ?, ?, ?, ?, ?) "
                "ON DUPLICATE KEY UPDATE vul_name = VALUES(vul_name), "
                "script = VALUES(script), CVSS = VALUES(CVSS), "
                "summary = VALUES(summary), vuln_type = VALUES(vuln_type)"
            )
                .bind(
                    vuln.Vuln_id,
                    vuln.vul_name,
                    vuln.script.empty() ? "" : vuln.script,  // 插入 NULL 或脚本名称
                    vuln.CVSS,
                    vuln.summary.empty() ? "" : vuln.summary,  // 插入 NULL 或漏洞描述
                    vuln.vulnType.empty() ? "" : vuln.vulnType  // 插入 NULL 或漏洞类型
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

void DatabaseHandler::insertAliveHosts(const std::vector<std::string>& aliveHosts, ConnectionPool& pool)
{
    try {
        auto conn = pool.getConnection();  // 获取连接
        for (const auto& ip : aliveHosts) {
            conn->sql(
                "INSERT INTO alive_hosts (ip_address, create_time, update_time) "
                "VALUES (?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP) "
                "ON DUPLICATE KEY UPDATE "
                "ip_address = VALUES(ip_address), "
                "update_time = CURRENT_TIMESTAMP"
            )
                .bind(ip)
                .execute();
            std::cout << "成功插入或更新存活主机: " << ip << std::endl;
        }
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "数据库错误: " << err.what() << std::endl;
    }
}

void DatabaseHandler::insertAliveHosts2scanHostResult(const std::vector<std::string>& aliveHosts, ConnectionPool& pool)
{
    try {
        auto conn = pool.getConnection();  // 获取连接
        for (const auto& ip : aliveHosts) {
            conn->sql(
                "INSERT INTO scan_host_result (ip, scan_time, alive, expire_time) "
                "VALUES (?, CURRENT_TIMESTAMP, 'true', DATE_ADD(CURRENT_TIMESTAMP, INTERVAL 7 DAY)) "
                "ON DUPLICATE KEY UPDATE "
                "scan_time = CURRENT_TIMESTAMP, "
                "alive = 'true', "
                "expire_time = DATE_ADD(CURRENT_TIMESTAMP, INTERVAL 7 DAY)"
            )
                .bind(ip)
                .execute();
            std::cout << "成功插入或更新存活主机: " << ip << std::endl;
        }
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "数据库错误: " << err.what() << std::endl;
    }
}

void DatabaseHandler::readAliveHosts(std::vector<std::string>& aliveHosts, ConnectionPool& pool)
{
    try {
        auto conn = pool.getConnection();  // 获取连接
        mysqlx::SqlResult result = conn->sql(
            "SELECT ip FROM scan_host_result "
            "WHERE alive = 'true' AND expire_time > CURRENT_TIMESTAMP"
        ).execute();

        for (auto row : result) {
            aliveHosts.push_back(row[0].get<std::string>());
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

void DatabaseHandler::updateAliveHosts(std::string aliveHost, ConnectionPool& pool)
{
	try {
		auto conn = pool.getConnection();  // 获取连接
		conn->sql(
			"UPDATE scan_host_result SET "
			"alive = 'false' "
			"WHERE ip = ?"
		)
			.bind(aliveHost)
			.execute();
		std::cout << "成功更新存活主机: " << aliveHost << std::endl;
	}
	catch (const mysqlx::Error& err) {
		std::cerr << "数据库错误: " << err.what() << std::endl;
	}
}

