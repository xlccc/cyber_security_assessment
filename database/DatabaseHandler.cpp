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
            //std::cout << "尝试插入或更新操作系统信息: " << os_version << std::endl;
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

            //std::cout << "成功插入或更新端口信息: 端口 " << port.portId
                //<< ", 协议 " << port.protocol << std::endl;
        }
        //修改为先插入cpe，这样就可以获取cpe_id。剩下三个表与cpe_id有关联
        //(3)插入cpe表
        processHostCpe(scanHostResult, shr_id, pool);

        //(4)插入vuln表, 添加了cpe_id字段
        processVulns(scanHostResult, pool);
        //(5)插入host_vuln_result表
        //目前已有shr_id
        processHostVulns(scanHostResult, shr_id, pool);
        //(6)插入port_vuln_result表
        processPortVulns(scanHostResult, shr_id, pool);



    }
    catch (const mysqlx::Error& err) {
        std::cerr << "executeUpdateOrInsert时数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }

}


//void DatabaseHandler::processHostVulns(const ScanHostResult& hostResult, const int shr_id, ConnectionPool& pool)
//{    
//
//    // 遍历主机级别的 cpes，并插入其中的漏洞
//    for (const auto& [cpe, vulns] : hostResult.cpes) {
//         //获取vector<Vuln> vulns
//        std::cout << "处理 CPE: " << cpe << std::endl;
//        insertHostVulnResult(vulns, shr_id, pool);
//    }
//
//}

void DatabaseHandler::processPortVulns(const ScanHostResult& hostResult, const int shr_id, ConnectionPool& pool)
{
    // 遍历每个端口，并从端口的 cpes 中提取漏洞
    for (const auto& port : hostResult.ports) {
        //std::cout << "处理端口: " << port.portId << std::endl;
        for (const auto& [cpe, vulns] : port.cpes) {
            //std::cout << "处理 CPE: " << cpe << " (端口 " << port.portId << ")" << std::endl;

            //由端口号去得到open_port的主键
            insertPortVulnResult(vulns, shr_id, port.portId, pool);
        }
    }

}

void DatabaseHandler::alterVulnsAfterPocSearch(ConnectionPool& pool, const Vuln& vuln)
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
        std::cerr << "alterVulnsAfterPocSearch时数据库错误: " << err.what() << std::endl;
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

        // 先检查vuln表中是否存在该漏洞
        auto checkResult = conn->sql("SELECT id, vuln_type FROM vuln WHERE vuln_id = ?")
            .bind(vuln_id).execute();

        int vuln_id_primary = 0;
        std::string existing_vuln_type;

        // 如果不存在，则插入
        if (checkResult.count() == 0) {
            auto insertResult = conn->sql(
                "INSERT INTO vuln (vuln_id, vul_name, script, CVSS, summary, vuln_type) "
                "VALUES (?, ?, ?, ?, ?, ?)")
                .bind(
                    vuln.Vuln_id,
                    vuln.vul_name,
                    vuln.script.empty() ? "" : vuln.script,
                    vuln.CVSS,
                    vuln.summary.empty() ? "" : vuln.summary,
                    vuln.vulnType.empty() ? "" : vuln.vulnType
                )
                .execute();

            vuln_id_primary = insertResult.getAutoIncrementValue();
        }
        else {
            // 获取已存在漏洞的ID 和 vuln_type
            mysqlx::Row row = checkResult.fetchOne();
            vuln_id_primary = row[0].get<int>();
            existing_vuln_type = row[1].get<std::string>();

            // **更新漏洞类型**
            if (!vuln.vulnType.empty() && existing_vuln_type != vuln.vulnType) {
                conn->sql("UPDATE vuln SET vuln_type = ? WHERE id = ?")
                    .bind(vuln.vulnType, vuln_id_primary).execute();
            }
        }

        // 现在查询对应的host_vuln_result记录
        auto result = conn->sql("SELECT shr.id FROM scan_host_result shr WHERE shr.ip = ?")
            .bind(ip).execute();

        mysqlx::Row hostRow = result.fetchOne();
        if (!hostRow) {
            return;
        }

        int shr_id = hostRow[0].get<int>();

        // 检查 host_vuln_result 是否已存在该记录
        auto checkHvrResult = conn->sql("SELECT COUNT(*) FROM host_vuln_result WHERE shr_id = ? AND vuln_id = ?")
            .bind(shr_id, vuln_id_primary).execute();

        mysqlx::Row countRow = checkHvrResult.fetchOne();
        int count = countRow[0].get<int>();

        if (count == 0) {
            // 不存在则插入新记录
            conn->sql("INSERT INTO host_vuln_result (shr_id, vuln_id, vulExist) VALUES (?, ?, ?)")
                .bind(shr_id, vuln_id_primary, vulExist).execute();
        }
        else {
            // 存在则更新 vulExist
            conn->sql("UPDATE host_vuln_result SET vulExist = ? WHERE shr_id = ? AND vuln_id = ?")
                .bind(vulExist, shr_id, vuln_id_primary).execute();
        }
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "alterHostVulnResultAfterPocVerify数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
    }
}



//void DatabaseHandler::alterPortVulnResultAfterPocVerify(ConnectionPool& pool, const Vuln& vuln, std::string ip, std::string portId)
//{
//    try {
//        auto conn = pool.getConnection();
//        std::string vulExist = vuln.vulExist;
//        std::string vuln_id = vuln.Vuln_id;
//
//        // 修改查询语句,添加 open_ports 表中 shr_id 的匹配条件
//        auto result = conn->sql("SELECT pvr.shr_id, op.id AS port_id, v.id AS vuln_id "
//            "FROM port_vuln_result pvr "
//            "JOIN scan_host_result shr ON pvr.shr_id = shr.id "
//            "JOIN open_ports op ON pvr.port_id = op.id AND op.shr_id = pvr.shr_id "  // 增加 shr_id 匹配
//            "JOIN vuln v ON pvr.vuln_id = v.id "
//            "WHERE shr.ip = ? AND v.vuln_id = ? AND op.port = ?"
//        ).bind(ip, vuln_id, portId).execute();
//
//        // 获取查询结果
//        for (auto row : result) {
//            int shr_id = row[0].get<int>();          // port_vuln_result 表中的 shr_id
//            int port_id_primary = row[1].get<int>();  // open_ports 表中的主键 id
//            int vuln_id_primary = row[2].get<int>();  // vuln 表中的主键 id
//
//            // 更新 port_vuln_result 表中的 vulExist 字段
//            conn->sql("UPDATE port_vuln_result SET "
//                "vulExist = ? "
//                "WHERE shr_id = ? AND port_id = ? AND vuln_id = ?"
//            ).bind(vulExist, shr_id, port_id_primary, vuln_id_primary).execute();
//        }
//    }
//    catch (const mysqlx::Error& err) {
//        std::cerr << "alterPortVulnResultAfterPocVerify时数据库错误: " << err.what() << std::endl;
//    }
//    catch (std::exception& ex) {
//        std::cerr << "异常: " << ex.what() << std::endl;
//    }
//    catch (...) {
//        std::cerr << "未知错误发生" << std::endl;
//    }
//}

void DatabaseHandler::alterPortVulnResultAfterPocVerify(ConnectionPool& pool, const Vuln& vuln, std::string ip, std::string portId)
{
    try {
        std::cout << "===============================================" << std::endl;
        std::cout << "【开始】更新漏洞验证结果" << std::endl;
        std::cout << "IP: " << ip << " | 端口: " << portId << " | 漏洞ID: " << vuln.Vuln_id << std::endl;
        std::cout << "期望设置的vulExist值: " << vuln.vulExist << std::endl;
        std::cout << "===============================================" << std::endl;

        auto conn = pool.getConnection();
        std::string vulExist = vuln.vulExist;
        std::string vuln_id = vuln.Vuln_id;

        // 1. 先检查vuln表中是否存在该漏洞
        std::cout << "\n【步骤1】检查漏洞信息是否存在" << std::endl;
        auto checkResult = conn->sql("SELECT id, vuln_type FROM vuln WHERE vuln_id = ?")
            .bind(vuln_id).execute();
        int vuln_id_primary = 0;
        std::string existing_vuln_type;

        // 如果不存在，则插入
        if (checkResult.count() == 0) {
            std::cout << "  ✗ 漏洞信息不存在，正在插入新漏洞记录..." << std::endl;
            auto insertResult = conn->sql(
                "INSERT INTO vuln (vuln_id, vul_name, script, CVSS, summary, vuln_type) "
                "VALUES (?, ?, ?, ?, ?, ?)")
                .bind(
                    vuln.Vuln_id,
                    vuln.vul_name,
                    vuln.script.empty() ? "" : vuln.script,
                    vuln.CVSS,
                    vuln.summary.empty() ? "" : vuln.summary,
                    vuln.vulnType.empty() ? "" : vuln.vulnType
                )
                .execute();
            vuln_id_primary = insertResult.getAutoIncrementValue();
            std::cout << "  ✓ 新漏洞记录已插入，ID: " << vuln_id_primary << std::endl;
        }
        else {
            // 获取已存在漏洞的ID和类型
            mysqlx::Row row = checkResult.fetchOne();
            vuln_id_primary = row[0].get<int>();
            existing_vuln_type = row[1].get<std::string>();
            std::cout << "  ✓ 漏洞记录已存在，ID: " << vuln_id_primary << ", 现有类型: " << existing_vuln_type << std::endl;

            // 更新漏洞类型逻辑
            if (!vuln.vulnType.empty() && existing_vuln_type != vuln.vulnType) {
                std::cout << "    > 更新漏洞类型为: " << vuln.vulnType << std::endl;
                auto updateTypeResult = conn->sql("UPDATE vuln SET vuln_type = ? WHERE id = ?")
                    .bind(vuln.vulnType, vuln_id_primary)
                    .execute();
                std::cout << "    > 漏洞类型更新" << (updateTypeResult.getAffectedItemsCount() > 0 ? "成功" : "失败") << std::endl;
            }
        }

        // 2. 获取主机和端口信息
        std::cout << "\n【步骤2】查询主机和端口信息" << std::endl;
        auto hostPortResult = conn->sql(
            "SELECT shr.id AS shr_id, op.id AS port_id "
            "FROM scan_host_result shr "
            "JOIN open_ports op ON shr.id = op.shr_id "
            "WHERE shr.ip = ? AND op.port = ?")
            .bind(ip, portId).execute();

        if (hostPortResult.count() == 0) {
            std::cout << "  ✗ 错误: 未找到对应的主机或端口记录!" << std::endl;
            std::cout << "===============================================" << std::endl;
            std::cout << "【结束】漏洞验证结果更新失败 - 找不到主机或端口信息" << std::endl;
            std::cout << "===============================================" << std::endl;
            return;
        }

        mysqlx::Row hostPortRow = hostPortResult.fetchOne();
        int shr_id = hostPortRow[0].get<int>();
        int port_id_primary = hostPortRow[1].get<int>();
        std::cout << "  ✓ 找到主机记录ID: " << shr_id << ", 端口记录ID: " << port_id_primary << std::endl;

        // 3. 检查port_vuln_result是否已存在该记录
        std::cout << "\n【步骤3】检查端口漏洞关联记录" << std::endl;
        auto checkPvrResult = conn->sql(
            "SELECT COUNT(*) FROM port_vuln_result "
            "WHERE shr_id = ? AND port_id = ? AND vuln_id = ?")
            .bind(shr_id, port_id_primary, vuln_id_primary).execute();
        mysqlx::Row countRow = checkPvrResult.fetchOne();
        int count = countRow[0].get<int>();

        // 4. 根据检查结果插入或更新数据
        std::cout << "\n【步骤4】" << (count == 0 ? "插入" : "更新") << "端口漏洞关联记录" << std::endl;
        if (count == 0) {
            std::cout << "  > 端口漏洞关联记录不存在，正在插入新记录..." << std::endl;
            std::cout << "  > 将插入记录: shr_id=" << shr_id << ", port_id=" << port_id_primary
                << ", vuln_id=" << vuln_id_primary << ", vulExist=" << vulExist << std::endl;

            auto insertResult = conn->sql(
                "INSERT INTO port_vuln_result (shr_id, port_id, vuln_id, vulExist) "
                "VALUES (?, ?, ?, ?)")
                .bind(shr_id, port_id_primary, vuln_id_primary, vulExist).execute();

            std::cout << "  " << (insertResult.getAffectedItemsCount() > 0 ? "✓" : "✗")
                << " 插入操作" << (insertResult.getAffectedItemsCount() > 0 ? "成功" : "失败")
                << "，受影响行数: " << insertResult.getAffectedItemsCount() << std::endl;
        }
        else {
            // 先查询当前值
            auto currentValueResult = conn->sql(
                "SELECT vulExist FROM port_vuln_result "
                "WHERE shr_id = ? AND port_id = ? AND vuln_id = ?")
                .bind(shr_id, port_id_primary, vuln_id_primary).execute();

            std::string currentValue = currentValueResult.fetchOne()[0].get<std::string>();
            std::cout << "  > 端口漏洞关联记录已存在，当前vulExist值: " << currentValue << std::endl;

            if (currentValue == vulExist) {
                std::cout << "  ✓ 当前值与期望值相同，无需更新" << std::endl;
            }
            else {
                std::cout << "  > 正在更新vulExist从 " << currentValue << " 到 " << vulExist << std::endl;
                auto updateResult = conn->sql(
                    "UPDATE port_vuln_result SET vulExist = ? "
                    "WHERE shr_id = ? AND port_id = ? AND vuln_id = ?")
                    .bind(vulExist, shr_id, port_id_primary, vuln_id_primary).execute();

                // 检查更新是否成功
                int affectedRows = updateResult.getAffectedItemsCount();
                std::cout << "  > 更新操作已执行，受影响行数: " << affectedRows << std::endl;

                if (affectedRows > 0) {
                    // 读取更新后的值，进行验证
                    auto verifyResult = conn->sql(
                        "SELECT vulExist FROM port_vuln_result "
                        "WHERE shr_id = ? AND port_id = ? AND vuln_id = ?")
                        .bind(shr_id, port_id_primary, vuln_id_primary).execute();

                    if (verifyResult.count() > 0) {
                        std::string updatedValue = verifyResult.fetchOne()[0].get<std::string>();
                        std::cout << "  > 验证结果: 更新后的vulExist值为: " << updatedValue << std::endl;
                        std::cout << "  " << (updatedValue == vulExist ? "✓ 更新成功" : "✗ 更新失败") << std::endl;
                    }
                }
                else {
                    std::cout << "  ✗ 更新失败，没有行被修改" << std::endl;
                }
            }
        }

        // 5. 提交事务
        std::cout << "\n【步骤5】提交事务" << std::endl;
        conn->commit();  // 显式提交事务
        std::cout << "  ✓ 事务已提交" << std::endl;

        std::cout << "===============================================" << std::endl;
        std::cout << "【结束】漏洞验证结果更新过程完成" << std::endl;
        std::cout << "===============================================" << std::endl;
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "===============================================" << std::endl;
        std::cerr << "【错误】alterPortVulnResultAfterPocVerify时数据库错误:" << std::endl;
        std::cerr << err.what() << std::endl;
        std::cerr << "===============================================" << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "===============================================" << std::endl;
        std::cerr << "【异常】" << ex.what() << std::endl;
        std::cerr << "===============================================" << std::endl;
    }
    catch (...) {
        std::cerr << "===============================================" << std::endl;
        std::cerr << "【错误】未知错误发生" << std::endl;
        std::cerr << "===============================================" << std::endl;
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
                "WHERE shr.ip = ? AND v.vuln_id = ? AND op.port = ?"
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
        std::cerr << "alterVulnAfterPocTask时数据库错误: " << err.what() << std::endl;
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
        //std::cout << "正在查询主机漏洞..." << std::endl;
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
        // std::cout << "主机漏洞查询完成，找到 " << hostVulnCount << " 个结果" << std::endl;

         // 2. 再查询端口漏洞
         //std::cout << "正在查询端口漏洞..." << std::endl;
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
        //std::cout << "端口漏洞查询完成，找到 " << portVulnCount << " 个结果" << std::endl;

        // 统计总结果
        int totalIPs = ip_vulns_map.size();
        int totalHostVulns = 0;
        int totalPortVulns = 0;
        for (const auto& pair : ip_vulns_map) {
            totalHostVulns += pair.second.host_vulnerabilities.size();
            totalPortVulns += pair.second.port_vulnerabilities.size();
        }

        //std::cout << "总IP数: " << totalIPs << std::endl;
        //std::cout << "总主机漏洞数: " << totalHostVulns << std::endl;
        //std::cout << "总端口漏洞数: " << totalPortVulns << std::endl;

        // 将map转换为vector返回
        std::vector<IpVulnerabilities> result_vector;
        for (const auto& pair : ip_vulns_map) {
            result_vector.push_back(pair.second);
        }
        return result_vector;
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "getVulnerabilities时数据库错误: " << err.what() << std::endl;
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

void DatabaseHandler::processHostCpe(const ScanHostResult& hostResult, const int shr_id, ConnectionPool& pool)
{
    std::set<std::string> all_cpes = extractAllCPEs(hostResult);
    insertHostCPEs(shr_id, all_cpes, pool);
}


//void DatabaseHandler::insertHostVulnResult(const std::vector<Vuln>& vulns, const int shr_id, ConnectionPool& pool)
//{
//    try {
//
//
//        auto conn = pool.getConnection();  // 获取连接
//
//        
//        // 2. 遍历 vector<Vuln>，逐个查询主键 ID
//        for (const auto& vuln : vulns) {
//            //这里的vuln_id是cve编号
//            mysqlx::SqlResult result = conn->sql(
//                "SELECT id FROM vuln WHERE vuln_id = ? "
//            ).bind(vuln.Vuln_id).execute();
//
//            // 如果查询到结果，获取主键 ID
//            if (result.count() > 0) {
//                mysqlx::Row row = result.fetchOne();
//                int vuln_id = row[0].get<int>();
//
//
//                //有了vuln_id 和shr_id
//                conn->sql(
//                    "INSERT INTO host_vuln_result (shr_id, vuln_id, vulExist) "
//                    "VALUES (?, ?, '未验证') "
//                    "ON DUPLICATE KEY UPDATE vulExist = '未验证'"
//                )
//                .bind(shr_id, vuln_id)
//                .execute();
//                
//            }
//            else {
//                std::cerr << "未找到漏洞: " << vuln.vul_name << std::endl;
//            }
//        }
//
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

//void DatabaseHandler::insertPortVulnResult(const std::vector<Vuln>& vulns, const int shr_id, const std::string port, ConnectionPool& pool)
//{
//    try {
//        auto conn = pool.getConnection();  // 获取连接
//
//
//
//        mysqlx::SqlResult resultPortId = conn->sql(
//            "SELECT id FROM open_ports WHERE port = ? "
//        ).bind(std::stoi(port)).execute();
//        mysqlx::Row row = resultPortId.fetchOne();
//        int port_id = row[0].get<int>();
//
//        // 2. 遍历 vector<Vuln>，逐个查询主键 ID
//        for (const auto& vuln : vulns) {
//            //这里的vuln_id是cve编号
//            mysqlx::SqlResult result = conn->sql(
//                "SELECT id FROM vuln WHERE vuln_id = ? "
//            ).bind(vuln.Vuln_id).execute();
//
//            // 如果查询到结果，获取主键 ID
//            if (result.count() > 0) {
//                mysqlx::Row row = result.fetchOne();
//                int vuln_id = row[0].get<int>();
//
//
//                //有了vuln_id 和shr_id 和port_id
//                conn->sql(
//                    "INSERT INTO port_vuln_result (shr_id, port_id, vuln_id, vulExist) "
//                    "VALUES (?, ?, ?, '未验证') "
//                    "ON DUPLICATE KEY UPDATE vulExist = '未验证'"
//                )
//                    .bind(shr_id, port_id, vuln_id)
//                    .execute();
//
//            }
//        }
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
//}

std::set<std::string> DatabaseHandler::extractAllCPEs(const ScanHostResult& hostResult)
{

    std::set<std::string> all_cpes;

    // 1. 遍历主机级别的 cpes
    for (const auto& [cpe, vulns] : hostResult.cpes) {
        all_cpes.insert(cpe);
        //std::cout << "找到主机级 CPE: " << cpe << std::endl;
    }

    // 2. 遍历每个端口的 cpes
    for (const auto& port : hostResult.ports) {
        for (const auto& [cpe, vulns] : port.cpes) {
            all_cpes.insert(cpe);
            //std::cout << "找到端口 " << port.portId << " 的 CPE: " << cpe << std::endl;
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

            //std::cout << "成功插入或更新 CPE: " << cpe << std::endl;
        }
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "insertHostCPEs时数据库错误: " << err.what() << std::endl;
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
            //std::cout << "成功插入或更新存活主机: " << ip << std::endl;
        }
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "insertAliveHosts时数据库错误: " << err.what() << std::endl;
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
            //std::cout << "成功插入或更新存活主机: " << ip << std::endl;
        }
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "insertAliveHosts2scanHostResult时数据库错误: " << err.what() << std::endl;
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
		std::cerr << "readAliveHosts时数据库错误: " << err.what() << std::endl;
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
		//std::cout << "成功更新存活主机: " << aliveHost << std::endl;
	}
	catch (const mysqlx::Error& err) {
		std::cerr << "updateAliveHosts时数据库错误: " << err.what() << std::endl;
	}
}

void DatabaseHandler::processVulns(const ScanHostResult& hostResult, ConnectionPool& pool)
{
    // 获取 scan_host_result 的 ID
    int shr_id = 0;
    try {
        auto conn = pool.getConnection();
        mysqlx::SqlResult result = conn->sql("SELECT id FROM scan_host_result WHERE ip = ?")
            .bind(hostResult.ip)
            .execute();

        // 正确处理结果集
        mysqlx::Row row = result.fetchOne();
        if (row) {
            shr_id = row[0];  // 直接访问列
        }
        else {
            std::cerr << "找不到IP为 " << hostResult.ip << " 的主机记录" << std::endl;
            return;
        }
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "获取主机ID时数据库错误: " << err.what() << std::endl;
        return;
    }

    // 遍历主机级别的 cpes，并插入其中的漏洞
    for (const auto& cpe_entry : hostResult.cpes) {
        const std::string& cpe = cpe_entry.first;
        const std::vector<Vuln>& vulns = cpe_entry.second;

        //std::cout << "处理 CPE: " << cpe << std::endl;

        // 查询已存在的 CPE 记录
        int cpe_id = getCpeId(shr_id, cpe, pool);
        if (cpe_id != 0) {
            // 传入 cpe_id 插入漏洞
            insertVulns(vulns, pool, cpe_id);
        }
        else {
            //std::cout << "找不到对应的 CPE 记录: " << cpe << "，跳过相关漏洞" << std::endl;
            // 如果确实需要，可以在没有 cpe_id 的情况下插入漏洞
            insertVulns(vulns, pool, 0);
        }
    }

    // 遍历每个端口，并从端口的 cpes 中提取漏洞
    for (const auto& port : hostResult.ports) {
        std::cout << "处理端口: " << port.portId << std::endl;

        for (const auto& cpe_entry : port.cpes) {
            const std::string& cpe = cpe_entry.first;
            const std::vector<Vuln>& vulns = cpe_entry.second;

            //std::cout << "处理 CPE: " << cpe << " (端口 " << port.portId << ")" << std::endl;

            // 查询已存在的 CPE 记录
            int cpe_id = getCpeId(shr_id, cpe, pool);
            if (cpe_id != 0) {
                // 传入 cpe_id 插入漏洞
                insertVulns(vulns, pool, cpe_id);
            }
            else {
                //std::cout << "找不到对应的 CPE 记录: " << cpe << "，跳过相关漏洞" << std::endl;
                // 如果确实需要，可以在没有 cpe_id 的情况下插入漏洞
                insertVulns(vulns, pool, 0);
            }
        }
    }
}

int DatabaseHandler::getCpeId(int shr_id, const std::string& cpe, ConnectionPool& pool)
{
    try {
        auto conn = pool.getConnection();

        // 查询 host_cpe 表中匹配的 CPE 记录
        mysqlx::SqlResult result = conn->sql("SELECT id FROM host_cpe WHERE shr_id = ? AND cpe = ?")
            .bind(shr_id, cpe)
            .execute();

        // 正确处理结果集
        mysqlx::Row row = result.fetchOne();
        if (row) {
            return row[0];  // 直接返回第一列
        }
        else {
            return 0; // 未找到匹配的 CPE 记录
        }
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "查询 CPE ID 时数据库错误: " << err.what() << std::endl;
        return 0;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
        return 0;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
        return 0;
    }
}

void DatabaseHandler::insertVulns(const std::vector<Vuln>& vulns, ConnectionPool& pool, int cpe_id)
{
    try {
        auto conn = pool.getConnection();  // 获取连接

        // 遍历 vuln_result 集合，逐条插入 vuln 表
        for (const auto& vuln : vulns) {
            //std::cout << "插入或更新漏洞: " << vuln.vul_name << std::endl;

            // 根据是否有 cpe_id 使用不同的 SQL
            if (cpe_id != 0) {
                conn->sql(
                    "INSERT INTO vuln (vuln_id, vul_name, script, CVSS, summary, vuln_type, cpe_id) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?) "
                    "ON DUPLICATE KEY UPDATE vul_name = VALUES(vul_name), "
                    "script = VALUES(script), CVSS = VALUES(CVSS), "
                    "summary = VALUES(summary), vuln_type = VALUES(vuln_type), "
                    "cpe_id = VALUES(cpe_id)"
                )
                    .bind(
                        vuln.Vuln_id,
                        vuln.vul_name,
                        vuln.script.empty() ? "" : vuln.script,
                        vuln.CVSS,
                        vuln.summary.empty() ? "" : vuln.summary,
                        vuln.vulnType.empty() ? "" : vuln.vulnType,
                        cpe_id
                    )
                    .execute();
            }
            else {
                // 没有 cpe_id 的情况下，不设置该字段
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
                        vuln.script.empty() ? "" : vuln.script,
                        vuln.CVSS,
                        vuln.summary.empty() ? "" : vuln.summary,
                        vuln.vulnType.empty() ? "" : vuln.vulnType
                    )
                    .execute();
            }
        }
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "insertVulns时数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
    }
}

void DatabaseHandler::processHostVulns(const ScanHostResult& hostResult, const int shr_id, ConnectionPool& pool)
{
    // 遍历主机级别的 cpes，并插入其中的漏洞
    for (const auto& [cpe, vulns] : hostResult.cpes) {
        std::cout << "处理 CPE: " << cpe << std::endl;
        // 处理该CPE下的所有漏洞
        for (const auto& vuln : vulns) {
            // 先根据漏洞ID获取vuln表中的记录ID
            int vuln_id = getVulnIdByVulnId(vuln.Vuln_id, pool);
            if (vuln_id != 0) {
                // 直接从vuln表获取cpe_id
                int cpe_id = getCpeIdFromVuln(vuln_id, pool);
                std::cout << vuln.Vuln_id << "对应的cpe_id为" << cpe_id << std::endl;
                // 插入host_vuln_result记录
                if (cpe_id != 0) {
                    // 有关联的cpe_id
                    insertHostVulnResult(vuln, shr_id, vuln_id, cpe_id, pool);
                }
                else {
                    //std::cout << "漏洞 " << vuln.Vuln_id << " 没有关联的cpe_id" << std::endl;
                    // 不关联cpe_id插入漏洞记录
                    insertHostVulnResult(vuln, shr_id, vuln_id, 0, pool);
                }
            }
            else {
                //std::cout << "找不到漏洞记录: " << vuln.Vuln_id << std::endl;
            }
        }
    }
}

// 根据漏洞ID字符串(CVE-XXXX-XXXX格式)获取vuln表中的记录ID
int DatabaseHandler::getVulnIdByVulnId(const std::string& vuln_id_str, ConnectionPool& pool)
{
    try {
        auto conn = pool.getConnection();
        mysqlx::SqlResult result = conn->sql("SELECT id FROM vuln WHERE vuln_id = ?")
            .bind(vuln_id_str)
            .execute();
        mysqlx::Row row = result.fetchOne();
        if (row) {
            return row[0];  // 直接访问列
        }
        else {
            return 0; // 未找到匹配的记录
        }
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "查询漏洞ID时数据库错误: " << err.what() << std::endl;
        return 0;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
        return 0;
    }
}

// 插入单条host_vuln_result记录
void DatabaseHandler::insertHostVulnResult(const Vuln& vuln, int shr_id, int vuln_id, int cpe_id, ConnectionPool& pool)
{
    try {
        auto conn = pool.getConnection();
        conn->sql("INSERT INTO host_vuln_result (shr_id, vuln_id, vulExist, cpe_id) VALUES (?, ?, ?, ?) "
            "ON DUPLICATE KEY UPDATE vulExist = ?, cpe_id = ?")
            .bind(shr_id, vuln_id, vuln.vulExist, cpe_id, vuln.vulExist, cpe_id)
            .execute();
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "插入主机漏洞关联记录时数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
    }
}



std::vector<PortInfo> DatabaseHandler::getAllPortInfoByIp(const std::string& ip, ConnectionPool& pool)
{
    std::vector<PortInfo> portInfoList;
    try {
        auto conn = pool.getConnection();
        // 首先查询scan_host_result表获取shr_id
        mysqlx::SqlResult hostResult = conn->sql("SELECT id FROM scan_host_result WHERE ip = ?")
            .bind(ip)
            .execute();
        mysqlx::Row hostRow = hostResult.fetchOne();
        if (!hostRow) {
            std::cerr << "未找到IP: " << ip << " 对应的扫描记录" << std::endl;
            return portInfoList;
        }
        int shr_id = hostRow[0]; // 获取shr_id
        mysqlx::SqlResult portResult = conn->sql(
            "SELECT port, protocol, status, service_name, product, version, software_type, "
            "weak_username, weak_password, password_verified, "
            "DATE_FORMAT(verify_time, '%Y-%m-%d %H:%i:%s') as formatted_verify_time "
            "FROM open_ports "
            "WHERE shr_id = ?")
            .bind(shr_id)
            .execute();
        while (mysqlx::Row portRow = portResult.fetchOne()) {
            PortInfo portInfo;
            portInfo.ip = ip;
            portInfo.port = static_cast<int>(portRow[0]);
            portInfo.protocol = static_cast<std::string>(portRow[1]);
            portInfo.status = static_cast<std::string>(portRow[2]);
            portInfo.service_name = static_cast<std::string>(portRow[3]);
            portInfo.product = portRow[4].isNull() ? "" : static_cast<std::string>(portRow[4]);
            portInfo.version = portRow[5].isNull() ? "" : static_cast<std::string>(portRow[5]);
            portInfo.software_type = portRow[6].isNull() ? "" : static_cast<std::string>(portRow[6]);

            // 添加弱口令相关信息
            portInfo.weak_username = portRow[7].isNull() ? "" : static_cast<std::string>(portRow[7]);
            portInfo.weak_password = portRow[8].isNull() ? "" : static_cast<std::string>(portRow[8]);
            portInfo.password_verified = portRow[9].isNull() ? false :
                (static_cast<std::string>(portRow[9]) == "true");
            portInfo.verify_time = portRow[10].isNull() ? "" : static_cast<std::string>(portRow[10]);

            portInfoList.push_back(portInfo);
        }
        if (portInfoList.empty()) {
            std::cerr << "IP: " << ip << " 没有关联的端口信息" << std::endl;
        }
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "获取端口信息时数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
    }
    return portInfoList;
}

int DatabaseHandler::getCpeIdFromVuln(int vuln_id, ConnectionPool& pool)
{
    try {
        auto conn = pool.getConnection();
        // 查询 vuln 表中指定 ID 的漏洞记录的 cpe_id
        mysqlx::SqlResult result = conn->sql("SELECT cpe_id FROM vuln WHERE id = ?")
            .bind(vuln_id)
            .execute();
        // 处理结果集
        mysqlx::Row row = result.fetchOne();
        if (row) {
            return row[0];  // 直接访问列
        }
        else {
            return 0; // 未找到 cpe_id 或值为 NULL
        }
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "查询漏洞 CPE ID 时数据库错误: " << err.what() << std::endl;
        return 0;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
        return 0;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
        return 0;
    }
}

void DatabaseHandler::insertPortVulnResult(const std::vector<Vuln>& vulns, const int shr_id, const std::string port, ConnectionPool& pool)
{
    try {
        auto conn = pool.getConnection();  // 获取连接

        // 获取端口ID
        mysqlx::SqlResult resultPortId = conn->sql("SELECT id FROM open_ports WHERE port = ? AND shr_id = ?")
            .bind(std::stoi(port), shr_id)
            .execute();

        // 检查是否找到对应端口记录
        mysqlx::Row portRow = resultPortId.fetchOne();
        if (!portRow) {
            std::cerr << "未找到端口: " << port << " 对应的记录" << std::endl;
            return;
        }

        int port_id = portRow[0];  // 直接访问列

        // 遍历漏洞列表
        for (const auto& vuln : vulns) {
            // 查询漏洞ID
            int vuln_id = getVulnIdByVulnId(vuln.Vuln_id, pool);

            if (vuln_id != 0) {
                // 从vuln表获取cpe_id
                int cpe_id = getCpeIdFromVuln(vuln_id, pool);

                // 插入或更新port_vuln_result记录
                if (cpe_id != 0) {
                    // 有关联的cpe_id
                    conn->sql("INSERT INTO port_vuln_result (shr_id, port_id, vuln_id, vulExist, cpe_id) VALUES (?, ?, ?, ?, ?) "
                        "ON DUPLICATE KEY UPDATE vulExist = ?, cpe_id = ?")
                        .bind(shr_id, port_id, vuln_id, "未验证", cpe_id, "未验证", cpe_id)
                        .execute();
                }
                else {
                    // 不关联cpe_id
                    conn->sql("INSERT INTO port_vuln_result (shr_id, port_id, vuln_id, vulExist) VALUES (?, ?, ?, ?) "
                        "ON DUPLICATE KEY UPDATE vulExist = ?")
                        .bind(shr_id, port_id, vuln_id, "未验证", "未验证")
                        .execute();
                }
            }
            else {
                std::cerr << "找不到漏洞记录: " << vuln.Vuln_id << std::endl;
            }
        }
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "insertPortVulnResult时数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
    }
}

ScanHostResult DatabaseHandler::getScanHostResult(const std::string& ip, ConnectionPool& pool)
{
    ScanHostResult result;
    result.ip = ip;
    result.is_merged = false;

    try {
        auto conn = pool.getConnection();

        mysqlx::SqlResult hostResult = conn->sql("SELECT id, url, DATE_FORMAT(scan_time, '%Y-%m-%d %H:%i:%s') as formatted_time FROM scan_host_result WHERE ip = ?")
            .bind(ip)
            .execute();

        mysqlx::Row hostRow = hostResult.fetchOne();
        if (!hostRow) {
            std::cerr << "未找到IP: " << ip << " 对应的扫描记录" << std::endl;
            return result;
        }

        int shr_id = hostRow[0]; // 获取shr_id
        result.url = hostRow[1].isNull() ? "" : static_cast<std::string>(hostRow[1]);
        result.scan_time = hostRow[2].get<std::string>();

        // 2. 查询操作系统信息
        mysqlx::SqlResult osResult = conn->sql("SELECT os_version FROM os_info WHERE shr_id = ?")
            .bind(shr_id)
            .execute();

        while (mysqlx::Row osRow = osResult.fetchOne()) {
            std::string os_version = static_cast<std::string>(osRow[0]);
            result.os_matches.push_back(os_version);

            // 提取操作系统类型
            size_t spacePos = os_version.find(' ');
            if (spacePos != std::string::npos) {
                result.os_list.insert(os_version.substr(0, spacePos));
            }
            else {
                result.os_list.insert(os_version);
            }
        }

        if (!result.os_list.empty()) {
            result.os_type = *result.os_list.begin();
        }

        // 3. 查询主机CPE信息
        mysqlx::SqlResult cpeResult = conn->sql("SELECT id, cpe FROM host_cpe WHERE shr_id = ?")
            .bind(shr_id)
            .execute();

        std::map<int, std::string> cpeMap;

        while (mysqlx::Row cpeRow = cpeResult.fetchOne()) {
            int cpe_id = cpeRow[0];
            std::string cpe = static_cast<std::string>(cpeRow[1]);
            cpeMap[cpe_id] = cpe;

            result.cpes[cpe] = std::vector<Vuln>();
        }

        // 4. 查询主机漏洞信息
        mysqlx::SqlResult vulnResult = conn->sql(
            "SELECT hvr.vuln_id, hvr.vulExist, hvr.cpe_id, "
            "v.vuln_id AS cve_id, v.vul_name, v.script, v.CVSS, v.summary, v.vuln_type "
            "FROM host_vuln_result hvr "
            "JOIN vuln v ON hvr.vuln_id = v.id "
            "WHERE hvr.shr_id = ?")
            .bind(shr_id)
            .execute();

        while (mysqlx::Row vulnRow = vulnResult.fetchOne()) {
            int db_vuln_id = vulnRow[0];
            std::string vulExist = static_cast<std::string>(vulnRow[1]);
            int cpe_id = vulnRow[2].isNull() ? 0 : static_cast<int>(vulnRow[2]);

            Vuln vuln;
            vuln.Vuln_id = static_cast<std::string>(vulnRow[3]); // CVE ID
            vuln.vul_name = static_cast<std::string>(vulnRow[4]);
            vuln.script = vulnRow[5].isNull() ? "" : static_cast<std::string>(vulnRow[5]);
            vuln.CVSS = static_cast<std::string>(vulnRow[6]);
            vuln.summary = vulnRow[7].isNull() ? "" : static_cast<std::string>(vulnRow[7]);
            vuln.vulnType = vulnRow[8].isNull() ? "" : static_cast<std::string>(vulnRow[8]);
            vuln.vulExist = vulExist;

            result.vuln_result.insert(vuln);

            if (cpe_id != 0 && cpeMap.find(cpe_id) != cpeMap.end()) {
                std::string cpe = cpeMap[cpe_id];
                result.cpes[cpe].push_back(vuln);
            }
        }

        // 5. 查询端口信息
        mysqlx::SqlResult portResult = conn->sql(
            "SELECT id, port, protocol, status, service_name, product, version, software_type "
            "FROM open_ports "
            "WHERE shr_id = ?")
            .bind(shr_id)
            .execute();

        std::map<int, int> portIdToIndex;

        while (mysqlx::Row portRow = portResult.fetchOne()) {
            int port_id = portRow[0];

            ScanResult scanResult;
            scanResult.portId = std::to_string(static_cast<int>(portRow[1]));
            scanResult.protocol = static_cast<std::string>(portRow[2]);
            scanResult.status = static_cast<std::string>(portRow[3]);
            scanResult.service_name = static_cast<std::string>(portRow[4]);
            scanResult.product = portRow[5].isNull() ? "" : static_cast<std::string>(portRow[5]);
            scanResult.version = portRow[6].isNull() ? "" : static_cast<std::string>(portRow[6]);
            scanResult.softwareType = portRow[7].isNull() ? "" : static_cast<std::string>(portRow[7]);
            scanResult.is_merged = false;

            result.ports.push_back(scanResult);
            portIdToIndex[port_id] = result.ports.size() - 1;
        }

        // 6. 查询端口漏洞信息
        mysqlx::SqlResult portVulnResult = conn->sql(
            "SELECT pvr.port_id, pvr.vuln_id, pvr.vulExist, pvr.cpe_id, "
            "v.vuln_id AS cve_id, v.vul_name, v.script, v.CVSS, v.summary, v.vuln_type, "
            "hc.cpe "
            "FROM port_vuln_result pvr "
            "JOIN vuln v ON pvr.vuln_id = v.id "
            "LEFT JOIN host_cpe hc ON pvr.cpe_id = hc.id "
            "WHERE pvr.shr_id = ?")
            .bind(shr_id)
            .execute();

        while (mysqlx::Row vulnRow = portVulnResult.fetchOne()) {
            int port_id = vulnRow[0];
            int db_vuln_id = vulnRow[1];
            std::string vulExist = static_cast<std::string>(vulnRow[2]);
            int cpe_id = vulnRow[3].isNull() ? 0 : static_cast<int>(vulnRow[3]);

            Vuln vuln;
            vuln.Vuln_id = static_cast<std::string>(vulnRow[4]); // CVE ID
            vuln.vul_name = static_cast<std::string>(vulnRow[5]);
            vuln.script = vulnRow[6].isNull() ? "" : static_cast<std::string>(vulnRow[6]);
            vuln.CVSS = static_cast<std::string>(vulnRow[7]);
            vuln.summary = vulnRow[8].isNull() ? "" : static_cast<std::string>(vulnRow[8]);
            vuln.vulnType = vulnRow[9].isNull() ? "" : static_cast<std::string>(vulnRow[9]);
            vuln.vulExist = vulExist;

            if (portIdToIndex.find(port_id) != portIdToIndex.end()) {
                int portIndex = portIdToIndex[port_id];

                result.ports[portIndex].vuln_result.insert(vuln);

                if (cpe_id != 0 && !vulnRow[10].isNull()) {
                    std::string cpe = static_cast<std::string>(vulnRow[10]);
                    if (result.ports[portIndex].cpes.find(cpe) == result.ports[portIndex].cpes.end()) {
                        result.ports[portIndex].cpes[cpe] = std::vector<Vuln>();
                    }
                    result.ports[portIndex].cpes[cpe].push_back(vuln);
                }
            }
        }
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "获取扫描结果时数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
    }

    return result;
}

// 获取指定IP的完整资产信息
AssetInfo DatabaseHandler::getCompleteAssetInfo(const std::string& ip, ConnectionPool& pool)
{
    AssetInfo assetInfo;
    assetInfo.ip = ip;

    try {
        // 1. 获取该IP的端口信息
        assetInfo.ports = getAllPortInfoByIp(ip, pool);

        // 2. 获取该IP的漏洞信息
        std::vector<std::string> singleIp = { ip };
        std::vector<IpVulnerabilities> vulnerabilities = getVulnerabilities(pool, singleIp);

        // 如果找到了该IP的漏洞信息，则填充到assetInfo中
        if (!vulnerabilities.empty()) {
            const IpVulnerabilities& ipVulns = vulnerabilities[0];
            assetInfo.host_vulnerabilities = ipVulns.host_vulnerabilities;
            assetInfo.port_vulnerabilities = ipVulns.port_vulnerabilities;
        }
    }
    catch (const std::exception& ex) {
        std::cerr << "获取IP资产信息时发生异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "获取IP资产信息时发生未知错误" << std::endl;
    }

    return assetInfo;
}

// 获取所有存活主机的完整资产信息
std::vector<AssetInfo> DatabaseHandler::getAllAssetsInfo(ConnectionPool& pool)
{
    std::vector<AssetInfo> allAssets;

    try {
        // 1. 获取所有存活主机
        std::vector<std::string> alive_hosts;
        readAliveHosts(alive_hosts, pool);

        // 2. 获取所有存活主机的漏洞信息
        std::vector<IpVulnerabilities> allVulnerabilities = getVulnerabilities(pool, alive_hosts);

        // 创建IP到漏洞信息的映射，便于快速查找
        std::map<std::string, IpVulnerabilities> ipToVulnMap;
        for (const auto& ipVuln : allVulnerabilities) {
            ipToVulnMap[ipVuln.ip] = ipVuln;
        }

        // 3. 为每个存活主机获取端口信息并组合数据
        for (const std::string& ip : alive_hosts) {
            AssetInfo assetInfo;
            assetInfo.ip = ip;

            // 获取端口信息
            assetInfo.ports = getAllPortInfoByIp(ip, pool);

            // 获取服务器系统信息
            assetInfo.serverinfo = getServerInfoByIp(ip, pool);

            // 如果有该IP的漏洞信息，则填充到assetInfo中
            if (ipToVulnMap.find(ip) != ipToVulnMap.end()) {
                const IpVulnerabilities& ipVulns = ipToVulnMap[ip];
                assetInfo.host_vulnerabilities = ipVulns.host_vulnerabilities;
                assetInfo.port_vulnerabilities = ipVulns.port_vulnerabilities;
            }
            // 获取该IP的基线检测结果并计算摘要
            std::vector<event> check_results = getSecurityCheckResults(ip, pool);
            std::vector<event> level3_check_results = getLevel3SecurityCheckResults(ip, pool);
            
            assetInfo.baseline_summary = calculateBaselineSummary(check_results);
            assetInfo.level3_baseline_summary = calculateBaselineSummary(level3_check_results);
            //计算等保得分
            // 定义合规等级映射表
            std::unordered_map<std::string, double> complyLevelMapping = {
                {"true", 1.0},
                {"false", 0.0},
                {"half_true", 0.5},
                {"pending", -1.0}  // pending状态可根据需要调整处理方式
            };

            // 计算评分
            int n = level3_check_results.size(); // 项数
            double sum = 0.0;

            // 累加每一项的得分
            for (const auto& item : level3_check_results) {
                double importantLevel = std::stod(item.importantLevel) / 3;

                // 通过映射表获取合规等级
                double complyLevel = 0.0; // 默认值
                auto it = complyLevelMapping.find(item.tmp_IsComply);
                if (it != complyLevelMapping.end()) {
                    complyLevel = it->second;
                }

                // 如果是pending状态，可以选择跳过或者作为不符合处理
                if (complyLevel < 0) {
                    // 如果遇到pending状态，将其视为不符合(0.0)
                    complyLevel = 0.0;
                }

                sum += importantLevel * (1.0 - complyLevel);

                // 输出每一项的计算值用于调试（可选）
                std::cout << "Item " << item.item_id << ": importantLevel = " << importantLevel
                    << ", complyLevel = " << complyLevel
                    << ", contribution = " << importantLevel * (1.0 - complyLevel) << std::endl;
            }

            // 输出总和用于调试
            std::cout << "Total sum: " << sum << std::endl;

            // 计算最终评分
            // 正确的保留两位小数方法
            double temp_score = 100.0 - (100.0 * sum / n);
            assetInfo.M = temp_score > 0 ?
                (round(temp_score * 10000.0) / 100.0) : 0.0;  // 改为10000

            //获取有哪些检测项没做
            assetInfo.undo_BaseLine = getUncheckedBaselineItems(ip, pool);
            //获取有哪些三级等保检测项没做
            assetInfo.undo_level3BaseLine = getUncheckedLevel3Items(ip, pool);
            allAssets.push_back(assetInfo);
        }
    }
    catch (const std::exception& ex) {
        std::cerr << "获取所有资产信息时发生异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "获取所有资产信息时发生未知错误" << std::endl;
    }

    return allAssets;
}

std::vector<std::string> DatabaseHandler::getServiceNameByIp(const std::string& ip, ConnectionPool& pool)
{
    std::vector<std::string> serviceNames;

    try {
        auto conn = pool.getConnection();

        // 首先获取scan_host_result表中的id
        mysqlx::SqlResult hostResult = conn->sql("SELECT id FROM scan_host_result WHERE ip = ?")
            .bind(ip)
            .execute();

        mysqlx::Row hostRow = hostResult.fetchOne();
        if (!hostRow) {
            std::cerr << "未找到IP: " << ip << " 对应的扫描记录" << std::endl;
            return serviceNames;
        }

        int shr_id = hostRow[0]; // 获取shr_id

        // 查询此IP地址对应的所有服务名称
        mysqlx::SqlResult serviceResult = conn->sql(
            "SELECT service_name FROM open_ports WHERE shr_id = ?")
            .bind(shr_id)
            .execute();

        while (mysqlx::Row serviceRow = serviceResult.fetchOne()) {
            std::string serviceName = static_cast<std::string>(serviceRow[0]);
            serviceNames.push_back(serviceName);
        }
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "获取服务名称时数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
    }

    return serviceNames;
}

void DatabaseHandler::saveWeakPasswordResult(
    const std::string& ip,
    int port,
    const std::string& service,
    const std::string& login,
    const std::string& password,
    ConnectionPool& pool)
{
    try {
        auto conn = pool.getConnection();
        // 首先获取scan_host_result表中的id
        mysqlx::SqlResult hostResult = conn->sql("SELECT id FROM scan_host_result WHERE ip = ?")
            .bind(ip)
            .execute();
        mysqlx::Row hostRow = hostResult.fetchOne();
        if (!hostRow) {
            std::cerr << "未找到IP: " << ip << " 对应的扫描记录" << std::endl;
            return;
        }
        int shr_id = hostRow[0]; // 获取shr_id

        // 查找对应的端口记录
        mysqlx::SqlResult portResult = conn->sql("SELECT id FROM open_ports WHERE shr_id = ? AND port = ?")
            .bind(shr_id)
            .bind(port)
            .execute();
        mysqlx::Row portRow = portResult.fetchOne();

        if (portRow) {
            // 如果找到对应的端口记录，则更新
            int port_id = portRow[0];
            conn->sql("UPDATE open_ports SET weak_username = ?, weak_password = ?, password_verified = 'true', verify_time = CURRENT_TIMESTAMP WHERE id = ?")
                .bind(login)
                .bind(password)
                .bind(port_id)
                .execute();
        }
        else {
            // 如果没找到对应的端口记录，则插入
            conn->sql("INSERT INTO open_ports (shr_id, port, protocol, status, service_name, weak_username, weak_password, password_verified, verify_time) VALUES (?, ?, 'tcp', 'open', ?, ?, ?, 'true', CURRENT_TIMESTAMP)")
                .bind(shr_id)
                .bind(port)
                .bind(service)
                .bind(login)
                .bind(password)
                .execute();
        }

        std::cout << "弱口令结果保存成功: " << ip << ":" << port << " - " << login << ":" << password << std::endl;
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "保存弱口令结果时数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
    }
}

void DatabaseHandler::saveLevel3SecurityCheckResult(const std::string& ip, const event& checkEvent, ConnectionPool& pool) {
    try {
        auto conn = pool.getConnection();  // 获取连接
        // 首先获取scan_host_result表中的id
        mysqlx::SqlResult hostResult = conn->sql("SELECT id FROM scan_host_result WHERE ip = ?")
            .bind(ip)
            .execute();
        mysqlx::Row hostRow = hostResult.fetchOne();
        if (!hostRow) {
            std::cerr << "未找到IP: " << ip << " 对应的扫描记录" << std::endl;
            return;
        }
        int shr_id = hostRow[0]; // 获取shr_id
        // 检查该项检查是否已存在
        mysqlx::SqlResult checkResult = conn->sql(
            "SELECT id FROM level3_security_check_results WHERE shr_id = ? AND item_id = ?")
            .bind(shr_id)
            .bind(checkEvent.item_id)
            .execute();
        if (checkResult.count() > 0) {
            // 已存在记录，进行更新
            conn->sql(
                "UPDATE level3_security_check_results SET "
                "description = ?, "
                "basis = ?, "
                "command = ?, "
                "result = ?, "
                "is_comply = ?, "
                "tmp_is_comply = ?, "  // 添加tmp_is_comply字段
                "recommend = ?, "
                "important_level = ?, "
                "check_time = CURRENT_TIMESTAMP "
                "WHERE shr_id = ? AND item_id = ?"
            )
                .bind(checkEvent.description)
                .bind(checkEvent.basis)
                .bind(checkEvent.command)
                .bind(checkEvent.result)
                .bind(checkEvent.IsComply)
                .bind(checkEvent.tmp_IsComply)  // 绑定tmp_IsComply值
                .bind(checkEvent.recommend)
                .bind(checkEvent.importantLevel)
                .bind(shr_id)
                .bind(checkEvent.item_id)
                .execute();
            std::cout << "成功更新安全检查结果: " << checkEvent.description << std::endl;
        }
        else {
            // 不存在记录，进行插入
            conn->sql(
                "INSERT INTO level3_security_check_results "
                "(shr_id, item_id, description, basis, command, result, is_comply, tmp_is_comply, recommend, important_level, check_time) "  // 添加tmp_is_comply字段
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)"
            )
                .bind(shr_id)
                .bind(checkEvent.item_id)
                .bind(checkEvent.description)
                .bind(checkEvent.basis)
                .bind(checkEvent.command)
                .bind(checkEvent.result)
                .bind(checkEvent.IsComply)
                .bind(checkEvent.tmp_IsComply)  // 绑定tmp_IsComply值
                .bind(checkEvent.recommend)
                .bind(checkEvent.importantLevel)
                .execute();
            std::cout << "成功插入安全检查结果: " << checkEvent.description << std::endl;
        }
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "saveSecurityCheckResult时数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
    }
}

void DatabaseHandler::updateLevel3SecurityCheckResult(const std::string& ip, ConnectionPool& pool, std::vector<scoreMeasure> vec_score)
{
    try {
        auto conn = pool.getConnection();  // 获取连接

        // 首先获取scan_host_result表中的id
        mysqlx::SqlResult hostResult = conn->sql("SELECT id FROM scan_host_result WHERE ip = ?")
            .bind(ip)
            .execute();

        mysqlx::Row hostRow = hostResult.fetchOne();
        if (!hostRow) {
            std::cerr << "未找到IP: " << ip << " 对应的扫描记录" << std::endl;
            return;
        }

        int shr_id = hostRow[0]; // 获取shr_id

        // 定义IsComplyLevel到is_comply的映射
        std::unordered_map<std::string, std::string> complyMapping = {
            {"1", "true"},        // 1.0 对应 true
            {"1.0", "true"},      // 1.0 对应 true
            {"0", "false"},       // 0 对应 false
            {"0.0", "false"},     // 0.0 对应 false
            {"0.5", "half_true"}  // 0.5 对应 half_true
        };

        // 遍历所有的评分项
        for (const auto& score : vec_score) {
            // 获取对应的is_comply值
            std::string isComply = "false"; // 默认值
            auto it = complyMapping.find(score.IsComplyLevel);
            if (it != complyMapping.end()) {
                isComply = it->second;
            }
            else {
                std::cerr << "警告：未知的IsComplyLevel值: " << score.IsComplyLevel
                    << "，使用默认值 'false'" << std::endl;
            }

            // 更新level3_security_check_results表中的tmp_is_comply字段
            mysqlx::SqlResult updateResult = conn->sql(
                "UPDATE level3_security_check_results "
                "SET tmp_is_comply = ? "
                "WHERE shr_id = ? AND item_id = ?"
            )
                .bind(isComply)
                .bind(shr_id)
                .bind(score.item_id)
                .execute();

            // 检查更新是否成功
            uint64_t affectedRows = updateResult.getAffectedItemsCount();
            if (affectedRows > 0) {
                std::cout << "成功更新item_id " << score.item_id
                    << " 的合规状态为: " << isComply << std::endl;
            }
            else {
                std::cerr << "警告：未找到item_id " << score.item_id
                    << " 对应的记录，无法更新" << std::endl;
            }
        }

        std::cout << "完成对IP " << ip << " 的安全检查结果合规状态更新" << std::endl;
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "updateLevel3SecurityCheckResult时数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
    }
}

std::vector<event> DatabaseHandler::getLevel3SecurityCheckResults(const std::string& ip, ConnectionPool& pool) {
    std::vector<event> checkResults;

    try {
        auto conn = pool.getConnection();  // 获取连接

        // 首先获取scan_host_result表中的id
        mysqlx::SqlResult hostResult = conn->sql("SELECT id FROM scan_host_result WHERE ip = ?")
            .bind(ip)
            .execute();

        mysqlx::Row hostRow = hostResult.fetchOne();
        if (!hostRow) {
            std::cerr << "未找到IP: " << ip << " 对应的扫描记录" << std::endl;
            return checkResults;
        }

        int shr_id = hostRow[0]; // 获取shr_id

        // 查询安全检查结果
        mysqlx::SqlResult checkResult = conn->sql(
            "SELECT item_id, description, basis, command, result, is_comply, tmp_is_comply, recommend, "
            "important_level, DATE_FORMAT(check_time, '%Y-%m-%d %H:%i:%s') as formatted_check_time "
            "FROM level3_security_check_results "
            "WHERE shr_id = ? "
            "ORDER BY item_id")
            .bind(shr_id)
            .execute();
        // 处理查询结果
        while (mysqlx::Row row = checkResult.fetchOne()) {
            event checkEvent;
            checkEvent.item_id = row[0].get<int>();
            checkEvent.description = row[1].get<std::string>();
            checkEvent.basis = row[2].isNull() ? "" : row[2].get<std::string>();
            checkEvent.command = row[3].isNull() ? "" : row[3].get<std::string>();
            checkEvent.result = row[4].get<std::string>();
            checkEvent.IsComply = row[5].get<std::string>();
            checkEvent.tmp_IsComply = row[6].get<std::string>();  // 新增处理tmp_is_comply字段
            checkEvent.recommend = row[7].isNull() ? "" : row[7].get<std::string>();
            checkEvent.importantLevel = row[8].get<std::string>();  // 索引向后移一位
            checkResults.push_back(checkEvent);
        }

        std::cout << "成功获取IP " << ip << " 的安全检查结果，共 " << checkResults.size() << " 条记录" << std::endl;
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "getLevel3SecurityCheckResults时数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
    }

    return checkResults;
}

std::vector<event> DatabaseHandler::getLevel3SecurityCheckResultsByIds(const std::string& ip, const std::vector<int>& ids, ConnectionPool& pool) {
    std::vector<event> checkResults;

    try {
        auto conn = pool.getConnection();  // 获取连接

        // 首先获取scan_host_result表中的id
        mysqlx::SqlResult hostResult = conn->sql("SELECT id FROM scan_host_result WHERE ip = ?")
            .bind(ip)
            .execute();

        mysqlx::Row hostRow = hostResult.fetchOne();
        if (!hostRow) {
            std::cerr << "未找到IP: " << ip << " 对应的扫描记录" << std::endl;
            return checkResults;
        }

        int shr_id = hostRow[0]; // 获取shr_id

        // 构建IN子句字符串
        std::string placeholders;
        for (size_t i = 0; i < ids.size(); ++i) {
            if (i > 0) placeholders += ", ";
            placeholders += "?";
        }

        // 查询特定item_id的安全检查结果
        std::string query = "SELECT item_id, description, basis, command, result, is_comply, tmp_is_comply, recommend, "
            "important_level, DATE_FORMAT(check_time, '%Y-%m-%d %H:%i:%s') as formatted_check_time "
            "FROM level3_security_check_results "
            "WHERE shr_id = ? AND item_id IN (" + placeholders + ") "
            "ORDER BY item_id";

        mysqlx::SqlStatement stmt = conn->sql(query);

        // 绑定shr_id参数
        stmt.bind(shr_id);

        // 绑定id列表参数
        for (const int& id : ids) {
            stmt.bind(id);
        }

        mysqlx::SqlResult checkResult = stmt.execute();

        // 处理查询结果
        while (mysqlx::Row row = checkResult.fetchOne()) {
            event checkEvent;
            checkEvent.item_id = row[0].get<int>();
            checkEvent.description = row[1].get<std::string>();
            checkEvent.basis = row[2].isNull() ? "" : row[2].get<std::string>();
            checkEvent.command = row[3].isNull() ? "" : row[3].get<std::string>();
            checkEvent.result = row[4].get<std::string>();
            checkEvent.IsComply = row[5].get<std::string>();
            checkEvent.tmp_IsComply = row[6].get<std::string>();  // 新增处理tmp_is_comply字段
            checkEvent.recommend = row[7].isNull() ? "" : row[7].get<std::string>();
            checkEvent.importantLevel = row[8].get<std::string>();  // 索引从7变为8
            checkResults.push_back(checkEvent);
        }

        std::cout << "成功获取IP " << ip << " 的指定安全检查结果，共 " << checkResults.size() << " 条记录" << std::endl;
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "getLevel3SecurityCheckResultsByIds时数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
    }

    return checkResults;
}


void DatabaseHandler::saveSecurityCheckResult(const std::string& ip, const event& checkEvent, ConnectionPool& pool) {
    try {
        auto conn = pool.getConnection();  // 获取连接
        // 首先获取scan_host_result表中的id
        mysqlx::SqlResult hostResult = conn->sql("SELECT id FROM scan_host_result WHERE ip = ?")
            .bind(ip)
            .execute();
        mysqlx::Row hostRow = hostResult.fetchOne();
        if (!hostRow) {
            std::cerr << "未找到IP: " << ip << " 对应的扫描记录" << std::endl;
            return;
        }
        int shr_id = hostRow[0]; // 获取shr_id
        // 检查该项检查是否已存在
        mysqlx::SqlResult checkResult = conn->sql(
            "SELECT id FROM security_check_results WHERE shr_id = ? AND item_id = ?")
            .bind(shr_id)
            .bind(checkEvent.item_id)
            .execute();
        if (checkResult.count() > 0) {
            // 已存在记录，进行更新
            conn->sql(
                "UPDATE security_check_results SET "
                "description = ?, "
                "basis = ?, "
                "command = ?, "
                "result = ?, "
                "is_comply = ?, "
                "tmp_is_comply = ?, "  // 添加tmp_is_comply字段
                "recommend = ?, "
                "important_level = ?, "
                "check_time = CURRENT_TIMESTAMP "
                "WHERE shr_id = ? AND item_id = ?"
            )
                .bind(checkEvent.description)
                .bind(checkEvent.basis)
                .bind(checkEvent.command)
                .bind(checkEvent.result)
                .bind(checkEvent.IsComply)
                .bind(checkEvent.tmp_IsComply)  // 绑定tmp_IsComply值
                .bind(checkEvent.recommend)
                .bind(checkEvent.importantLevel)
                .bind(shr_id)
                .bind(checkEvent.item_id)
                .execute();
            std::cout << "成功更新安全检查结果: " << checkEvent.description << std::endl;
        }
        else {
            // 不存在记录，进行插入
            conn->sql(
                "INSERT INTO security_check_results "
                "(shr_id, item_id, description, basis, command, result, is_comply, tmp_is_comply, recommend, important_level, check_time) "  // 添加tmp_is_comply字段
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)"
            )
                .bind(shr_id)
                .bind(checkEvent.item_id)
                .bind(checkEvent.description)
                .bind(checkEvent.basis)
                .bind(checkEvent.command)
                .bind(checkEvent.result)
                .bind(checkEvent.IsComply)
                .bind(checkEvent.tmp_IsComply)  // 绑定tmp_IsComply值
                .bind(checkEvent.recommend)
                .bind(checkEvent.importantLevel)
                .execute();
            std::cout << "成功插入安全检查结果: " << checkEvent.description << std::endl;
        }
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "saveSecurityCheckResult时数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
    }
}

std::vector<event> DatabaseHandler::getSecurityCheckResults(const std::string& ip, ConnectionPool& pool) {
    std::vector<event> checkResults;

    try {
        auto conn = pool.getConnection();  // 获取连接

        // 首先获取scan_host_result表中的id
        mysqlx::SqlResult hostResult = conn->sql("SELECT id FROM scan_host_result WHERE ip = ?")
            .bind(ip)
            .execute();

        mysqlx::Row hostRow = hostResult.fetchOne();
        if (!hostRow) {
            std::cerr << "未找到IP: " << ip << " 对应的扫描记录" << std::endl;
            return checkResults;
        }

        int shr_id = hostRow[0]; // 获取shr_id

        // 查询安全检查结果
        mysqlx::SqlResult checkResult = conn->sql(
            "SELECT item_id, description, basis, command, result, is_comply, tmp_is_comply, recommend, "
            "important_level, DATE_FORMAT(check_time, '%Y-%m-%d %H:%i:%s') as formatted_check_time "
            "FROM security_check_results "
            "WHERE shr_id = ? "
            "ORDER BY item_id")
            .bind(shr_id)
            .execute();

        // 处理查询结果
        while (mysqlx::Row row = checkResult.fetchOne()) {
            event checkEvent;
            checkEvent.item_id = row[0].get<int>();
            checkEvent.description = row[1].get<std::string>();
            checkEvent.basis = row[2].isNull() ? "" : row[2].get<std::string>();
            checkEvent.command = row[3].isNull() ? "" : row[3].get<std::string>();
            checkEvent.result = row[4].get<std::string>();
            checkEvent.IsComply = row[5].get<std::string>();
            checkEvent.tmp_IsComply = row[6].get<std::string>();  // 新增处理tmp_is_comply字段
            checkEvent.recommend = row[7].isNull() ? "" : row[7].get<std::string>();
            checkEvent.importantLevel = row[8].get<std::string>();  // 索引从7变为8
            checkResults.push_back(checkEvent);
        }

        std::cout << "成功获取IP " << ip << " 的安全检查结果，共 " << checkResults.size() << " 条记录" << std::endl;
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "getSecurityCheckResults时数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
    }

    return checkResults;
}

std::vector<event> DatabaseHandler::getSecurityCheckResultsByIds(const std::string& ip, const std::vector<int>& ids, ConnectionPool& pool) {
    std::vector<event> checkResults;

    try {
        auto conn = pool.getConnection();  // 获取连接

        // 首先获取scan_host_result表中的id
        mysqlx::SqlResult hostResult = conn->sql("SELECT id FROM scan_host_result WHERE ip = ?")
            .bind(ip)
            .execute();

        mysqlx::Row hostRow = hostResult.fetchOne();
        if (!hostRow) {
            std::cerr << "未找到IP: " << ip << " 对应的扫描记录" << std::endl;
            return checkResults;
        }

        int shr_id = hostRow[0]; // 获取shr_id

        // 构建IN子句字符串
        std::string placeholders;
        for (size_t i = 0; i < ids.size(); ++i) {
            if (i > 0) placeholders += ", ";
            placeholders += "?";
        }

        // 查询特定item_id的安全检查结果
        std::string query = "SELECT item_id, description, basis, command, result, is_comply, tmp_is_comply, recommend, "
            "important_level, DATE_FORMAT(check_time, '%Y-%m-%d %H:%i:%s') as formatted_check_time "
            "FROM security_check_results "
            "WHERE shr_id = ? AND item_id IN (" + placeholders + ") "
            "ORDER BY item_id";

        mysqlx::SqlStatement stmt = conn->sql(query);

        // 绑定shr_id参数
        stmt.bind(shr_id);

        // 绑定id列表参数
        for (const int& id : ids) {
            stmt.bind(id);
        }

        mysqlx::SqlResult checkResult = stmt.execute();

        // 处理查询结果
        while (mysqlx::Row row = checkResult.fetchOne()) {
            event checkEvent;
            checkEvent.item_id = row[0].get<int>();
            checkEvent.description = row[1].get<std::string>();
            checkEvent.basis = row[2].isNull() ? "" : row[2].get<std::string>();
            checkEvent.command = row[3].isNull() ? "" : row[3].get<std::string>();
            checkEvent.result = row[4].get<std::string>();
            checkEvent.IsComply = row[5].get<std::string>();
            checkEvent.tmp_IsComply = row[6].get<std::string>();  // 新增处理tmp_is_comply字段
            checkEvent.recommend = row[7].isNull() ? "" : row[7].get<std::string>();
            checkEvent.importantLevel = row[8].get<std::string>();  // 索引从7变为8
            checkResults.push_back(checkEvent);
        }

        std::cout << "成功获取IP " << ip << " 的指定安全检查结果，共 " << checkResults.size() << " 条记录" << std::endl;
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "getSecurityCheckResultsByIds时数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
    }

    return checkResults;
}

// 计算基线检测摘要信息
BaselineCheckSummary DatabaseHandler::calculateBaselineSummary(const std::vector<event>& check_results) {
    BaselineCheckSummary summary = {};  // 初始化所有字段为0

    summary.total_checks = check_results.size();

    for (const auto& result : check_results) {
        // 统计合规项
        if (result.tmp_IsComply == "true"|| result.tmp_IsComply == "half_true") {
            if (result.tmp_IsComply == "true") {
                summary.compliant_items++;
            }
            if (result.tmp_IsComply == "half_true") {
                summary.half_compliant_items++;
            }

            // 按重要程度统计合规项
            if (result.importantLevel == "1") {
                summary.critical_compliant++;
            }
            else if (result.importantLevel == "2") {
                summary.high_compliant++;
            }
            else if (result.importantLevel == "3") {
                summary.medium_compliant++;
            }
        }

        // 统计各重要程度的总项数
        if (result.importantLevel == "1") {
            summary.critical_items++;
        }
        else if (result.importantLevel == "2") {
            summary.high_items++;
        }
        else if (result.importantLevel == "3") {
            summary.medium_items++;
        }
    }

    // 计算不合规项数
    summary.non_compliant_items = summary.total_checks - summary.compliant_items - summary.half_compliant_items;



    
    // 计算不合规率并保留两位小数(不使用round函数)
    summary.compliance_rate = summary.total_checks > 0 ?
        (round(static_cast<double>(summary.non_compliant_items) / summary.total_checks * 10000.0) / 100.0) : 0.0;
    return summary;
}

void DatabaseHandler::insertServerInfo(const ServerInfo& info, const std::string& ip, ConnectionPool& pool) {
    try {
        auto conn = pool.getConnection();  // 获取连接

        // 1. 首先获取scan_host_result表中的id
        mysqlx::SqlResult hostResult = conn->sql("SELECT id FROM scan_host_result WHERE ip = ?")
            .bind(ip)
            .execute();

        mysqlx::Row hostRow = hostResult.fetchOne();
        if (!hostRow) {
            std::cerr << "未找到IP: " << ip << " 对应的扫描记录" << std::endl;
            return;
        }

        int shr_id = hostRow[0]; // 获取shr_id

        // 2. 检查该IP是否已有服务器信息记录
        mysqlx::SqlResult checkResult = conn->sql(
            "SELECT id FROM server_info WHERE shr_id = ?")
            .bind(shr_id)
            .execute();

        if (checkResult.count() > 0) {
            // 已存在记录，进行更新
            conn->sql(
                "UPDATE server_info SET "
                "hostname = ?, "
                "arch = ?, "
                "cpu = ?, "
                "cpu_physical = ?, "
                "cpu_core = ?, "
                "free_memory = ?, "
                "product_name = ?, "
                "version = ?, "
                "os_name = ?, "
                "is_internet = ?, "
                "update_time = CURRENT_TIMESTAMP "
                "WHERE shr_id = ?"
            )
                .bind(info.hostname)
                .bind(info.arch)
                .bind(info.cpu)
                .bind(info.cpuPhysical)
                .bind(info.cpuCore)
                .bind(info.free)
                .bind(info.ProductName)
                .bind(info.version)
                .bind(info.osName)
                .bind(info.isInternet)
                .bind(shr_id)
                .execute();

            std::cout << "成功更新服务器信息: " << ip << std::endl;
        }
        else {
            // 不存在记录，进行插入
            conn->sql(
                "INSERT INTO server_info "
                "(shr_id, hostname, arch, cpu, cpu_physical, cpu_core, free_memory, product_name, version, os_name, is_internet, create_time, update_time) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
            )
                .bind(shr_id)
                .bind(info.hostname)
                .bind(info.arch)
                .bind(info.cpu)
                .bind(info.cpuPhysical)
                .bind(info.cpuCore)
                .bind(info.free)
                .bind(info.ProductName)
                .bind(info.version)
                .bind(info.osName)
                .bind(info.isInternet)
                .execute();

            std::cout << "成功插入服务器信息: " << ip << std::endl;
        }
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "insertServerInfo时数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
    }
}

ServerInfo DatabaseHandler::getServerInfoByIp(const std::string& ip, ConnectionPool& pool) {
    ServerInfo info;
    // 初始化默认值
    info.hostname = "";
    info.arch = "";
    info.cpu = "";
    info.cpuPhysical = "";
    info.cpuCore = "";
    info.free = "";
    info.ProductName = "";
    info.version = "";
    info.osName = "";
    info.isInternet = "";

    try {
        auto conn = pool.getConnection();  // 获取连接

        // 1. 首先获取scan_host_result表中的id
        mysqlx::SqlResult hostResult = conn->sql("SELECT id FROM scan_host_result WHERE ip = ?")
            .bind(ip)
            .execute();

        mysqlx::Row hostRow = hostResult.fetchOne();
        if (!hostRow) {
            std::cerr << "未找到IP: " << ip << " 对应的扫描记录" << std::endl;
            return info;
        }

        int shr_id = hostRow[0]; // 获取shr_id

        // 2. 查询服务器信息
        mysqlx::SqlResult infoResult = conn->sql(
            "SELECT hostname, arch, cpu, cpu_physical, cpu_core, free_memory, "
            "product_name, version, os_name, is_internet "
            "FROM server_info WHERE shr_id = ?")
            .bind(shr_id)
            .execute();

        mysqlx::Row infoRow = infoResult.fetchOne();
        if (!infoRow) {
            std::cerr << "未找到IP: " << ip << " 对应的服务器信息" << std::endl;
            return info;
        }

        // 3. 填充ServerInfo结构体
        info.hostname = infoRow[0].isNull() ? "" : static_cast<std::string>(infoRow[0]);
        info.arch = infoRow[1].isNull() ? "" : static_cast<std::string>(infoRow[1]);
        info.cpu = infoRow[2].isNull() ? "" : static_cast<std::string>(infoRow[2]);
        info.cpuPhysical = infoRow[3].isNull() ? "" : static_cast<std::string>(infoRow[3]);
        info.cpuCore = infoRow[4].isNull() ? "" : static_cast<std::string>(infoRow[4]);
        info.free = infoRow[5].isNull() ? "" : static_cast<std::string>(infoRow[5]);
        info.ProductName = infoRow[6].isNull() ? "" : static_cast<std::string>(infoRow[6]);
        info.version = infoRow[7].isNull() ? "" : static_cast<std::string>(infoRow[7]);
        info.osName = infoRow[8].isNull() ? "" : static_cast<std::string>(infoRow[8]);
        info.isInternet = infoRow[9].isNull() ? "" : static_cast<std::string>(infoRow[9]);

        std::cout << "成功获取IP: " << ip << " 的服务器信息" << std::endl;
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "getServerInfoByIp时数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
    }

    return info;
}

//获取所有支持的漏洞类型
std::vector<std::string> DatabaseHandler::getAllVulnTypes(ConnectionPool& pool)
{
    std::vector<std::string> types;

    try {
        auto conn = pool.getConnection();

        mysqlx::SqlResult result = conn->sql("SELECT TypeName FROM VulnType")
            .execute();

        while (mysqlx::Row row = result.fetchOne()) {
            std::string type = static_cast<std::string>(row[0]);
            types.push_back(type);
        }
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "[DB] 获取漏洞类型出错: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "[DB] 异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "[DB] 未知错误" << std::endl;
    }

    return types;
}

// 添加/删除漏洞类型（统一入口）
bool DatabaseHandler::editVulnType(const std::string& type, const std::string& action, ConnectionPool& pool) {
    try {
        auto conn = pool.getConnection();
        if (action == "add") {
            conn->sql("INSERT INTO VulnType (TypeName) VALUES (?)")
                .bind(type)
                .execute();
            system_logger->info("[editVulnType] 添加漏洞类型成功：{}", type);
            console->info("[editVulnType] 添加漏洞类型成功：{}", type);
        }
        else if (action == "delete") {
            conn->sql("DELETE FROM VulnType WHERE TypeName = ?")
                .bind(type)
                .execute();
            system_logger->info("[editVulnType] 删除漏洞类型成功：{}", type);
            console->info("[editVulnType] 删除漏洞类型成功：{}", type);
        }
        else {
            system_logger->warn("[editVulnType] 无效操作: {}", action);
            console->warn("[editVulnType] 无效操作: {}", action);
            return false;
        }
        return true;
    }
    catch (const mysqlx::Error& err) {
        system_logger->error("[editVulnType] MySQL 错误: {}", err.what());
        console->error("[editVulnType] MySQL 错误: {}", err.what());
        return false;
    }
}

//插入POC
bool DatabaseHandler::insertData(const POC& poc, ConnectionPool& pool) {
    try {
        auto conn = pool.getConnection();

        conn->sql(R"(
            INSERT INTO POC (Vuln_id, Vul_name, Type, Description, Affected_infra, Script_type, Script, Timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, NOW())
        )")
            .bind(
                poc.vuln_id,
                poc.vul_name,
                poc.type,
                poc.description,
                poc.affected_infra,
                poc.script_type,
                poc.script
            )
            .execute();

        system_logger->info("成功插入POC: {} - {}", poc.vuln_id, poc.vul_name);
        console->info("成功插入POC: {} - {}", poc.vuln_id, poc.vul_name);
        return true;
    }
    catch (const mysqlx::Error& err) {
        system_logger->error("[insertData] MySQL 错误: {}", err.what());  
        console->error("[insertData] MySQL 错误: {}", err.what());
        return false;
    }
}

//删除POC
bool DatabaseHandler::deleteDataById(int id, ConnectionPool& pool) {
    try {
        auto conn = pool.getConnection();

        auto result = conn->sql("DELETE FROM POC WHERE ID = ?")
            .bind(id)
            .execute();

        if (result.getAffectedItemsCount() > 0) {
            system_logger->info("成功删除 POC，ID = {}", id);
            console->info("成功删除 POC，ID = {}", id);
            return true;
        }
        else {
            system_logger->error("删除失败，未找到 ID = {}", id);
            console->error("删除失败，未找到 ID = {}", id);
            return false;
        }
    }
    catch (const mysqlx::Error& err) {
        system_logger->error("[deleteDataById] MySQL 错误: {}", err.what());
        console->error("[deleteDataById] MySQL 错误: {}", err.what());
        return false;
    }
}

//更新POC

bool DatabaseHandler::updateDataById(int id, const POC& poc, ConnectionPool& pool) {
    try {
        auto conn = pool.getConnection();

        auto check = conn->sql("SELECT COUNT(*) FROM POC WHERE ID = ?")
            .bind(id)
            .execute();

        int count = check.fetchOne()[0].get<int>();
        if (count == 0) {
            system_logger->error("[updateDataById] 错误：ID {} 不存在", id); 
            console->error("[updateDataById] 错误：ID {} 不存在", id);
            return false;
        }

        conn->sql(R"(
            UPDATE POC SET
                Vuln_id = ?,
                Vul_name = ?,
                Type = ?,
                Description = ?,
                Affected_infra = ?,
                Script_type = ?,
                Script = ?,
                Timestamp = NOW()
            WHERE ID = ?
        )")
            .bind(
                poc.vuln_id,
                poc.vul_name,
                poc.type,
                poc.description,
                poc.affected_infra,
                poc.script_type,
                poc.script,
                id
            )
            .execute();

        system_logger->info("成功更新 POC: ID = {}, Vuln_id = {}", id, poc.vuln_id);
        console->info("成功更新 POC: ID = {}, Vuln_id = {}", id, poc.vuln_id);
        return true;
    }
    catch (const mysqlx::Error& err) {
        system_logger->error("[updateDataById] MySQL 错误: {}", err.what());
        console->error("[updateDataById] MySQL 错误: {}", err.what());
        return false;
    }
}

std::vector<POC> DatabaseHandler::searchData(const std::string& keyword, ConnectionPool& pool) {
    std::vector<POC> records;
    std::string pattern = "%" + keyword + "%";

    try {
        auto conn = pool.getConnection();

        std::string sql = R"(
            SELECT * FROM POC WHERE
                Vuln_id LIKE ? OR
                Vul_name LIKE ? OR
                Type LIKE ? OR
                Description LIKE ? OR
                Affected_infra LIKE ? OR
                Script_type LIKE ? OR
                Timestamp LIKE ?
        )";

        auto stmt = conn->sql(sql)
            .bind(pattern, pattern, pattern, pattern, pattern, pattern, pattern)
            .execute();

        while (mysqlx::Row row = stmt.fetchOne()) {
            POC poc;
            poc.id = row[0].get<int>();
            poc.vuln_id = row[1].get<std::string>();
            poc.vul_name = row[2].get<std::string>();
            poc.type = row[3].get<std::string>();
            poc.description = row[4].get<std::string>();
            poc.affected_infra = row[5].get<std::string>();
            poc.script_type = row[6].get<std::string>();
            poc.script = row[7].isNull() ? "" : row[7].get<std::string>();
            poc.timestamp = row[8].get<std::string>();
            records.push_back(poc);
        }

        system_logger->info("成功搜索POC关键字：{}，匹配到 {} 条", keyword, records.size());
        console->info("成功搜索POC关键字：{}，匹配到 {} 条", keyword, records.size());
    }
    catch (const mysqlx::Error& err) {
        system_logger->error("[searchData] 错误: {}", err.what());  // ⛔ 原为 searchPoc
        console->error("[searchData] 错误: {}", err.what());
    }

    return records;
}

std::vector<POC> DatabaseHandler::searchDataByIds(const std::vector<int>& ids, ConnectionPool& pool) {
    std::vector<POC> records;
    if (ids.empty()) return records;

    try {
        auto conn = pool.getConnection();

        std::string placeholders = "";
        for (size_t i = 0; i < ids.size(); ++i) {
            placeholders += "?";
            if (i < ids.size() - 1) placeholders += ",";
        }

        std::string sql = "SELECT * FROM POC WHERE ID IN (" + placeholders + ")";
        auto stmt = conn->sql(sql);
        for (int id : ids) stmt.bind(id);
        auto result = stmt.execute();

        while (mysqlx::Row row = result.fetchOne()) {
            POC poc;
            poc.id = row[0].get<int>();
            poc.vuln_id = row[1].get<std::string>();
            poc.vul_name = row[2].get<std::string>();
            poc.type = row[3].get<std::string>();
            poc.description = row[4].get<std::string>();
            poc.affected_infra = row[5].get<std::string>();
            poc.script_type = row[6].get<std::string>();
            poc.script = row[7].isNull() ? "" : row[7].get<std::string>();
            poc.timestamp = row[8].get<std::string>();
            records.push_back(poc);
        }

        system_logger->info("根据ID列表查询POC成功，共 {} 条", records.size());
        console->info("根据ID列表查询POC成功，共 {} 条", records.size());
    }
    catch (const mysqlx::Error& err) {
        system_logger->error("[searchDataByIds] 错误: {}", err.what());
        console->error("[searchDataByIds] 错误: {}", err.what());
    }

    return records;
}
std::vector<POC> DatabaseHandler::searchDataByCVE(const std::string& vuln_id, ConnectionPool& pool) {
    std::vector<POC> records;

    try {
        auto conn = pool.getConnection();
        auto result = conn->sql("SELECT * FROM POC WHERE Vuln_id = ?")
            .bind(vuln_id)
            .execute();

        while (mysqlx::Row row = result.fetchOne()) {
            POC poc;
            poc.id = row[0].get<int>();
            poc.vuln_id = row[1].get<std::string>();
            poc.vul_name = row[2].get<std::string>();
            poc.type = row[3].get<std::string>();
            poc.description = row[4].get<std::string>();
            poc.affected_infra = row[5].get<std::string>();
            poc.script_type = row[6].get<std::string>();
            poc.script = row[7].isNull() ? "" : row[7].get<std::string>();
            poc.timestamp = row[8].get<std::string>();
            records.push_back(poc);
        }

        system_logger->info("[searchDataByCVE] 找到 {} 条记录，vuln_id = {}", records.size(), vuln_id);
        console->info("[searchDataByCVE] 找到 {} 条记录，vuln_id = {}", records.size(), vuln_id);
    }
    catch (const mysqlx::Error& err) {
        system_logger->error("[searchDataByCVE] 错误: {}", err.what());
        console->error("[searchDataByCVE] 错误: {}", err.what());
    }

    return records;
}
bool DatabaseHandler::isExistCVE(const std::string& vuln_id, ConnectionPool& pool) {
    try {
        auto conn = pool.getConnection();
        auto result = conn->sql("SELECT COUNT(*) FROM POC WHERE Vuln_id = ?")
            .bind(vuln_id)
            .execute();

        int count = result.fetchOne()[0].get<int>();

        system_logger->info("isExistCVE: {} -> {}", vuln_id, count > 0 ? "存在" : "不存在");
        console->info("isExistCVE: {} -> {}", vuln_id, count > 0 ? "存在" : "不存在");

        return count > 0;
    }
    catch (const mysqlx::Error& err) {
        system_logger->error("isExistCVE 错误: {}", err.what());
        console->error("isExistCVE 错误: {}", err.what());
        return false;
    }
}

std::string DatabaseHandler::searchPOCById(const int& id, ConnectionPool& pool) {
    std::string filename = "";
    std::string pathPrefix = "../../../src/scan/scripts/";

    try {
        auto conn = pool.getConnection();
        auto result = conn->sql("SELECT Script FROM POC WHERE ID = ?")
            .bind(id)
            .execute();

        mysqlx::Row row = result.fetchOne();
        if (!row || row[0].isNull()) {
            system_logger->info("[searchPOCById] 未找到 ID={} 的脚本路径", id);
            console->info("[searchPOCById] 未找到 ID={} 的脚本路径", id);
            return "";
        }

        filename = row[0].get<std::string>();
        return filename.empty() ? "" : pathPrefix + filename;
    }
    catch (const mysqlx::Error& err) {
        system_logger->error("[searchPOCById] MySQL 错误: {}", err.what());
        console->error("[searchPOCById] MySQL 错误: {}", err.what());
        return "";
    }
}

std::string DatabaseHandler::searchPOCById(const std::string& vuln_id, ConnectionPool& pool) {
    std::string filename = "";
    std::string pathPrefix = "../../../src/scan/scripts/";

    try {
        auto conn = pool.getConnection();
        auto result = conn->sql("SELECT Script FROM POC WHERE Vuln_id = ?")
            .bind(vuln_id)
            .execute();

        mysqlx::Row row = result.fetchOne();
        if (!row || row[0].isNull()) {
            system_logger->info("[searchPOCById] 未找到 Vuln_id={} 的脚本路径", vuln_id);
            console->info("[searchPOCById] 未找到 Vuln_id={} 的脚本路径", vuln_id);
            return "";
        }

        filename = row[0].get<std::string>();
        return filename.empty() ? "" : pathPrefix + filename;
    }
    catch (const mysqlx::Error& err) {
        system_logger->error("[searchPOCById] MySQL 错误: {}", err.what());
        console->error("[searchPOCById] MySQL 错误: {}", err.what());
        return "";
    }
}

bool DatabaseHandler::searchDataById(const int& id, POC& poc, ConnectionPool& pool) {
    try {
        auto conn = pool.getConnection();
        auto result = conn->sql("SELECT * FROM POC WHERE ID = ?")
            .bind(id)
            .execute();

        mysqlx::Row row = result.fetchOne();
        if (!row) {
            system_logger->error("[searchDataById] POC ID {} 不存在", id);
            console->error("[searchDataById] POC ID {} 不存在", id);
            return false;
        }

        poc.id = row[0].get<int>();
        poc.vuln_id = row[1].get<std::string>();
        poc.vul_name = row[2].get<std::string>();
        poc.type = row[3].get<std::string>();
        poc.description = row[4].get<std::string>();
        poc.affected_infra = row[5].get<std::string>();
        poc.script_type = row[6].get<std::string>();
        poc.script = row[7].isNull() ? "" : row[7].get<std::string>();
        poc.timestamp = row[8].get<std::string>();

        system_logger->info("[searchDataById] 成功查询 POC ID={}", id);
        console->info("[searchDataById] 成功查询 POC ID={}", id);
        return true;
    }
    catch (const mysqlx::Error& err) {
        system_logger->error("[searchDataById] MySQL 错误: {}", err.what());
        console->error("[searchDataById] MySQL 错误: {}", err.what());
        return false;
    }
}
std::vector<POC> DatabaseHandler::getAllData(ConnectionPool& pool) {
    std::vector<POC> records;
    try {
        auto conn = pool.getConnection();
        auto result = conn->sql("SELECT * FROM POC").execute();

        while (mysqlx::Row row = result.fetchOne()) {
            POC poc;
            poc.id = row[0].get<int>();
            poc.vuln_id = row[1].get<std::string>();
            poc.vul_name = row[2].get<std::string>();
            poc.type = row[3].get<std::string>();
            poc.description = row[4].get<std::string>();
            poc.affected_infra = row[5].get<std::string>();
            poc.script_type = row[6].get<std::string>();
            poc.script = row[7].isNull() ? "" : row[7].get<std::string>();
            poc.timestamp = row[8].get<std::string>();
            records.push_back(poc);
        }

        system_logger->info("[getAllData] 成功加载 {} 条POC数据", records.size());
        console->info("[getAllData] 成功加载 {} 条POC数据", records.size());
    }
    catch (const mysqlx::Error& err) {
        system_logger->error("[getAllData] MySQL 错误: {}", err.what());
        console->error("[getAllData] MySQL 错误: {}", err.what());
        exit(1);
    }
    return records;
}
std::vector<POC> DatabaseHandler::getVaildPOCData(ConnectionPool& pool) {
    std::vector<POC> records;
    try {
        auto conn = pool.getConnection();
        auto result = conn->sql("SELECT * FROM POC WHERE Script IS NOT NULL AND Script != ''").execute();

        while (mysqlx::Row row = result.fetchOne()) {
            POC poc;
            poc.id = row[0].get<int>();
            poc.vuln_id = row[1].get<std::string>();
            poc.vul_name = row[2].get<std::string>();
            poc.type = row[3].get<std::string>();
            poc.description = row[4].get<std::string>();
            poc.affected_infra = row[5].get<std::string>();
            poc.script_type = row[6].get<std::string>();
            poc.script = row[7].isNull() ? "" : row[7].get<std::string>();
            poc.timestamp = row[8].get<std::string>();
            records.push_back(poc);
        }

        system_logger->info("[getVaildPOCData] 成功加载有效POC {} 条", records.size());
        console->info("[getVaildPOCData] 成功加载有效POC {} 条", records.size());
    }
    catch (const mysqlx::Error& err) {
        system_logger->error("[getVaildPOCData] MySQL 错误: {}", err.what());
        console->error("[getVaildPOCData] MySQL 错误: {}", err.what());
        exit(1);
    }
    return records;
}

void DatabaseHandler::updateBaseLineSecurityCheckResult(const std::string& ip, ConnectionPool& pool, std::vector<scoreMeasure> vec_score)
{
    try {
        auto conn = pool.getConnection();  // 获取连接

        // 首先获取scan_host_result表中的id
        mysqlx::SqlResult hostResult = conn->sql("SELECT id FROM scan_host_result WHERE ip = ?")
            .bind(ip)
            .execute();

        mysqlx::Row hostRow = hostResult.fetchOne();
        if (!hostRow) {
            std::cerr << "未找到IP: " << ip << " 对应的扫描记录" << std::endl;
            return;
        }

        int shr_id = hostRow[0]; // 获取shr_id

        // 定义IsComplyLevel到is_comply的映射
        std::unordered_map<std::string, std::string> complyMapping = {
            {"1", "true"},        // 1.0 对应 true
            {"1.0", "true"},      // 1.0 对应 true
            {"0", "false"},       // 0 对应 false
            {"0.0", "false"},     // 0.0 对应 false
            {"0.5", "half_true"}  // 0.5 对应 half_true
        };

        // 遍历所有的评分项
        for (const auto& score : vec_score) {
            // 获取对应的is_comply值
            std::string isComply = "false"; // 默认值
            auto it = complyMapping.find(score.IsComplyLevel);
            if (it != complyMapping.end()) {
                isComply = it->second;
            }
            else {
                std::cerr << "警告：未知的IsComplyLevel值: " << score.IsComplyLevel
                    << "，使用默认值 'false'" << std::endl;
            }

            // 更新security_check_results表中的tmp_is_comply字段
            mysqlx::SqlResult updateResult = conn->sql(
                "UPDATE security_check_results "
                "SET tmp_is_comply = ? "
                "WHERE shr_id = ? AND item_id = ?"
            )
                .bind(isComply)
                .bind(shr_id)
                .bind(score.item_id)
                .execute();

            // 检查更新是否成功
            uint64_t affectedRows = updateResult.getAffectedItemsCount();
            if (affectedRows > 0) {
                std::cout << "成功更新item_id " << score.item_id
                    << " 的合规状态为: " << isComply << std::endl;
            }
            else {
                std::cerr << "警告：未找到item_id " << score.item_id
                    << " 对应的记录，无法更新" << std::endl;
            }
        }

        std::cout << "完成对IP " << ip << " 的安全检查结果合规状态更新" << std::endl;
    }
    catch (const mysqlx::Error& err) {
        std::cerr << "updateBaseLineSecurityCheckResult时数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
    }
}
// 根据IP获取未完成的基线检查项
std::vector<event> DatabaseHandler::getUncheckedBaselineItems(const std::string& ip, ConnectionPool& pool)
{
    std::vector<event> uncheckedItems;

    try {
        auto conn = pool.getConnection();

        // 1. 根据IP获取shr_id
        mysqlx::SqlResult shrResult = conn->sql("SELECT id FROM scan_host_result WHERE ip = ?")
            .bind(ip)
            .execute();

        mysqlx::Row shrRow = shrResult.fetchOne();
        if (!shrRow) {
            std::cerr << "未找到IP: " << ip << " 对应的扫描记录" << std::endl;
            return uncheckedItems;
        }

        int shr_id = shrRow[0];

        // 2. 获取已检查的item_id列表
        mysqlx::SqlResult checkedResult = conn->sql(
            "SELECT DISTINCT item_id FROM security_check_results WHERE shr_id = ?")
            .bind(shr_id)
            .execute();

        std::set<int> checkedItemIds;
        while (mysqlx::Row checkedRow = checkedResult.fetchOne()) {
            int itemId = checkedRow[0];
            checkedItemIds.insert(itemId);
        }

        // 3. 获取所有基线检查项，排除已检查的项
        std::string baselineQuery = "SELECT item_id, description, basis, important_level FROM baseline_check_items";

        // 如果有已检查的项，添加WHERE条件排除它们
        if (!checkedItemIds.empty()) {
            baselineQuery += " WHERE item_id NOT IN (";
            bool first = true;
            for (int checkedId : checkedItemIds) {
                if (!first) {
                    baselineQuery += ",";
                }
                baselineQuery += std::to_string(checkedId);
                first = false;
            }
            baselineQuery += ")";
        }

        baselineQuery += " ORDER BY item_id";

        mysqlx::SqlResult baselineResult = conn->sql(baselineQuery).execute();

        // 4. 将未检查的基线项转换为event结构
        while (mysqlx::Row baselineRow = baselineResult.fetchOne()) {
            event uncheckedEvent;

            uncheckedEvent.item_id = baselineRow[0];
            uncheckedEvent.description = static_cast<std::string>(baselineRow[1]);
            uncheckedEvent.basis = baselineRow[2].isNull() ? "" : static_cast<std::string>(baselineRow[2]);
            uncheckedEvent.importantLevel = static_cast<std::string>(baselineRow[3]);

            // 设置未检查项的默认值
            uncheckedEvent.command = "";
            uncheckedEvent.result = "";
            uncheckedEvent.IsComply = "false";
            uncheckedEvent.tmp_IsComply = "false";
            uncheckedEvent.recommend = "";

            uncheckedItems.push_back(uncheckedEvent);
        }

        std::cout << "IP: " << ip << " 未完成的基线检查项数量: " << uncheckedItems.size() << std::endl;

    }
    catch (const mysqlx::Error& err) {
        std::cerr << "获取未完成基线检查项时数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
    }

    return uncheckedItems;
}

// 辅助函数：获取指定IP已完成的检查项ID列表
std::vector<int> DatabaseHandler::getCheckedItemIds(const std::string& ip, ConnectionPool& pool)
{
    std::vector<int> checkedIds;

    try {
        auto conn = pool.getConnection();

        // 根据IP获取shr_id，然后获取已检查的item_id列表
        mysqlx::SqlResult result = conn->sql(
            "SELECT DISTINCT scr.item_id "
            "FROM security_check_results scr "
            "JOIN scan_host_result shr ON scr.shr_id = shr.id "
            "WHERE shr.ip = ? "
            "ORDER BY scr.item_id")
            .bind(ip)
            .execute();

        while (mysqlx::Row row = result.fetchOne()) {
            checkedIds.push_back(row[0]);
        }

    }
    catch (const mysqlx::Error& err) {
        std::cerr << "获取已检查项ID时数据库错误: " << err.what() << std::endl;
    }

    return checkedIds;
}

// 辅助函数：获取所有基线检查项ID列表
std::vector<int> DatabaseHandler::getAllBaselineItemIds(ConnectionPool& pool)
{
    std::vector<int> allIds;

    try {
        auto conn = pool.getConnection();

        mysqlx::SqlResult result = conn->sql(
            "SELECT item_id FROM baseline_check_items ORDER BY item_id")
            .execute();

        while (mysqlx::Row row = result.fetchOne()) {
            allIds.push_back(row[0]);
        }

    }
    catch (const mysqlx::Error& err) {
        std::cerr << "获取所有基线检查项ID时数据库错误: " << err.what() << std::endl;
    }

    return allIds;
}

// 根据IP获取未完成的Level3安全检查项
std::vector<event> DatabaseHandler::getUncheckedLevel3Items(const std::string& ip, ConnectionPool& pool)
{
    std::vector<event> uncheckedItems;

    try {
        auto conn = pool.getConnection();

        // 1. 根据IP获取shr_id
        mysqlx::SqlResult shrResult = conn->sql("SELECT id FROM scan_host_result WHERE ip = ?")
            .bind(ip)
            .execute();

        mysqlx::Row shrRow = shrResult.fetchOne();
        if (!shrRow) {
            std::cerr << "未找到IP: " << ip << " 对应的扫描记录" << std::endl;
            return uncheckedItems;
        }

        int shr_id = shrRow[0];

        // 2. 获取已检查的item_id列表
        mysqlx::SqlResult checkedResult = conn->sql(
            "SELECT DISTINCT item_id FROM level3_security_check_results WHERE shr_id = ?")
            .bind(shr_id)
            .execute();

        std::set<int> checkedItemIds;
        while (mysqlx::Row checkedRow = checkedResult.fetchOne()) {
            int itemId = checkedRow[0];
            checkedItemIds.insert(itemId);
        }

        // 3. 获取所有Level3检查项，排除已检查的项
        std::string level3Query = "SELECT item_id, description, basis, important_level FROM level3_security_check_items";

        // 如果有已检查的项，添加WHERE条件排除它们
        if (!checkedItemIds.empty()) {
            level3Query += " WHERE item_id NOT IN (";
            bool first = true;
            for (int checkedId : checkedItemIds) {
                if (!first) {
                    level3Query += ",";
                }
                level3Query += std::to_string(checkedId);
                first = false;
            }
            level3Query += ")";
        }

        level3Query += " ORDER BY item_id";

        mysqlx::SqlResult level3Result = conn->sql(level3Query).execute();

        // 4. 将未检查的Level3项转换为event结构
        while (mysqlx::Row level3Row = level3Result.fetchOne()) {
            event uncheckedEvent;

            uncheckedEvent.item_id = level3Row[0];
            uncheckedEvent.description = static_cast<std::string>(level3Row[1]);
            uncheckedEvent.basis = level3Row[2].isNull() ? "" : static_cast<std::string>(level3Row[2]);
            uncheckedEvent.importantLevel = static_cast<std::string>(level3Row[3]);

            // 设置未检查项的默认值
            uncheckedEvent.command = "";
            uncheckedEvent.result = "";
            uncheckedEvent.IsComply = "false";
            uncheckedEvent.tmp_IsComply = "false";
            uncheckedEvent.recommend = "";

            uncheckedItems.push_back(uncheckedEvent);
        }

        std::cout << "IP: " << ip << " 未完成的Level3安全检查项数量: " << uncheckedItems.size() << std::endl;

    }
    catch (const mysqlx::Error& err) {
        std::cerr << "获取未完成Level3检查项时数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }
    catch (...) {
        std::cerr << "未知错误发生" << std::endl;
    }

    return uncheckedItems;
}

// 辅助函数：获取指定IP已完成的Level3检查项ID列表
std::vector<int> DatabaseHandler::getCheckedLevel3ItemIds(const std::string& ip, ConnectionPool& pool)
{
    std::vector<int> checkedIds;

    try {
        auto conn = pool.getConnection();

        // 根据IP获取shr_id，然后获取已检查的item_id列表
        mysqlx::SqlResult result = conn->sql(
            "SELECT DISTINCT l3cr.item_id "
            "FROM level3_security_check_results l3cr "
            "JOIN scan_host_result shr ON l3cr.shr_id = shr.id "
            "WHERE shr.ip = ? "
            "ORDER BY l3cr.item_id")
            .bind(ip)
            .execute();

        while (mysqlx::Row row = result.fetchOne()) {
            checkedIds.push_back(row[0]);
        }

    }
    catch (const mysqlx::Error& err) {
        std::cerr << "获取已检查Level3项ID时数据库错误: " << err.what() << std::endl;
    }

    return checkedIds;
}

// 辅助函数：获取所有Level3检查项ID列表
std::vector<int> DatabaseHandler::getAllLevel3ItemIds(ConnectionPool& pool)
{
    std::vector<int> allIds;

    try {
        auto conn = pool.getConnection();

        mysqlx::SqlResult result = conn->sql(
            "SELECT item_id FROM level3_security_check_items ORDER BY item_id")
            .execute();

        while (mysqlx::Row row = result.fetchOne()) {
            allIds.push_back(row[0]);
        }

    }
    catch (const mysqlx::Error& err) {
        std::cerr << "获取所有Level3检查项ID时数据库错误: " << err.what() << std::endl;
    }

    return allIds;
}

std::vector<AssetInfo> DatabaseHandler::getAllAssetsFullInfo(ConnectionPool& pool) {
    std::vector<AssetInfo> allAssets;

    try {
        auto session_ptr = pool.getConnection();  // std::shared_ptr<mysqlx::Session>
        mysqlx::Session& session = *session_ptr;

        auto result = session.sql("SELECT ip, alive,group_id FROM scan_host_result").execute();

        //1.获取所有主机及存活状态
        std::vector<std::string> all_ips;
        std::map<std::string, std::string> ip_alive_map;
        std::map<std::string, int> ip_group_map;

        for (auto row : result) {
            std::string ip = row[0].get<std::string>();
            std::string alive = row[1].get<std::string>();
            int group_id = row[2].isNull() ? -1 : row[2].get<int>();

            all_ips.push_back(ip);
            ip_alive_map[ip] = alive;
            ip_group_map[ip] = group_id;
        }

        //2.获取所有存活主机的漏洞信息
        auto allVulns = getVulnerabilities(pool, all_ips);
        std::map<std::string, IpVulnerabilities> ipToVulnMap;
        for (const auto& v : allVulns) {
            ipToVulnMap[v.ip] = v;
        }

        //3.为每个存活主机获取端口信息并组合数据
        for (const auto& ip : all_ips) {
            AssetInfo assetInfo;
            assetInfo.ip = ip;
            assetInfo.alive = (ip_alive_map[ip] == "true");
            assetInfo.group_id = ip_group_map[ip];


            // 获取端口信息
            assetInfo.ports = getAllPortInfoByIp(ip, pool);

            // 获取服务器系统信息
            assetInfo.serverinfo = getServerInfoByIp(ip, pool);

            // 如果有该IP的漏洞信息，则填充到assetInfo中
            if (ipToVulnMap.find(ip) != ipToVulnMap.end()) {
                const IpVulnerabilities& ipVulns = ipToVulnMap[ip];
                assetInfo.host_vulnerabilities = ipVulns.host_vulnerabilities;
                assetInfo.port_vulnerabilities = ipVulns.port_vulnerabilities;
            }
            // 获取该IP的基线检测结果并计算摘要
            std::vector<event> check_results = getSecurityCheckResults(ip, pool);
            std::vector<event> level3_check_results = getLevel3SecurityCheckResults(ip, pool);

            assetInfo.baseline_summary = calculateBaselineSummary(check_results);
            assetInfo.level3_baseline_summary = calculateBaselineSummary(level3_check_results);
            //计算等保得分
            // 定义合规等级映射表
            std::unordered_map<std::string, double> complyLevelMapping = {
                {"true", 1.0},
                {"false", 0.0},
                {"half_true", 0.5},
                {"pending", -1.0}  // pending状态可根据需要调整处理方式
            };

            // 计算评分
            int n = level3_check_results.size(); // 项数
            double sum = 0.0;

            // 累加每一项的得分
            for (const auto& item : level3_check_results) {
                double importantLevel = std::stod(item.importantLevel) / 3;

                // 通过映射表获取合规等级
                double complyLevel = 0.0; // 默认值
                auto it = complyLevelMapping.find(item.tmp_IsComply);
                if (it != complyLevelMapping.end()) {
                    complyLevel = it->second;
                }

                // 如果是pending状态，可以选择跳过或者作为不符合处理
                if (complyLevel < 0) {
                    // 如果遇到pending状态，将其视为不符合(0.0)
                    complyLevel = 0.0;
                }

                sum += importantLevel * (1.0 - complyLevel);

                // 输出每一项的计算值用于调试（可选）
                std::cout << "Item " << item.item_id << ": importantLevel = " << importantLevel
                    << ", complyLevel = " << complyLevel
                    << ", contribution = " << importantLevel * (1.0 - complyLevel) << std::endl;
            }

            // 输出总和用于调试
            std::cout << "Total sum: " << sum << std::endl;

            // 计算最终评分
            assetInfo.M = 100.0 - (100.0 * sum / n);

            //获取有哪些检测项没做
            assetInfo.undo_BaseLine = getUncheckedBaselineItems(ip, pool);
            //获取有哪些三级等保检测项没做
            assetInfo.undo_level3BaseLine = getUncheckedLevel3Items(ip, pool);

            allAssets.push_back(assetInfo);
        }
    }
    catch (const std::exception& ex) {
        console->error("getAllAssetsFullInfo error: {}", ex.what());
    }

    return allAssets;
}


bool DatabaseHandler::isAssetGroupExists(const std::string& group_name, ConnectionPool& pool) {
    try {
        auto session_ptr = pool.getConnection();  // std::shared_ptr<mysqlx::Session>
        mysqlx::Session& session = *session_ptr;

        std::string query = "SELECT COUNT(*) FROM asset_group WHERE group_name = ?";
        auto result = session.sql(query).bind(group_name).execute();
        auto row = result.fetchOne();
        return row[0].get<int>() > 0;
    }
    catch (const mysqlx::Error& err) {
        console->error("[DB] isAssetGroupExists failed: {}", err.what());
        return false;
    }
}

int DatabaseHandler::createAssetGroup(const std::string& group_name, const std::string& description, ConnectionPool& pool) {
    try {
        auto session_ptr = pool.getConnection();  // std::shared_ptr<mysqlx::Session>
        mysqlx::Session& session = *session_ptr;

        std::string insert = "INSERT INTO asset_group (group_name, description) VALUES (?, ?)";
        auto result = session.sql(insert).bind(group_name, description).execute();
        return static_cast<int>(result.getAutoIncrementValue());
    }
    catch (const mysqlx::Error& err) {
        console->error("[DB] createAssetGroup failed: {}", err.what());
        throw;
    }
}

std::vector<std::pair<int, std::string>> DatabaseHandler::getAllAssetGroups(ConnectionPool& pool) {
    std::vector<std::pair<int, std::string>> groups;

    try {
        auto session_ptr = pool.getConnection();  // std::shared_ptr<mysqlx::Session>
        mysqlx::Session& session = *session_ptr;

        std::string query = "SELECT id, group_name FROM asset_group ORDER BY id ASC";
        auto result = session.sql(query).execute();

        for (auto row : result) {
            int id = row[0].get<int>();
            std::string name = row[1].get<std::string>();
            groups.emplace_back(id, name);
        }

    }
    catch (const mysqlx::Error& err) {
        console->error("[DB] getAllAssetGroups failed: {}", err.what());
        throw;
    }

    return groups;
}

bool DatabaseHandler::updateAssetGroup(const std::string& ip, int group_id, bool is_null, ConnectionPool& pool) {
    try {
        auto session_ptr = pool.getConnection();  // std::shared_ptr<mysqlx::Session>
        mysqlx::Session& session = *session_ptr;

        // 检查 IP 是否存在
        auto check = session.sql("SELECT COUNT(*) FROM scan_host_result WHERE ip = ?").bind(ip).execute();
        if (check.fetchOne()[0].get<int>() == 0) {
            return false; // IP 不存在
        }

        if (!is_null) {
            // 检查 group_id 是否存在
            auto group_check = session.sql("SELECT COUNT(*) FROM asset_group WHERE id = ?")
                .bind(group_id).execute();
            if (group_check.fetchOne()[0].get<int>() == 0) {
                return false;
            }

            session.sql("UPDATE scan_host_result SET group_id = ? WHERE ip = ?")
                .bind(group_id, ip).execute();
        }
        else {
            // 设置为 NULL
            session.sql("UPDATE scan_host_result SET group_id = NULL WHERE ip = ?")
                .bind(ip).execute();
        }

        return true;

    }
    catch (const mysqlx::Error& err) {
        console->error("[DB] updateAssetGroup failed: {}", err.what());
        return false;
    }
}


bool DatabaseHandler::renameAssetGroup(int group_id, const std::string& new_name, ConnectionPool& pool) {
    try {
        auto session_ptr = pool.getConnection();  // std::shared_ptr<mysqlx::Session>
        mysqlx::Session& session = *session_ptr;


        // 检查是否存在此 ID
        auto check = session.sql("SELECT COUNT(*) FROM asset_group WHERE id = ?").bind(group_id).execute();
        if (check.fetchOne()[0].get<int>() == 0) {
            return false;
        }

        // 检查是否已存在该名字
        auto dup = session.sql("SELECT COUNT(*) FROM asset_group WHERE group_name = ? AND id != ?")
            .bind(new_name, group_id).execute();
        if (dup.fetchOne()[0].get<int>() > 0) {
            return false;
        }

        session.sql("UPDATE asset_group SET group_name = ? WHERE id = ?")
            .bind(new_name, group_id).execute();

        return true;

    }
    catch (const mysqlx::Error& err) {
        console->error("[DB] renameAssetGroup failed: {}", err.what());
        return false;
    }
}

bool DatabaseHandler::deleteAssetGroup(int group_id, bool deleteAssets, ConnectionPool& pool) {
    try {
        auto session_ptr = pool.getConnection();  // std::shared_ptr<mysqlx::Session>
        mysqlx::Session& session = *session_ptr;

        // 先检查资产组是否存在
        auto check = session.sql("SELECT COUNT(*) FROM asset_group WHERE id = ?").bind(group_id).execute();
        if (check.fetchOne()[0].get<int>() == 0) {
            return false;
        }

        if (deleteAssets) {
            // 删除资产组下的所有资产（IP）
            session.sql("DELETE FROM scan_host_result WHERE group_id = ?")
                .bind(group_id).execute();
        }
        else {
            // 仅解除资产归属
            session.sql("UPDATE scan_host_result SET group_id = NULL WHERE group_id = ?")
                .bind(group_id).execute();
        }

        // 删除资产组本身
        session.sql("DELETE FROM asset_group WHERE id = ?").bind(group_id).execute();

        return true;
    }
    catch (const mysqlx::Error& err) {
        console->error("[DB] deleteAssetGroup failed: {}", err.what());
        return false;
    }
}

