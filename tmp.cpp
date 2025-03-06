//获取ip对应的ScanHostResult
ScanHostResult DatabaseHandler::getScanHostResult(const std::string& ip, ConnectionPool& pool) {
    ScanHostResult oldScanResult;
    oldScanResult.ip = ip;

    try {
        auto conn = pool.getConnection();  // 获取连接

        // 查询 scan_host_result 表获取基本信息
        mysqlx::SqlResult result = conn->sql("SELECT id, scan_time, alive, expire_time FROM scan_host_result WHERE ip = ?")
            .bind(ip).execute();
        mysqlx::Row row = result.fetchOne();
        if (!row) {
            std::cerr << "未找到对应 IP 的主机记录：" << ip << std::endl;
            return oldScanResult;
        }
        int shr_id = row[0];  // 获取主机ID
        oldScanResult.scan_time = row[1].get<std::string>();

        // 查询 os_info 表获取操作系统信息
        result = conn->sql("SELECT os_version FROM os_info WHERE shr_id = ?")
            .bind(shr_id).execute();
        while (mysqlx::Row osRow = result.fetchOne()) {
            oldScanResult.os_matches.push_back(osRow[0].get<std::string>());
        }

        // 查询 open_ports 表获取端口信息
        result = conn->sql("SELECT port, protocol, status, service_name, product, version, software_type FROM open_ports WHERE shr_id = ?")
            .bind(shr_id).execute();
        while (mysqlx::Row portRow = result.fetchOne()) {
            ScanResult portResult;
            portResult.portId = std::to_string(portRow[0].get<int>());
            portResult.protocol = portRow[1].get<std::string>();
            portResult.status = portRow[2].get<std::string>();
            portResult.service_name = portRow[3].get<std::string>();
            portResult.product = portRow[4].get<std::string>();
            portResult.version = portRow[5].get<std::string>();
            portResult.softwareType = portRow[6].get<std::string>();
            oldScanResult.ports.push_back(portResult);
        }

        // 查询 host_cpe 表获取 CPE 信息
        result = conn->sql("SELECT cpe FROM host_cpe WHERE shr_id = ?")
            .bind(shr_id).execute();
        while (mysqlx::Row cpeRow = result.fetchOne()) {
            std::string cpe = cpeRow[0].get<std::string>();
            // 这里需要根据 CPE 进一步查询相关的 Vuln 信息，可根据实际情况实现
            // 目前先简单处理，不填充 cpes 和 vuln_result
        }

    }
    catch (const mysqlx::Error& err) {
        std::cerr << "数据库错误: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "异常: " << ex.what() << std::endl;
    }

    return oldScanResult;
}
