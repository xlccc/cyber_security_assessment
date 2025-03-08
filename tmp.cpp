//��ȡip��Ӧ��ScanHostResult
ScanHostResult DatabaseHandler::getScanHostResult(const std::string& ip, ConnectionPool& pool) {
    ScanHostResult oldScanResult;
    oldScanResult.ip = ip;

    try {
        auto conn = pool.getConnection();  // ��ȡ����

        // ��ѯ scan_host_result ���ȡ������Ϣ
        mysqlx::SqlResult result = conn->sql("SELECT id, scan_time, alive, expire_time FROM scan_host_result WHERE ip = ?")
            .bind(ip).execute();
        mysqlx::Row row = result.fetchOne();
        if (!row) {
            std::cerr << "δ�ҵ���Ӧ IP ��������¼��" << ip << std::endl;
            return oldScanResult;
        }
        int shr_id = row[0];  // ��ȡ����ID
        oldScanResult.scan_time = row[1].get<std::string>();

        // ��ѯ os_info ���ȡ����ϵͳ��Ϣ
        result = conn->sql("SELECT os_version FROM os_info WHERE shr_id = ?")
            .bind(shr_id).execute();
        while (mysqlx::Row osRow = result.fetchOne()) {
            oldScanResult.os_matches.push_back(osRow[0].get<std::string>());
        }

        // ��ѯ open_ports ���ȡ�˿���Ϣ
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

        // ��ѯ host_cpe ���ȡ CPE ��Ϣ
        result = conn->sql("SELECT cpe FROM host_cpe WHERE shr_id = ?")
            .bind(shr_id).execute();
        while (mysqlx::Row cpeRow = result.fetchOne()) {
            std::string cpe = cpeRow[0].get<std::string>();
            // ������Ҫ���� CPE ��һ����ѯ��ص� Vuln ��Ϣ���ɸ���ʵ�����ʵ��
            // Ŀǰ�ȼ򵥴�������� cpes �� vuln_result
        }

    }
    catch (const mysqlx::Error& err) {
        std::cerr << "���ݿ����: " << err.what() << std::endl;
    }
    catch (std::exception& ex) {
        std::cerr << "�쳣: " << ex.what() << std::endl;
    }

    return oldScanResult;
}
