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

// �� Redis ���л�ȡ����
std::string pop_task_from_redis(redisContext* redis_client) {

    const int timeout_seconds = 1;  // ���ó�ʱʱ�䣬��λ��

    // ��ȡ���г��Ȳ���ӡ
    redisReply* length_reply = (redisReply*)redisCommand(redis_client, "LLEN POC_TASK_QUEUE");
    if (length_reply == nullptr) {
        console->error("[pop_task_from_redis] Failed to get queue length: {}", redis_client->errstr);
        system_logger->error("[pop_task_from_redis] Failed to get queue length: {}", redis_client->errstr);
        return "";
    }
    long long queue_length = length_reply->integer;
    console->info("[pop_task_from_redis] Current queue length: {}", queue_length);
    freeReplyObject(length_reply);

    // �������Ƿ�Ϊ��
    if (queue_length == 0) {
        console->info("[pop_task_from_redis] Queue is empty, no task to pop.");
        return "";
    }


    // ���Ե�������
    redisReply* reply = (redisReply*)redisCommand(redis_client, "BRPOP POC_TASK_QUEUE %d", timeout_seconds);
    if (reply == nullptr) {
        console->error("[pop_task_from_redis] Redis command failed: {}", redis_client->errstr);
        system_logger->error("[pop_task_from_redis] Redis command failed: {}", redis_client->errstr);
        return "";
    }

    // ��鷵�ص������Ƿ�Ϊ��
    if (reply->type == REDIS_REPLY_NIL) {
        console->info("[pop_task_from_redis] No task data found (RPOP returned NIL).");
        freeReplyObject(reply);
        return "";
    }

    // ������Ҫ������ reply->str �Ƿ�Ϊ nullptr
    if (reply->type == REDIS_REPLY_STRING && reply->str == nullptr) {
        console->error("[pop_task_from_redis] Redis reply string is null although type is REDIS_REPLY_STRING.");
        system_logger->error("[pop_task_from_redis] Redis reply string is null although type is REDIS_REPLY_STRING.");
        freeReplyObject(reply);
        return "";
    }

    cout << "pop_task : " << (reply->str == nullptr) << endl;

    // �ٴμ�� reply->str �Ƿ�Ϊ nullptr
    if (reply->str == nullptr) {
        console->error("[pop_task_from_redis] Redis reply string is null, returning empty string.");
        system_logger->error("[pop_task_from_redis] Redis reply string is null, returning empty string.");
        freeReplyObject(reply);
        return "";
    }

    // ���������Ϣ����ӡ���ص���������
    console->info("[pop_task_from_redis] Popped task data: {}", reply->str);

    // ��ȡ�������ݲ��ͷ� Redis �ظ�����
    std::string task_data(reply->str);
    freeReplyObject(reply);

    return task_data;


    /* �ɰ棺���Թ�
    if (reply->type == REDIS_REPLY_STRING) {
        std::string task_data = reply->str;
        console->info("[pop_task_from_redis] Task data: {}", task_data);
        freeReplyObject(reply);
        return task_data;
    }
    else {
        console->info("[pop_task_from_redis] No task data found (empty response).");;
        freeReplyObject(reply);
        return "";
    }*/
}


// �ȴ������ӽ������
for (pid_t pid : child_pids) {
    int status;
    pid_t terminated_pid = waitpid(pid, &status, 0);
    if (terminated_pid > 0) {
        if (WIFEXITED(status)) {
            system_logger->info("[Parent Process] Child process with PID: {} exited normally with status: {}", terminated_pid, WEXITSTATUS(status));
            console->debug("[Parent Process] Child process with PID: {} exited normally with status: {}", terminated_pid, WEXITSTATUS(status));
        }
        else if (WIFSIGNALED(status)) {
            console->debug("[Parent Process] Child process with PID: {} was terminated by signal: {}", terminated_pid, WTERMSIG(status));
        }
    }
    else {
        console->error("[Parent Process] Failed to wait for child process with PID: {}", pid);
        system_logger->error("[Parent Process] Failed to wait for child process with PID: {}", pid);
    }
}

