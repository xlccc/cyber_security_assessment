////获取ip对应的ScanHostResult
//ScanHostResult DatabaseHandler::getScanHostResult(const std::string& ip, ConnectionPool& pool) {
//    ScanHostResult oldScanResult;
//    oldScanResult.ip = ip;
//
//    try {
//        auto conn = pool.getConnection();  // 获取连接
//
//        // 查询 scan_host_result 表获取基本信息
//        mysqlx::SqlResult result = conn->sql("SELECT id, scan_time, alive, expire_time FROM scan_host_result WHERE ip = ?")
//            .bind(ip).execute();
//        mysqlx::Row row = result.fetchOne();
//        if (!row) {
//            std::cerr << "未找到对应 IP 的主机记录：" << ip << std::endl;
//            return oldScanResult;
//        }
//        int shr_id = row[0];  // 获取主机ID
//        oldScanResult.scan_time = row[1].get<std::string>();
//
//        // 查询 os_info 表获取操作系统信息
//        result = conn->sql("SELECT os_version FROM os_info WHERE shr_id = ?")
//            .bind(shr_id).execute();
//        while (mysqlx::Row osRow = result.fetchOne()) {
//            oldScanResult.os_matches.push_back(osRow[0].get<std::string>());
//        }
//
//        // 查询 open_ports 表获取端口信息
//        result = conn->sql("SELECT port, protocol, status, service_name, product, version, software_type FROM open_ports WHERE shr_id = ?")
//            .bind(shr_id).execute();
//        while (mysqlx::Row portRow = result.fetchOne()) {
//            ScanResult portResult;
//            portResult.portId = std::to_string(portRow[0].get<int>());
//            portResult.protocol = portRow[1].get<std::string>();
//            portResult.status = portRow[2].get<std::string>();
//            portResult.service_name = portRow[3].get<std::string>();
//            portResult.product = portRow[4].get<std::string>();
//            portResult.version = portRow[5].get<std::string>();
//            portResult.softwareType = portRow[6].get<std::string>();
//            oldScanResult.ports.push_back(portResult);
//        }
//
//        // 查询 host_cpe 表获取 CPE 信息
//        result = conn->sql("SELECT cpe FROM host_cpe WHERE shr_id = ?")
//            .bind(shr_id).execute();
//        while (mysqlx::Row cpeRow = result.fetchOne()) {
//            std::string cpe = cpeRow[0].get<std::string>();
//            // 这里需要根据 CPE 进一步查询相关的 Vuln 信息，可根据实际情况实现
//            // 目前先简单处理，不填充 cpes 和 vuln_result
//        }
//
//    }
//    catch (const mysqlx::Error& err) {
//        std::cerr << "数据库错误: " << err.what() << std::endl;
//    }
//    catch (std::exception& ex) {
//        std::cerr << "异常: " << ex.what() << std::endl;
//    }
//
//    return oldScanResult;
//}
//
//// 从 Redis 队列获取任务
//std::string pop_task_from_redis(redisContext* redis_client) {
//
//    const int timeout_seconds = 1;  // 设置超时时间，单位秒
//
//    // 获取队列长度并打印
//    redisReply* length_reply = (redisReply*)redisCommand(redis_client, "LLEN POC_TASK_QUEUE");
//    if (length_reply == nullptr) {
//        console->error("[pop_task_from_redis] Failed to get queue length: {}", redis_client->errstr);
//        system_logger->error("[pop_task_from_redis] Failed to get queue length: {}", redis_client->errstr);
//        return "";
//    }
//    long long queue_length = length_reply->integer;
//    console->info("[pop_task_from_redis] Current queue length: {}", queue_length);
//    freeReplyObject(length_reply);
//
//    // 检查队列是否为空
//    if (queue_length == 0) {
//        console->info("[pop_task_from_redis] Queue is empty, no task to pop.");
//        return "";
//    }
//
//
//    // 尝试弹出任务
//    redisReply* reply = (redisReply*)redisCommand(redis_client, "BRPOP POC_TASK_QUEUE %d", timeout_seconds);
//    if (reply == nullptr) {
//        console->error("[pop_task_from_redis] Redis command failed: {}", redis_client->errstr);
//        system_logger->error("[pop_task_from_redis] Redis command failed: {}", redis_client->errstr);
//        return "";
//    }
//
//    // 检查返回的数据是否为空
//    if (reply->type == REDIS_REPLY_NIL) {
//        console->info("[pop_task_from_redis] No task data found (RPOP returned NIL).");
//        freeReplyObject(reply);
//        return "";
//    }
//
//    // 这里需要额外检查 reply->str 是否为 nullptr
//    if (reply->type == REDIS_REPLY_STRING && reply->str == nullptr) {
//        console->error("[pop_task_from_redis] Redis reply string is null although type is REDIS_REPLY_STRING.");
//        system_logger->error("[pop_task_from_redis] Redis reply string is null although type is REDIS_REPLY_STRING.");
//        freeReplyObject(reply);
//        return "";
//    }
//
//    cout << "pop_task : " << (reply->str == nullptr) << endl;
//
//    // 再次检查 reply->str 是否为 nullptr
//    if (reply->str == nullptr) {
//        console->error("[pop_task_from_redis] Redis reply string is null, returning empty string.");
//        system_logger->error("[pop_task_from_redis] Redis reply string is null, returning empty string.");
//        freeReplyObject(reply);
//        return "";
//    }
//
//    // 输出调试信息：打印返回的任务数据
//    console->info("[pop_task_from_redis] Popped task data: {}", reply->str);
//
//    // 获取任务数据并释放 Redis 回复对象
//    std::string task_data(reply->str);
//    freeReplyObject(reply);
//
//    return task_data;
//
//
//    /* 旧版：测试过
//    if (reply->type == REDIS_REPLY_STRING) {
//        std::string task_data = reply->str;
//        console->info("[pop_task_from_redis] Task data: {}", task_data);
//        freeReplyObject(reply);
//        return task_data;
//    }
//    else {
//        console->info("[pop_task_from_redis] No task data found (empty response).");;
//        freeReplyObject(reply);
//        return "";
//    }*/
//}
//
//
//// 等待所有子进程完成
//for (pid_t pid : child_pids) {
//    int status;
//    pid_t terminated_pid = waitpid(pid, &status, 0);
//    if (terminated_pid > 0) {
//        if (WIFEXITED(status)) {
//            system_logger->info("[Parent Process] Child process with PID: {} exited normally with status: {}", terminated_pid, WEXITSTATUS(status));
//            console->debug("[Parent Process] Child process with PID: {} exited normally with status: {}", terminated_pid, WEXITSTATUS(status));
//        }
//        else if (WIFSIGNALED(status)) {
//            console->debug("[Parent Process] Child process with PID: {} was terminated by signal: {}", terminated_pid, WTERMSIG(status));
//        }
//    }
//    else {
//        console->error("[Parent Process] Failed to wait for child process with PID: {}", pid);
//        system_logger->error("[Parent Process] Failed to wait for child process with PID: {}", pid);
//    }
//}
//
