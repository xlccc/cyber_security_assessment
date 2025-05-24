#include "ServerManager.h"

using namespace web;
using namespace web::http;
using namespace web::http::experimental::listener;
using namespace concurrency::streams;

ServerManager::ServerManager()
    : localConfig{
        CONFIG.getDbHost(),
        CONFIG.getDbPort(),
        CONFIG.getDbUser(),
        CONFIG.getDbPassword(),
        CONFIG.getDbSchema()
    },
    pool(localConfig),    // 使用 localConfig 初始化 pool
    //dbManager(CONFIG.getPocDatabasePath())    // 原有的 dbManager 初始化
    dbManager(pool, dbHandler_)
{
    globalThreadPool = std::make_shared<ThreadPool>(CONFIG.getThreadCount());// 线程池创建
    system_logger->info("Global ThreadPool initialized with {} threads.", CONFIG.getThreadCount());

    utility::string_t address = utility::conversions::to_string_t(CONFIG.getServerUrl());
    uri_builder uri(address);
    auto addr = uri.to_uri().to_string();
    listener = std::make_unique<http_listener>(addr);

    listener->support(methods::OPTIONS, std::bind(&ServerManager::handle_options, this, std::placeholders::_1));
    listener->support(methods::GET, std::bind(&ServerManager::handle_request, this, std::placeholders::_1));
    listener->support(methods::POST, std::bind(&ServerManager::handle_request, this, std::placeholders::_1));
    listener->support(methods::PUT, std::bind(&ServerManager::handle_request, this, std::placeholders::_1));
    listener->support(methods::DEL, std::bind(&ServerManager::handle_request, this, std::placeholders::_1));

    // 检查并创建临时文件
    struct stat buffer;
    if (stat(CONFIG.getPocTempFile().c_str(), &buffer) != 0) {
        std::ofstream temp_file(CONFIG.getPocTempFile(), std::ios::binary);
        if (!temp_file.is_open()) {
            throw std::runtime_error("Failed to create temporary file");
        }
        temp_file.close();
    }
    //if (stat(TEMP_FILENAME.c_str(), &buffer) != 0) {
    //    std::ofstream temp_file(TEMP_FILENAME, std::ios::binary);
    //    if (!temp_file.is_open()) {
    //        throw std::runtime_error("Failed to create temporary file");
    //    }
    //    temp_file.close();
    //}

}

void ServerManager::open_listener() {
    listener->open().then([this]() {
        console->info("Starting to listen at: {}", listener->uri().to_string());
        system_logger->info("Starting to listen at: {}", listener->uri().to_string());

        }).wait();
}

void ServerManager::handle_options(http_request request) {
    http_response response(status_codes::OK);
    response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
    response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
    response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
    request.reply(response);
}

void ServerManager::handle_request(http_request request) {
    auto path = uri::split_path(uri::decode(request.relative_uri().path()));

    // 打印接收到的请求方法和路径
    system_logger->info("Received {} request for: {}", request.method(), request.relative_uri().to_string());


    if (path.empty()) {
        request.reply(status_codes::NotFound, _XPLATSTR("Path not found"));
        return;
    }

    auto first_segment = path[0];
    auto second_segment = (path.size() > 1) ? path[1] : "";
    //用于HTTP LOG回显，在无回显的POC中得到有效验证信息
    if (first_segment == _XPLATSTR("poc_callback")) {
        log_poc_callback(request);
    }
    //返回基线检测的结果
    else if (first_segment == _XPLATSTR("userinfo") && request.method() == methods::GET) {
        handle_get_userInfo(request);//
    }
    else if (first_segment == _XPLATSTR("tmpUserinfo") && request.method() == methods::GET) {
        handle_get_tmpUserInfo(request);//
    }
    //基线检测的账号密码登录
    else if (first_segment == _XPLATSTR("login") && request.method() == methods::POST) {
        handle_post_login(request);//
    }
    //三级等保检测的账号密码登录
    else if (first_segment == _XPLATSTR("level3Login") && request.method() == methods::POST) {
        handle_post_level3(request);//
    }
    //返回三级等保检测的结果
    else if (first_segment == _XPLATSTR("level3Userinfo") && request.method() == methods::GET) {
        handle_get_level3UserInfo(request);//
    }
    //返回三级等保当前检测的结果
    else if (first_segment == _XPLATSTR("level3TmpUserinfo") && request.method() == methods::GET) {
        handle_get_level3TmpUserInfo(request);//
    }

    //主机发现
    else if (first_segment == _XPLATSTR("host_discovery") && request.method() == methods::POST) {
        handle_host_discovery(request);
    }
    //返回主机所有可能的cve漏洞，调用cve-search
    else if (first_segment == _XPLATSTR("cveScan") && request.method() == methods::GET) {
        handle_get_cve_scan(request);
    }
    //返回目标IP主机的结果
    else if (first_segment == _XPLATSTR("ScanHostResult") && request.method() == methods::GET) {
        handle_get_ScanHostResult(request);
    }
    else if (first_segment == _XPLATSTR("getAllData") && request.method() == methods::GET) {
        handle_get_all_data(request);
    }
    else if (first_segment == _XPLATSTR("getVaildPOCData") && request.method() == methods::GET) {
        handle_get_vaild_poc_data(request);
    }
    else if (first_segment == _XPLATSTR("searchData") && request.method() == methods::GET) {
        handle_search_data(request);
    }
    else if (first_segment == _XPLATSTR("insertData") && request.method() == methods::POST) {
        handle_post_insert_data(request);
    }
    else if (first_segment == _XPLATSTR("updateDataById") && request.method() == methods::PUT) {
        handle_put_update_data_by_id(request);
    }
    else if (first_segment == _XPLATSTR("deleteDataById") && request.method() == methods::DEL) {
        handle_delete_data_by_id(request);
    }
    else if (first_segment == _XPLATSTR("getNmapIp") && request.method() == methods::POST) {
        handle_post_get_Nmap(request);
    }
    else if (first_segment == _XPLATSTR("getWeakPassword") && request.method() == methods::POST) {
        handle_post_hydra(request);
    }
    else if (first_segment == _XPLATSTR("testWeakPassword") && request.method() == methods::POST) {
        handle_post_testWeak(request);
    }

    else if (first_segment == _XPLATSTR("getPOCContent") && request.method() == methods::GET) {
        handle_get_poc_content(request);    //查看POC代码
    }
    else if (first_segment == _XPLATSTR("pocSearch") && request.method() == methods::POST) {
        handle_post_poc_search(request);
    }
    else if (first_segment == _XPLATSTR("pocVerify") && request.method() == methods::POST) {
        handle_post_poc_verify_new(request);
    }
    else if (first_segment == _XPLATSTR("updatePoc") && request.method() == methods::PUT) {
        update_poc_by_cve(request);
    }
    //根据前端传来的进行等级保护计算
    else if (first_segment == _XPLATSTR("classifyProtect") && request.method() == methods::POST) {
        handle_post_classify_protect(request);
    }
    //    vector<scoreMeasure> vecScoreMeasure 转json传回前端
    else if (first_segment == _XPLATSTR("classifyProtectGetRes") && request.method() == methods::GET) {
        handle_get_classify_protect(request);
    }
    //根据前端传来的vecScore进行等级数据库操作修改
    else if (first_segment == _XPLATSTR("updateLevel3Protect") && request.method() == methods::POST) {
        handle_post_updateLevel3_protect(request);//
    }
    //根据前端传来的vecScore进行等级数据库操作修改
    else if (first_segment == _XPLATSTR("updateBaseLineProtect") && request.method() == methods::POST) {
        handle_post_updateBaseLine_protect(request);//
    }

    else if (first_segment == _XPLATSTR("pocExcute") && request.method() == methods::POST) {
        handle_post_poc_excute(request);
    }
    // /pocScan
    else if (first_segment == _XPLATSTR("pocScan") && second_segment.empty() && request.method() == methods::POST) {
        handle_post_poc_scan(request);
    }
    // /pocScan/mergeResults
    else if (first_segment == _XPLATSTR("pocScan") && second_segment == _XPLATSTR("mergeResults") && request.method() == methods::POST) {
        handle_merge_vuln_results(request);
    }
    // /pocScan/autoSelectPoc
    else if (first_segment == _XPLATSTR("pocScan") && second_segment == _XPLATSTR("autoSelectPoc") && request.method() == methods::POST) {
        handle_auto_select_poc(request);
    }
    else if (first_segment == _XPLATSTR("getAllAssetsVulnData") && request.method() == methods::GET) {
        handle_get_all_assets_vuln_data(request);
    }
    else if (first_segment == _XPLATSTR("mysqlScan") && request.method() == methods::POST) {
		handle_post_mysql_scan(request);
	}
    else if (first_segment == _XPLATSTR("getAliveHosts") && request.method() == methods::GET) {
		handle_get_alive_hosts(request);
	}
    else if (first_segment == _XPLATSTR("redisScan") && request.method() == methods::GET) {
        redis_get_scan(request);
    }
    else if (first_segment == _XPLATSTR("printTest") && request.method() == methods::GET) {
        handle_get_test(request);
    }
    else if (first_segment == _XPLATSTR("getAllAssetInfo") && request.method() == methods::GET) {
        handle_get_all_assets_info(request);
    }
    else if (first_segment == _XPLATSTR("getSecurityCheckByIp") && request.method() == methods::GET) {
        handle_get_security_check_by_ip(request);
    }
    else if (first_segment == _XPLATSTR("getWeakPasswordByIp") && request.method() == methods::GET) {
        handle_get_weak_password_by_ip(request);
    }
    //获取等保分数
    else if (first_segment == _XPLATSTR("getlevel3ResultByIp") && request.method() == methods::GET) {
        handle_get_level3Result(request);
    }
    //获取基线检测分数
    else if (first_segment == _XPLATSTR("getBaseLineResultByIp") && request.method() == methods::GET) {
        handle_get_baseLineResult(request);
    }
    else if (first_segment == _XPLATSTR("getAllWeakPassword") && request.method() == methods::GET) {
        handle_get_all_weak_passwords(request);
    }

    else if (first_segment == _XPLATSTR("poc") && second_segment == _XPLATSTR("getAllVulnTypes") && request.method() == methods::GET) {
        handle_get_vuln_types(request);
    }
    else if (first_segment == _XPLATSTR("poc") && second_segment == _XPLATSTR("editVulnType") && request.method() == methods::POST) {
        handle_edit_vuln_type(request);
    }
    
    
    else {
        request.reply(status_codes::NotFound, _XPLATSTR("Path not found"));
    }
}

void ServerManager::redis_get_scan(http_request request) {
    
    std::cout << check_redis_unauthorized("root", "12341234", "12341234", CONFIG.getServerIp()) << std::endl;
    std::cout << check_pgsql_unauthorized("root", "12341234", "postgres", "12341234", CONFIG.getServerIp()) << std::endl;
    request.reply(web::http::status_codes::OK, "result");
}

void ServerManager::handle_get_test(http_request request)
{
    try {
        // 解析请求中的IP参数
        auto query = uri::split_query(request.request_uri().query());
        auto it = query.find(_XPLATSTR("ip"));
        if (it == query.end()) {
            request.reply(status_codes::BadRequest, _XPLATSTR("Missing 'ip' parameter"));
            return;
        }

        // 获取IP地址并检查是否为空
        std::string ip = utility::conversions::to_utf8string(it->second);
        if (ip.empty()) {
            request.reply(status_codes::BadRequest, _XPLATSTR("Empty IP parameter"));
            return;
        }

        // 使用从请求中获取的IP地址
        ScanHostResult result = dbHandler_.getScanHostResult(ip, pool);

        // 打印结果
        printScanHostResult(result);

        // 使用已有的函数将ScanHostResult转换为JSON
        web::json::value response = ScanHostResult_to_json(result);

        // 返回结果
        http_response http_resp(status_codes::OK);
        http_resp.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
        http_resp.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, OPTIONS"));
        http_resp.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
        http_resp.set_body(response);
        request.reply(http_resp);
    }
    catch (const std::exception& e) {
        std::cerr << "处理扫描主机结果请求时出错: " << e.what() << std::endl;
        request.reply(status_codes::InternalError,
            web::json::value::string(utility::conversions::to_string_t("内部服务器错误: " + std::string(e.what()))));
    }
}



void ServerManager::printScanHostResult(const ScanHostResult& result)
{
    
        std::cout << "========= 主机扫描结果 =========" << std::endl;
        std::cout << "IP地址: " << result.ip << std::endl;
        std::cout << "URL: " << result.url << std::endl;
        std::cout << "扫描时间: " << result.scan_time << std::endl;

        // 打印操作系统信息
        std::cout << "\n-- 操作系统信息 --" << std::endl;
        std::cout << "操作系统类型: " << result.os_type << std::endl;
        std::cout << "检测到的操作系统版本: ";
        for (const auto& os : result.os_matches) {
            std::cout << os << "  ";
        }
        std::cout << std::endl;

        // 打印主机CPE信息
        std::cout << "\n-- 主机CPE信息 --" << std::endl;
        std::cout << "CPE数量: " << result.cpes.size() << std::endl;
        for (const auto& cpe_entry : result.cpes) {
            std::cout << "CPE: " << cpe_entry.first << std::endl;
            std::cout << "  关联漏洞数量: " << cpe_entry.second.size() << std::endl;
            if (!cpe_entry.second.empty()) {
                std::cout << "  示例漏洞: " << cpe_entry.second[0].Vuln_id
                    << " - " << cpe_entry.second[0].vul_name << std::endl;
            }
        }

        // 打印主机漏洞信息
        std::cout << "\n-- 主机漏洞信息 --" << std::endl;
        std::cout << "漏洞总数: " << result.vuln_result.size() << std::endl;
        int count = 0;
        for (const auto& vuln : result.vuln_result) {
            count++;
            std::cout << "  漏洞 " << count << ": " << vuln.Vuln_id
                << " - " << vuln.vul_name << " (CVSS: " << vuln.CVSS << ")" << std::endl;
            //if (count >= 3) {
            //    std::cout << "  (显示前3条漏洞，共" << result.vuln_result.size() << "条)" << std::endl;
            //    break;
            //}
        }

        // 打印端口信息
        std::cout << "\n-- 端口信息 --" << std::endl;
        std::cout << "开放端口数: " << result.ports.size() << std::endl;
        for (const auto& port : result.ports) {
            std::cout << "  端口: " << port.portId << " (" << port.protocol
                << "/" << port.service_name << ")" << std::endl;
            std::cout << "    状态: " << port.status << std::endl;
            if (!port.product.empty())
                std::cout << "    产品: " << port.product << std::endl;
            if (!port.version.empty())
                std::cout << "    版本: " << port.version << std::endl;
            std::cout << "    漏洞数: " << port.vuln_result.size() << std::endl;

            // 只显示每个端口的前2个漏洞
            count = 0;
            for (const auto& vuln : port.vuln_result) {
                count++;
                std::cout << "      漏洞 " << count << ": " << vuln.Vuln_id
                    << " - " << vuln.vul_name << std::endl;
                //if (count >= 2 && port.vuln_result.size() > 2) {
                //    std::cout << "      (更多漏洞省略...)" << std::endl;
                //    break;
                //}
            }
        }

        std::cout << "\n========= 扫描结果摘要 =========" << std::endl;
        std::cout << "主机漏洞总数: " << result.vuln_result.size() << std::endl;

        // 计算所有端口漏洞总数
        int portVulnTotal = 0;
        for (const auto& port : result.ports) {
            portVulnTotal += port.vuln_result.size();
        }
        std::cout << "端口漏洞总数: " << portVulnTotal << std::endl;
        std::cout << "漏洞总数(主机+端口): " << (result.vuln_result.size() + portVulnTotal) << std::endl;
        std::cout << "开放端口数: " << result.ports.size() << std::endl;
    

}

// 将资产信息转换为JSON格式
web::json::value ServerManager::convertAssetInfoToJson(const AssetInfo& assetInfo)
{
    web::json::value result = web::json::value::object();
    result["ip"] = web::json::value::string(assetInfo.ip);
    // 在设置 JSON 时也要检查
    // 修改 JSON 设置部分
    if (std::isnan(assetInfo.M) || std::isinf(assetInfo.M)) {
        result["M"] = web::json::value::number(0.0);
    }
    else {
        result["M"] = web::json::value::number(assetInfo.M);
    }
    
    // 添加服务器信息
    web::json::value serverInfoObj = web::json::value::object();
    serverInfoObj["hostname"] = web::json::value::string(assetInfo.serverinfo.hostname);
    serverInfoObj["arch"] = web::json::value::string(assetInfo.serverinfo.arch);
    serverInfoObj["cpu"] = web::json::value::string(assetInfo.serverinfo.cpu);
    serverInfoObj["cpuPhysical"] = web::json::value::string(assetInfo.serverinfo.cpuPhysical);
    serverInfoObj["cpuCore"] = web::json::value::string(assetInfo.serverinfo.cpuCore);
    serverInfoObj["free"] = web::json::value::string(assetInfo.serverinfo.free);
    serverInfoObj["ProductName"] = web::json::value::string(assetInfo.serverinfo.ProductName);
    serverInfoObj["version"] = web::json::value::string(assetInfo.serverinfo.version);
    serverInfoObj["osName"] = web::json::value::string(assetInfo.serverinfo.osName);
    serverInfoObj["isInternet"] = web::json::value::string(assetInfo.serverinfo.isInternet);
    result["serverinfo"] = serverInfoObj;

    // 添加端口信息
    web::json::value portsArray = web::json::value::array(assetInfo.ports.size());
    for (size_t i = 0; i < assetInfo.ports.size(); i++) {
        web::json::value portObj = web::json::value::object();
        const PortInfo& port = assetInfo.ports[i];

        portObj["port"] = web::json::value::number(port.port);
        portObj["protocol"] = web::json::value::string(port.protocol);
        portObj["status"] = web::json::value::string(port.status);
        portObj["service_name"] = web::json::value::string(port.service_name);
        portObj["product"] = web::json::value::string(port.product);
        portObj["version"] = web::json::value::string(port.version);
        portObj["software_type"] = web::json::value::string(port.software_type);

        // 添加弱口令相关信息
        portObj["weak_username"] = web::json::value::string(port.weak_username);
        portObj["weak_password"] = web::json::value::string(port.weak_password);
        portObj["password_verified"] = web::json::value::boolean(port.password_verified);

        // 仅当验证时间不为空时添加
        if (!port.verify_time.empty()) {
            portObj["verify_time"] = web::json::value::string(port.verify_time);
        }

        portsArray[i] = portObj;
    }
    result["ports"] = portsArray;

    // 添加主机漏洞信息
    web::json::value hostVulnArray = web::json::value::array(assetInfo.host_vulnerabilities.size());
    for (size_t i = 0; i < assetInfo.host_vulnerabilities.size(); i++) {
        web::json::value vulnObj = web::json::value::object();
        const VulnerabilityInfo& vuln = assetInfo.host_vulnerabilities[i];
        vulnObj["vuln_id"] = web::json::value::string(vuln.vuln_id);
        vulnObj["vuln_name"] = web::json::value::string(vuln.vuln_name);
        vulnObj["cvss"] = web::json::value::string(vuln.cvss);
        vulnObj["summary"] = web::json::value::string(vuln.summary);
        vulnObj["vulExist"] = web::json::value::string(vuln.vulExist);
        vulnObj["softwareType"] = web::json::value::string(vuln.softwareType);
        vulnObj["vulType"] = web::json::value::string(vuln.vulType);
        hostVulnArray[i] = vulnObj;
    }
    result["host_vulnerabilities"] = hostVulnArray;

    // 添加端口漏洞信息
    web::json::value portVulnArray = web::json::value::array(assetInfo.port_vulnerabilities.size());
    for (size_t i = 0; i < assetInfo.port_vulnerabilities.size(); i++) {
        web::json::value vulnObj = web::json::value::object();
        const PortVulnerabilityInfo& vuln = assetInfo.port_vulnerabilities[i];
        vulnObj["port_id"] = web::json::value::number(vuln.port_id);
        vulnObj["vuln_id"] = web::json::value::string(vuln.vuln_id);
        vulnObj["vuln_name"] = web::json::value::string(vuln.vuln_name);
        vulnObj["cvss"] = web::json::value::string(vuln.cvss);
        vulnObj["summary"] = web::json::value::string(vuln.summary);
        vulnObj["vulExist"] = web::json::value::string(vuln.vulExist);
        vulnObj["softwareType"] = web::json::value::string(vuln.softwareType);
        vulnObj["vulType"] = web::json::value::string(vuln.vulType);
        vulnObj["service_name"] = web::json::value::string(vuln.service_name);
        portVulnArray[i] = vulnObj;
    }
    result["port_vulnerabilities"] = portVulnArray;
    // 添加基线检测摘要（普通基线）
    web::json::value baseline_summary = web::json::value::object();
    baseline_summary[_XPLATSTR("total_checks")] = web::json::value::number(assetInfo.baseline_summary.total_checks);
    baseline_summary[_XPLATSTR("compliant_items")] = web::json::value::number(assetInfo.baseline_summary.compliant_items);
    baseline_summary[_XPLATSTR("half_compliant_items")] = web::json::value::number(assetInfo.baseline_summary.half_compliant_items);
    baseline_summary[_XPLATSTR("non_compliant_items")] = web::json::value::number(assetInfo.baseline_summary.non_compliant_items);
    baseline_summary[_XPLATSTR("compliance_rate")] = web::json::value::number(assetInfo.baseline_summary.compliance_rate);
    baseline_summary[_XPLATSTR("critical_items")] = web::json::value::number(assetInfo.baseline_summary.critical_items);
    baseline_summary[_XPLATSTR("critical_compliant")] = web::json::value::number(assetInfo.baseline_summary.critical_compliant);
    baseline_summary[_XPLATSTR("high_items")] = web::json::value::number(assetInfo.baseline_summary.high_items);
    baseline_summary[_XPLATSTR("high_compliant")] = web::json::value::number(assetInfo.baseline_summary.high_compliant);
    baseline_summary[_XPLATSTR("medium_items")] = web::json::value::number(assetInfo.baseline_summary.medium_items);
    baseline_summary[_XPLATSTR("medium_compliant")] = web::json::value::number(assetInfo.baseline_summary.medium_compliant);
    result[_XPLATSTR("baseline_summary")] = baseline_summary;

    // 添加三级等保基线检测摘要
    web::json::value level3_baseline_summary = web::json::value::object();
    level3_baseline_summary[_XPLATSTR("total_checks")] = web::json::value::number(assetInfo.level3_baseline_summary.total_checks);
    level3_baseline_summary[_XPLATSTR("compliant_items")] = web::json::value::number(assetInfo.level3_baseline_summary.compliant_items);
    level3_baseline_summary[_XPLATSTR("half_compliant_items")] = web::json::value::number(assetInfo.level3_baseline_summary.half_compliant_items);
    level3_baseline_summary[_XPLATSTR("non_compliant_items")] = web::json::value::number(assetInfo.level3_baseline_summary.non_compliant_items);
    level3_baseline_summary[_XPLATSTR("compliance_rate")] = web::json::value::number(assetInfo.level3_baseline_summary.compliance_rate);
    level3_baseline_summary[_XPLATSTR("critical_items")] = web::json::value::number(assetInfo.level3_baseline_summary.critical_items);
    level3_baseline_summary[_XPLATSTR("critical_compliant")] = web::json::value::number(assetInfo.level3_baseline_summary.critical_compliant);
    level3_baseline_summary[_XPLATSTR("high_items")] = web::json::value::number(assetInfo.level3_baseline_summary.high_items);
    level3_baseline_summary[_XPLATSTR("high_compliant")] = web::json::value::number(assetInfo.level3_baseline_summary.high_compliant);
    level3_baseline_summary[_XPLATSTR("medium_items")] = web::json::value::number(assetInfo.level3_baseline_summary.medium_items);
    level3_baseline_summary[_XPLATSTR("medium_compliant")] = web::json::value::number(assetInfo.level3_baseline_summary.medium_compliant);
    result[_XPLATSTR("level3_baseline_summary")] = level3_baseline_summary;

    //添加检测项未作的情况
    web::json::value undoBaselineArray = web::json::value::array(assetInfo.undo_BaseLine.size());
    for (size_t i = 0; i < assetInfo.undo_BaseLine.size(); i++) {
        web::json::value itemObj = web::json::value::object();
        const event& item = assetInfo.undo_BaseLine[i];

        itemObj["item_id"] = web::json::value::number(item.item_id);
        itemObj["description"] = web::json::value::string(item.description);
        itemObj["basis"] = web::json::value::string(item.basis);
        itemObj["important_level"] = web::json::value::string(item.importantLevel);

        undoBaselineArray[i] = itemObj;
    }
    result["undo_baseline"] = undoBaselineArray;

    // 添加未完成的三级等保基线检查项
    web::json::value undoLevel3BaselineArray = web::json::value::array(assetInfo.undo_level3BaseLine.size());
    for (size_t i = 0; i < assetInfo.undo_level3BaseLine.size(); i++) {
        web::json::value itemObj = web::json::value::object();
        const event& item = assetInfo.undo_level3BaseLine[i];

        itemObj["item_id"] = web::json::value::number(item.item_id);
        itemObj["description"] = web::json::value::string(item.description);
        itemObj["basis"] = web::json::value::string(item.basis);
        itemObj["important_level"] = web::json::value::string(item.importantLevel);

        undoLevel3BaselineArray[i] = itemObj;
    }
    result["undo_level3_baseline"] = undoLevel3BaselineArray;
    return result;
}


web::json::value ServerManager::convertPortsToJson(const std::vector<PortInfo>& ports)
{
    web::json::value portsArray = web::json::value::array(ports.size());
    for (size_t i = 0; i < ports.size(); i++) {
        web::json::value portObj = web::json::value::object();
        const PortInfo& port = ports[i];

        portObj["port"] = web::json::value::number(port.port);
        portObj["protocol"] = web::json::value::string(port.protocol);
        portObj["status"] = web::json::value::string(port.status);
        portObj["service_name"] = web::json::value::string(port.service_name);
        portObj["product"] = web::json::value::string(port.product);
        portObj["version"] = web::json::value::string(port.version);
        portObj["software_type"] = web::json::value::string(port.software_type);

        // 添加弱口令相关信息
        portObj["weak_username"] = web::json::value::string(port.weak_username);
        portObj["weak_password"] = web::json::value::string(port.weak_password);
        portObj["password_verified"] = web::json::value::boolean(port.password_verified);

        // 仅当验证时间不为空时添加
        if (!port.verify_time.empty()) {
            portObj["verify_time"] = web::json::value::string(port.verify_time);
        }

        portsArray[i] = portObj;
    }
    return portsArray;
}


// 处理获取所有资产信息的HTTP请求
void ServerManager::handle_get_all_assets_info(http_request request)
{
    try {
        // 获取所有资产信息
        std::vector<AssetInfo> allAssets = dbHandler_.getAllAssetsInfo(pool);

        // 转换为JSON格式
        web::json::value response = web::json::value::array(allAssets.size());
        for (size_t i = 0; i < allAssets.size(); i++) {
            response[i] = convertAssetInfoToJson(allAssets[i]);
        }

        // 返回响应
        request.reply(status_codes::OK, response);
    }
    catch (const std::exception& ex) {
        std::cerr << "处理获取所有资产信息请求时发生异常: " << ex.what() << std::endl;
        request.reply(status_codes::InternalError, web::json::value::string("服务器内部错误"));
    }
    catch (...) {
        std::cerr << "处理获取所有资产信息请求时发生未知错误" << std::endl;
        request.reply(status_codes::InternalError, web::json::value::string("服务器内部错误"));
    }
}

// 处理获取单个IP资产信息的HTTP请求
void ServerManager::handle_get_asset_info(http_request request)
{
    try {
        // 从URL中获取IP参数
        std::string ip;
        auto params = uri::split_query(request.request_uri().query());
        auto it = params.find("ip");
        if (it != params.end()) {
            ip = it->second;
        }
        else {
            request.reply(status_codes::BadRequest, web::json::value::string("缺少IP参数"));
            return;
        }

        // 获取该IP的资产信息
        AssetInfo assetInfo = dbHandler_.getCompleteAssetInfo(ip, pool);

        // 转换为JSON格式并返回
        web::json::value response = convertAssetInfoToJson(assetInfo);
        request.reply(status_codes::OK, response);
    }
    catch (const std::exception& ex) {
        std::cerr << "处理获取单个资产信息请求时发生异常: " << ex.what() << std::endl;
        request.reply(status_codes::InternalError, web::json::value::string("服务器内部错误"));
    }
    catch (...) {
        std::cerr << "处理获取单个资产信息请求时发生未知错误" << std::endl;
        request.reply(status_codes::InternalError, web::json::value::string("服务器内部错误"));
    }
}

bool ServerManager::isServiceExistByIp(const std::string& ip, const std::string& service_name, ConnectionPool& pool)
{
    // 使用类的私有成员dbHandler_调用getServiceNameByIp方法
    std::vector<std::string> serviceNames = dbHandler_.getServiceNameByIp(ip, pool);

    // 遍历服务列表，查找是否存在指定的服务名
    for (const auto& name : serviceNames) {
        if (name == service_name) {
            return true; // 找到匹配的服务名
        }
    }

    return false; // 未找到匹配的服务名
}

void ServerManager::handle_get_userInfo(http_request request) {
    try {
        // 解析请求中的IP参数
        auto query = uri::split_query(request.request_uri().query());
        auto it = query.find(_XPLATSTR("ip"));
        if (it == query.end()) {
            request.reply(status_codes::BadRequest, _XPLATSTR("Missing 'ip' parameter"));
            return;
        }

        // 获取IP地址
        std::string ip = utility::conversions::to_utf8string(it->second);

        // 检查IP是否为空
        if (ip.empty()) {
            request.reply(status_codes::BadRequest, _XPLATSTR("Empty IP parameter"));
            return;
        }

        // 获取安全检查结果
        std::vector<event> check_results = dbHandler_.getSecurityCheckResults(ip, pool);//

        // 获取服务器信息
        ServerInfo server_info = dbHandler_.getServerInfoByIp(ip, pool);

        // 创建返回的JSON对象
        web::json::value response_json = web::json::value::object();

        // 将安全检查结果添加到JSON中
        web::json::value results_array = web::json::value::array();
        for (size_t i = 0; i < check_results.size(); ++i) {
            web::json::value result = web::json::value::object();
            result[_XPLATSTR("item_id")] = web::json::value::number(check_results[i].item_id);
            result[_XPLATSTR("description")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].description));
            result[_XPLATSTR("basis")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].basis));
            result[_XPLATSTR("command")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].command));
            result[_XPLATSTR("result")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].result));
            result[_XPLATSTR("IsComply")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].IsComply));
            result[_XPLATSTR("tmp_IsComply")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].tmp_IsComply));
            result[_XPLATSTR("recommend")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].recommend));
            result[_XPLATSTR("importantLevel")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].importantLevel));
            results_array[i] = result;
        }
        response_json[_XPLATSTR("checkResults")] = results_array;

        // 将服务器信息添加到JSON中
        web::json::value server_info_json = web::json::value::object();
        server_info_json[_XPLATSTR("hostname")] = web::json::value::string(utility::conversions::to_string_t(server_info.hostname));
        server_info_json[_XPLATSTR("arch")] = web::json::value::string(utility::conversions::to_string_t(server_info.arch));
        server_info_json[_XPLATSTR("cpu")] = web::json::value::string(utility::conversions::to_string_t(server_info.cpu));
        server_info_json[_XPLATSTR("cpuPhysical")] = web::json::value::string(utility::conversions::to_string_t(server_info.cpuPhysical));
        server_info_json[_XPLATSTR("cpuCore")] = web::json::value::string(utility::conversions::to_string_t(server_info.cpuCore));
        server_info_json[_XPLATSTR("free")] = web::json::value::string(utility::conversions::to_string_t(server_info.free));
        server_info_json[_XPLATSTR("ProductName")] = web::json::value::string(utility::conversions::to_string_t(server_info.ProductName));
        server_info_json[_XPLATSTR("version")] = web::json::value::string(utility::conversions::to_string_t(server_info.version));
        server_info_json[_XPLATSTR("osName")] = web::json::value::string(utility::conversions::to_string_t(server_info.osName));
        server_info_json[_XPLATSTR("isInternet")] = web::json::value::string(utility::conversions::to_string_t(server_info.isInternet));
        response_json[_XPLATSTR("serverInfo")] = server_info_json;

        // 构造HTTP响应
        http_response response(status_codes::OK);
        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
        response.set_body(response_json);

        // 返回响应
        request.reply(response);
    }
    catch (const std::exception& e) {
        std::cerr << "处理用户信息请求时出错: " << e.what() << std::endl;
        request.reply(status_codes::InternalError,
            web::json::value::string(utility::conversions::to_string_t("内部服务器错误: " + std::string(e.what()))));
    }
}

void ServerManager::handle_get_tmpUserInfo(http_request request) {
    try {
        // 解析请求中的IP参数
        auto query = uri::split_query(request.request_uri().query());
        auto it = query.find(_XPLATSTR("ip"));
        if (it == query.end()) {
            request.reply(status_codes::BadRequest, _XPLATSTR("Missing 'ip' parameter"));
            return;
        }

        // 获取IP地址
        std::string ip = utility::conversions::to_utf8string(it->second);

        // 检查IP是否为空
        if (ip.empty()) {
            request.reply(status_codes::BadRequest, _XPLATSTR("Empty IP parameter"));
            return;
        }

        // 从lastCheckedIds获取该IP最近检查的项目IDs
        std::vector<int> selectedIds;
        auto lastIdsIt = lastCheckedIds.find(ip);
        if (lastIdsIt != lastCheckedIds.end()) {
            selectedIds = lastIdsIt->second;
        }
        else {
            // 如果没有找到该IP的最近检查记录，返回空结果
            web::json::value response_json = web::json::value::object();
            response_json[_XPLATSTR("checkResults")] = web::json::value::array();
            response_json[_XPLATSTR("serverInfo")] = web::json::value::object();

            // 构造HTTP响应
            http_response response(status_codes::OK);
            response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
            response.set_body(response_json);

            // 返回响应
            request.reply(response);
            return;
        }

        // 获取选定IDs的安全检查结果
        std::vector<event> check_results = dbHandler_.getSecurityCheckResultsByIds(ip, selectedIds, pool);//

        // 获取服务器信息
        ServerInfo server_info = dbHandler_.getServerInfoByIp(ip, pool);

        // 创建返回的JSON对象
        web::json::value response_json = web::json::value::object();

        // 将安全检查结果添加到JSON中
        web::json::value results_array = web::json::value::array();
        for (size_t i = 0; i < check_results.size(); ++i) {
            web::json::value result = web::json::value::object();
            result[_XPLATSTR("item_id")] = web::json::value::number(check_results[i].item_id);
            result[_XPLATSTR("description")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].description));
            result[_XPLATSTR("basis")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].basis));
            result[_XPLATSTR("command")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].command));
            result[_XPLATSTR("result")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].result));
            result[_XPLATSTR("IsComply")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].IsComply));
            result[_XPLATSTR("tmp_IsComply")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].tmp_IsComply));
            result[_XPLATSTR("recommend")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].recommend));
            result[_XPLATSTR("importantLevel")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].importantLevel));
            results_array[i] = result;
        }
        response_json[_XPLATSTR("checkResults")] = results_array;

        // 将服务器信息添加到JSON中
        web::json::value server_info_json = web::json::value::object();
        server_info_json[_XPLATSTR("hostname")] = web::json::value::string(utility::conversions::to_string_t(server_info.hostname));
        server_info_json[_XPLATSTR("arch")] = web::json::value::string(utility::conversions::to_string_t(server_info.arch));
        server_info_json[_XPLATSTR("cpu")] = web::json::value::string(utility::conversions::to_string_t(server_info.cpu));
        server_info_json[_XPLATSTR("cpuPhysical")] = web::json::value::string(utility::conversions::to_string_t(server_info.cpuPhysical));
        server_info_json[_XPLATSTR("cpuCore")] = web::json::value::string(utility::conversions::to_string_t(server_info.cpuCore));
        server_info_json[_XPLATSTR("free")] = web::json::value::string(utility::conversions::to_string_t(server_info.free));
        server_info_json[_XPLATSTR("ProductName")] = web::json::value::string(utility::conversions::to_string_t(server_info.ProductName));
        server_info_json[_XPLATSTR("version")] = web::json::value::string(utility::conversions::to_string_t(server_info.version));
        server_info_json[_XPLATSTR("osName")] = web::json::value::string(utility::conversions::to_string_t(server_info.osName));
        server_info_json[_XPLATSTR("isInternet")] = web::json::value::string(utility::conversions::to_string_t(server_info.isInternet));
        response_json[_XPLATSTR("serverInfo")] = server_info_json;

        // 构造HTTP响应
        http_response response(status_codes::OK);
        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
        response.set_body(response_json);

        // 返回响应
        request.reply(response);
    }
    catch (const std::exception& e) {
        std::cerr << "处理临时用户信息请求时出错: " << e.what() << std::endl;
        request.reply(status_codes::InternalError,
            web::json::value::string(utility::conversions::to_string_t("内部服务器错误: " + std::string(e.what()))));
    }
}


// 在 ServerManager.cpp 中实现该函数
void ServerManager::handle_get_security_check_by_ip(http_request request) {
    try {
        // 解析请求中的IP参数
        auto query = uri::split_query(request.request_uri().query());
        auto it = query.find(_XPLATSTR("ip"));
        if (it == query.end()) {
            request.reply(status_codes::BadRequest, _XPLATSTR("Missing 'ip' parameter"));
            return;
        }

        // 获取IP地址
        std::string ip = utility::conversions::to_utf8string(it->second);

        // 检查IP是否为空
        if (ip.empty()) {
            request.reply(status_codes::BadRequest, _XPLATSTR("Empty IP parameter"));
            return;
        }

        // 从数据库中获取该IP的安全检查结果
        std::vector<event> check_results = dbHandler_.getSecurityCheckResults(ip, pool);

        // 创建结果JSON数组
        web::json::value results_array = web::json::value::array();
        for (size_t i = 0; i < check_results.size(); ++i) {
            web::json::value result = web::json::value::object();
            result[_XPLATSTR("item_id")] = web::json::value::number(check_results[i].item_id);
            result[_XPLATSTR("description")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].description));
            result[_XPLATSTR("basis")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].basis));
            result[_XPLATSTR("command")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].command));
            result[_XPLATSTR("result")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].result));
            result[_XPLATSTR("IsComply")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].IsComply));
            result[_XPLATSTR("recommend")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].recommend));
            result[_XPLATSTR("importantLevel")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].importantLevel));

            results_array[i] = result;
        }

        // 返回结果
        http_response response(status_codes::OK);
        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
        response.set_body(results_array);
        request.reply(response);
    }
    catch (const std::exception& e) {
        std::cerr << "处理安全检查结果请求时出错: " << e.what() << std::endl;
        request.reply(status_codes::InternalError,
            web::json::value::string(utility::conversions::to_string_t("内部服务器错误: " + std::string(e.what()))));
    }
}

void ServerManager::handle_post_level3(http_request request) {
    request.extract_json().then([&](json::value jsonReq) {
        this->global_ip = jsonReq[_XPLATSTR("ip")].as_string();
        this->global_pd = jsonReq[_XPLATSTR("pd")].as_string();


        //pd是密码
        string ip = (global_ip);
        string pd = (global_pd);

        // 从请求体获取 ids
        vector<int> selectedIds;
        if (jsonReq.has_field(_XPLATSTR("ids"))) {
            const json::array& ids = jsonReq[_XPLATSTR("ids")].as_array();
            for (const auto& id : ids) {
                selectedIds.push_back(id.as_integer());
            }
        }
        // 缓存该 IP 最后检测的 IDs
        lastLevel3CheckedIds[ip] = selectedIds;

        level3Fun(ip, "root", pd, pool, dbHandler_, selectedIds);//

        http_response response(status_codes::OK);
        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
        json::value response_data = json::value::object();
        response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("Received"));
        response.set_body(response_data);
        request.reply(response);
        }).wait();
}

void ServerManager::handle_get_level3UserInfo(http_request request)
{
    try {
        // 解析请求中的IP参数
        auto query = uri::split_query(request.request_uri().query());
        auto it = query.find(_XPLATSTR("ip"));
        if (it == query.end()) {
            request.reply(status_codes::BadRequest, _XPLATSTR("Missing 'ip' parameter"));
            return;
        }

        // 获取IP地址
        std::string ip = utility::conversions::to_utf8string(it->second);

        // 检查IP是否为空
        if (ip.empty()) {
            request.reply(status_codes::BadRequest, _XPLATSTR("Empty IP parameter"));
            return;
        }

        // 获取三级等保结果
        std::vector<event> check_results = dbHandler_.getLevel3SecurityCheckResults(ip, pool);//


        // 创建返回的JSON对象
        web::json::value response_json = web::json::value::object();

        // 将安全检查结果添加到JSON中
        web::json::value results_array = web::json::value::array();
        for (size_t i = 0; i < check_results.size(); ++i) {
            web::json::value result = web::json::value::object();
            result[_XPLATSTR("item_id")] = web::json::value::number(check_results[i].item_id);
            result[_XPLATSTR("description")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].description));
            result[_XPLATSTR("basis")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].basis));
            result[_XPLATSTR("command")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].command));
            result[_XPLATSTR("result")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].result));
            result[_XPLATSTR("IsComply")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].IsComply));
            result[_XPLATSTR("tmp_IsComply")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].tmp_IsComply));
            result[_XPLATSTR("recommend")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].recommend));
            result[_XPLATSTR("importantLevel")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].importantLevel));
            results_array[i] = result;
        }
        response_json[_XPLATSTR("checkResults")] = results_array;


        // 构造HTTP响应
        http_response response(status_codes::OK);
        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
        response.set_body(response_json);

        // 返回响应
        request.reply(response);
    }
    catch (const std::exception& e) {
        std::cerr << "处理用户信息请求时出错: " << e.what() << std::endl;
        request.reply(status_codes::InternalError,
            web::json::value::string(utility::conversions::to_string_t("内部服务器错误: " + std::string(e.what()))));
    }
}

void ServerManager::handle_get_level3TmpUserInfo(http_request request)
{
    try {
        // 解析请求中的IP参数
        auto query = uri::split_query(request.request_uri().query());
        auto it = query.find(_XPLATSTR("ip"));
        if (it == query.end()) {
            request.reply(status_codes::BadRequest, _XPLATSTR("Missing 'ip' parameter"));
            return;
        }

        // 获取IP地址
        std::string ip = utility::conversions::to_utf8string(it->second);

        // 检查IP是否为空
        if (ip.empty()) {
            request.reply(status_codes::BadRequest, _XPLATSTR("Empty IP parameter"));
            return;
        }

        // 从lastCheckedIds获取该IP最近检查的项目IDs
        std::vector<int> selectedIds;
        auto lastIdsIt = lastLevel3CheckedIds.find(ip);
        if (lastIdsIt != lastLevel3CheckedIds.end()) {
            selectedIds = lastIdsIt->second;
        }
        else {
            // 如果没有找到该IP的最近检查记录，返回空结果
            web::json::value response_json = web::json::value::object();
            response_json[_XPLATSTR("checkResults")] = web::json::value::array();

            // 构造HTTP响应
            http_response response(status_codes::OK);
            response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
            response.set_body(response_json);

            // 返回响应
            request.reply(response);
            return;
        }

        // 获取选定IDs的安全检查结果
        std::vector<event> check_results = dbHandler_.getLevel3SecurityCheckResultsByIds(ip, selectedIds, pool);//


        // 创建返回的JSON对象
        web::json::value response_json = web::json::value::object();

        // 将安全检查结果添加到JSON中
        web::json::value results_array = web::json::value::array();
        for (size_t i = 0; i < check_results.size(); ++i) {
            web::json::value result = web::json::value::object();
            result[_XPLATSTR("item_id")] = web::json::value::number(check_results[i].item_id);
            result[_XPLATSTR("description")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].description));
            result[_XPLATSTR("basis")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].basis));
            result[_XPLATSTR("command")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].command));
            result[_XPLATSTR("result")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].result));
            result[_XPLATSTR("IsComply")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].IsComply));
            result[_XPLATSTR("tmp_IsComply")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].tmp_IsComply));
            result[_XPLATSTR("recommend")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].recommend));
            result[_XPLATSTR("importantLevel")] = web::json::value::string(utility::conversions::to_string_t(check_results[i].importantLevel));
            results_array[i] = result;
        }
        response_json[_XPLATSTR("checkResults")] = results_array;


        // 构造HTTP响应
        http_response response(status_codes::OK);
        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
        response.set_body(response_json);

        // 返回响应
        request.reply(response);
    }
    catch (const std::exception& e) {
        std::cerr << "处理临时用户信息请求时出错: " << e.what() << std::endl;
        request.reply(status_codes::InternalError,
            web::json::value::string(utility::conversions::to_string_t("内部服务器错误: " + std::string(e.what()))));
    }
}

// 在 ServerManager.cpp 中实现该函数
void ServerManager::handle_get_weak_password_by_ip(http_request request) {
    try {
        // 解析请求中的IP参数
        auto query = uri::split_query(request.request_uri().query());
        auto it = query.find(_XPLATSTR("ip"));
        if (it == query.end()) {
            request.reply(status_codes::BadRequest, _XPLATSTR("Missing 'ip' parameter"));
            return;
        }
        // 获取IP地址
        std::string ip = utility::conversions::to_utf8string(it->second);
        // 检查IP是否为空
        if (ip.empty()) {
            request.reply(status_codes::BadRequest, _XPLATSTR("Empty IP parameter"));
            return;
        }
        // 从数据库中获取该IP的所有端口信息
        std::vector<PortInfo> port_infos = dbHandler_.getAllPortInfoByIp(ip, pool);

        // 筛选出有弱密码的端口信息
        std::vector<PortInfo> weak_password_ports;
        for (const auto& port_info : port_infos) {
            if (!port_info.weak_username.empty() && !port_info.weak_password.empty() && port_info.password_verified) {
                weak_password_ports.push_back(port_info);
            }
        }

        // 使用已有的convertPortsToJson函数转换为JSON
        web::json::value results_array = convertPortsToJson(weak_password_ports);

        // 返回结果
        http_response response(status_codes::OK);
        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
        response.set_body(results_array);
        request.reply(response);
    }
    catch (const std::exception& e) {
        std::cerr << "处理弱密码请求时出错: " << e.what() << std::endl;
        request.reply(status_codes::InternalError,
            web::json::value::string(utility::conversions::to_string_t("内部服务器错误: " + std::string(e.what()))));
    }
}

// 在 ServerManager.cpp 中添加新函数
void ServerManager::handle_get_all_weak_passwords(http_request request) {
    try {
        // 获取所有存活主机
        std::vector<std::string> alive_hosts;
        dbHandler_.readAliveHosts(alive_hosts, pool);

        // 创建一个JSON数组来存储所有主机的弱口令信息
        web::json::value all_results = web::json::value::array();
        int index = 0;

        // 遍历每个存活主机
        for (const auto& ip : alive_hosts) {
            // 从数据库中获取该IP的所有端口信息
            std::vector<PortInfo> port_infos = dbHandler_.getAllPortInfoByIp(ip, pool);

            // 筛选出有弱密码的端口信息
            std::vector<PortInfo> weak_password_ports;
            for (const auto& port_info : port_infos) {
                if (!port_info.weak_username.empty() && !port_info.weak_password.empty() && port_info.password_verified) {
                    weak_password_ports.push_back(port_info);
                }
            }

            // 如果该主机有弱密码，则添加到结果数组中
            if (!weak_password_ports.empty()) {
                web::json::value host_result = web::json::value::object();
                host_result[_XPLATSTR("ip")] = web::json::value::string(utility::conversions::to_string_t(ip));
                host_result[_XPLATSTR("weak_passwords")] = convertPortsToJson(weak_password_ports);

                all_results[index++] = host_result;
            }
        }

        // 返回结果
        http_response response(status_codes::OK);
        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
        response.set_body(all_results);
        request.reply(response);
    }
    catch (const std::exception& e) {
        std::cerr << "处理所有主机弱密码请求时出错: " << e.what() << std::endl;
        request.reply(status_codes::InternalError,
            web::json::value::string(utility::conversions::to_string_t("内部服务器错误: " + std::string(e.what()))));
    }
}


void ServerManager::handle_post_login(http_request request) {
    request.extract_json().then([&](json::value jsonReq) {
        this->global_ip = jsonReq[_XPLATSTR("ip")].as_string();
        this->global_pd = jsonReq[_XPLATSTR("pd")].as_string();


        //pd是密码
        string ip = (global_ip);
        string pd = (global_pd);

        // 从请求体获取 ids
        vector<int> selectedIds;
        if (jsonReq.has_field(_XPLATSTR("ids"))) {
            const json::array& ids = jsonReq[_XPLATSTR("ids")].as_array();
            for (const auto& id : ids) {
                selectedIds.push_back(id.as_integer());
            }
        }
        // 缓存该 IP 最后检测的 IDs
        lastCheckedIds[ip] = selectedIds;
        /*
        vector<int> selectedIds = {
        1,  // 密码生命周期检查
        4,  // 密码复杂度检查
        5   // 空密码检查
        };
        */

        fun2( ip, "root", pd,  pool, dbHandler_, selectedIds);
        // Create connection pool for ServerInfo
        auto start = std::chrono::high_resolution_clock::now();
        SSHConnectionPool sshPool(ip, "root", pd, 1); // Single connection is enough for sequential operations
        ServerInfo info;
        ServerInfo_Padding2(info, ip, sshPool, pool, dbHandler_);
        // 获取结束时间（用于测试）
        auto end = std::chrono::high_resolution_clock::now();
        // 计算时间差（以毫秒为单位）
        std::chrono::duration<double, std::milli> elapsed = end - start;
        // 输出时间差
        std::cout << "代码执行时间: " << elapsed.count() << " 毫秒" << std::endl;

        http_response response(status_codes::OK);
        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
        json::value response_data = json::value::object();
        response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("Received"));
        response.set_body(response_data);
        request.reply(response);
        }).wait();
}

//旧版：从局部变量中获取扫描结果
void ServerManager::handle_get_cve_scan(http_request request) {
    web::json::value result = web::json::value::array();
    int index = 0;
    for (const auto& scan_host_result : scan_host_result) {
        result[index++] = ScanHostResult_to_json(scan_host_result);
    }
    //std::cout << result.serialize() << std::endl;

    request.reply(web::http::status_codes::OK, result);
}

//新版：从数据库中获取扫描结果
void ServerManager::handle_get_ScanHostResult(http_request request) {
    try {
        // 解析查询参数
        auto query = uri::split_query(request.request_uri().query());
        auto it = query.find(_XPLATSTR("ip"));
        if (it == query.end()) {
            request.reply(status_codes::BadRequest, _XPLATSTR("Missing 'ip' parameter"));
            return;
        }

        std::string ip = utility::conversions::to_utf8string(it->second);
        //user_logger->info("[INFO] 查询扫描结果，目标IP: {}", ip);
        console->info("[INFO] 查询扫描结果，目标IP: {}", ip);

        // 查询数据库
        ScanHostResult scan_host_result = dbHandler_.getScanHostResult(ip, pool);

        if (!scan_host_result.ports.empty()) {
            // 有结果，转换为JSON
            json::value json_result = ScanHostResult_to_json(scan_host_result);

            json::value response_data;
            response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("成功获取扫描结果"));
            response_data[_XPLATSTR("scan_result")] = json_result;

            http_response response(status_codes::OK);
            response.set_body(response_data);
            response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
            request.reply(response);
        }
        else {
            // 无数据，返回错误信息
            std::string error_msg = "No scan result found for IP: " + ip;
            user_logger->warn("[WARN] {}", error_msg);
            console->warn("[WARN] {}", error_msg);
            request.reply(status_codes::NotFound, json::value::string(utility::conversions::to_string_t(error_msg)));
        }
    }
    catch (const std::exception& e) {
        std::string error_msg = std::string("Internal server error: ") + e.what();
        //user_logger->error("[ERROR] {}", error_msg);
        console->error("[ERROR] {}", error_msg);
        request.reply(status_codes::InternalError, json::value::string(utility::conversions::to_string_t(error_msg)));
    }
}

void ServerManager::handle_get_all_data(http_request request) {
    poc_list = dbManager.getAllData();
    json::value all_data = poc_list_to_json(poc_list);

    http_response response(status_codes::OK);
    response.headers().add(_XPLATSTR("Content-Type"), _XPLATSTR("application/json; charset=utf-8"));
    response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
    response.set_body(all_data);
    request.reply(response);
}

void ServerManager::handle_get_vaild_poc_data(http_request request) {
    poc_list = dbManager.getVaildPOCData();
    json::value all_data = poc_list_to_json(poc_list);

    http_response response(status_codes::OK);
    response.headers().add(_XPLATSTR("Content-Type"), _XPLATSTR("application/json; charset=utf-8"));
    response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
    response.set_body(all_data);
    request.reply(response);
}

void ServerManager::handle_search_data(http_request request) {
    auto query = uri::split_query(request.relative_uri().query());
    auto searchKeyword = uri::decode(query[_XPLATSTR("keyword")]);
    auto poc_data = dbManager.searchData(searchKeyword);
    json::value search_data = json::value::array();
    for (size_t i = 0; i < poc_data.size(); i++) {
        json::value data;
        data[_XPLATSTR("id")] = json::value::number(poc_data[i].id);
        data[_XPLATSTR("cve_id")] = json::value::string(utility::conversions::to_string_t(poc_data[i].vuln_id));
        data[_XPLATSTR("vul_name")] = json::value::string(utility::conversions::to_string_t(poc_data[i].vul_name));
        data[_XPLATSTR("type")] = json::value::string(utility::conversions::to_string_t(poc_data[i].type));
        data[_XPLATSTR("description")] = json::value::string(utility::conversions::to_string_t(poc_data[i].description));
        data[_XPLATSTR("affected_infra")] = json::value::string(utility::conversions::to_string_t(poc_list[i].affected_infra));
        data[_XPLATSTR("script_type")] = json::value::string(utility::conversions::to_string_t(poc_data[i].script_type));
        data[_XPLATSTR("script")] = json::value::string(utility::conversions::to_string_t(poc_data[i].script));
        data[_XPLATSTR("timestamp")] = json::value::string(utility::conversions::to_string_t(poc_data[i].timestamp));
        search_data[i] = data;
    }
    http_response response(status_codes::OK);
    response.headers().add(_XPLATSTR("Content-Type"), _XPLATSTR("application/json; charset=utf-8"));
    response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
    response.set_body(search_data);
    request.reply(response);
}

void ServerManager::handle_post_insert_data(http_request request) {
    json::value response_data;
    http_response response;

    try {
        // 检查是否为multipart/form-data格式
        auto content_type = request.headers().content_type();
        if (content_type.find(_XPLATSTR("multipart/form-data")) == std::string::npos) {
            response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("Invalid content type. Expected multipart/form-data."));
            response.set_status_code(status_codes::BadRequest);
            response.set_body(response_data);
            request.reply(response);  // 提前回复，终止操作
            return;
        }

        // 将请求体保存到临时文件
        save_request_to_temp_file(request);

        // 解析表单字段
        std::string cve_id, vul_name, type, description, affected_infra, script_type, mode, edit_filename, filename, poc_content;
        std::ifstream temp_file(CONFIG.getPocTempFile(), std::ios::binary);
        std::string body((std::istreambuf_iterator<char>(temp_file)), std::istreambuf_iterator<char>());
        temp_file.close();

        auto boundary_pos = content_type.find("boundary=");
        if (boundary_pos != std::string::npos) {
            std::string boundary = "--" + content_type.substr(boundary_pos + 9);
            size_t pos = 0, next_pos;
            while ((next_pos = body.find(boundary, pos)) != std::string::npos) {
                std::string part = body.substr(pos, next_pos - pos);
                pos = next_pos + boundary.length() + 2; // Skip boundary and CRLF

                auto header_end_pos = part.find("\r\n\r\n");
                if (header_end_pos == std::string::npos) continue;

                std::string headers = part.substr(0, header_end_pos);
                std::string part_data = part.substr(header_end_pos + 4, part.length() - header_end_pos - 6); // Exclude trailing CRLF

                /*测试所用
                std::cout << headers << std::endl;
                std::cout << part_data << std::endl;
                */

                std::string decoded_data = autoConvertToUTF8(part_data);

                if (headers.find("filename=") == std::string::npos) {
                    auto name_pos = headers.find("name=");
                    if (name_pos != std::string::npos) {
                        std::string name = headers.substr(name_pos + 6);
                        name = name.substr(0, name.find("\"", 1)); // Extract name between quotes
                        if (name == "cve_id") cve_id = decoded_data;
                        else if (name == "vul_name") vul_name = decoded_data;
                        else if (name == "type") type = decoded_data;
                        else if (name == "description") description = decoded_data;
                        else if (name == "affected_infra") affected_infra = decoded_data;
                        else if (name == "script_type") script_type = decoded_data;
                        else if (name == "mode") mode = decoded_data;
                        else if (name == "edit_filename") edit_filename = decoded_data;
                        else if (name == "poc_content") poc_content = decoded_data;  // 获取编辑后的文件内容
                    }
                }
            }
        }

        // 检查CVE_ID是否已存在
        if (dbManager.isExistCVE(cve_id)) {
            response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("CVE_ID already exists"));
            http_response response(status_codes::BadRequest);
            response.set_body(response_data);
            request.reply(response);
            return;
        }

        // 编辑逻辑
        if (mode == "edit") {
            if (!edit_filename.empty()) {
                std::string full_file_path = CONFIG.getPocDirectory() + edit_filename;

                // 检查文件是否已经存在
                std::ifstream infile(full_file_path);
                if (infile.good() && edit_filename != "") {
                    http_response response;
                    response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("添加失败！文件名已存在，请修改！"));
                    response.set_status_code(status_codes::BadRequest);
                    response.set_body(response_data);
                    request.reply(response);
                    return;
                }

                //写入文件
                std::ofstream outfile(full_file_path);
                if (outfile.is_open()) {
                    outfile << poc_content;
                    outfile.close();
                    filename = edit_filename;
                }
                else {
                    response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("无法保存编辑后的文件内容。"));
                    response.set_status_code(status_codes::InternalError);
                    response.set_body(response_data);
                    request.reply(response);  // 提前回复
                    return;
                }
            }
        }

        // 上传逻辑
        if (mode == "upload") {
            std::string error_message = "";
            if (!check_and_get_filename(body, content_type, filename, poc_content, error_message)) {
                if (!filename.empty()) {
                    upload_file(filename, poc_content);
                }
            }
            else
            {
                http_response response;
                response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("添加失败！文件名已存在，请修改！"));
                response.set_status_code(status_codes::BadRequest);
                response.set_body(response_data);
                request.reply(response);
                return;
            }
        }

        // 插入数据到数据库
        bool success = dbManager.insertData(cve_id, vul_name, type, description, affected_infra, script_type, filename);
        if (success) {
            poc_list = dbManager.getAllData();
            response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("添加成功！"));
            response.set_status_code(status_codes::OK);
        }
        else {
            response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("添加失败：未能修改数据库！"));
            response.set_status_code(status_codes::BadRequest);
        }
    }
    catch (const std::exception& e) {
        std::cerr << "General error during file upload or edit: " << e.what() << std::endl;
        response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("An error occurred: ") + utility::conversions::to_string_t(e.what()));
        response.set_status_code(status_codes::InternalError);
    }

    response.set_body(response_data);
    request.reply(response);
}


//void ServerManager::handle_post_insert_data(http_request request) {
//    try {
//        // 检查是否为multipart/form-data格式
//        auto content_type = request.headers().content_type();
//        if (content_type.find(_XPLATSTR("multipart/form-data")) == std::string::npos) {
//            json::value response_data;
//            response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("Invalid content type. Expected multipart/form-data."));
//            http_response response(status_codes::BadRequest);
//            response.set_body(response_data);
//            request.reply(response);
//            return;
//        }
//
//        // 将请求体保存到临时文件
//        save_request_to_temp_file(request);
//
//        // 解析表单字段
//        std::string cve_id, vul_name, type, description, script_type;
//        std::ifstream temp_file(TEMP_FILENAME, std::ios::binary);
//        std::string body((std::istreambuf_iterator<char>(temp_file)), std::istreambuf_iterator<char>());
//        temp_file.close();
//
//        auto boundary_pos = content_type.find("boundary=");
//        if (boundary_pos != std::string::npos) {
//            std::string boundary = "--" + content_type.substr(boundary_pos + 9);
//            size_t pos = 0, next_pos;
//            while ((next_pos = body.find(boundary, pos)) != std::string::npos) {
//                std::string part = body.substr(pos, next_pos - pos);
//                pos = next_pos + boundary.length() + 2; // Skip boundary and CRLF
//
//                auto header_end_pos = part.find("\r\n\r\n");
//                if (header_end_pos == std::string::npos) continue;
//
//                std::string headers = part.substr(0, header_end_pos);
//                std::string data = part.substr(header_end_pos + 4, part.length() - header_end_pos - 6); // Exclude trailing CRLF
//
//                //std::cout << "Headers: " << headers << std::endl;
//                //std::cout << "Data: " << data << std::endl;
//
//                // 使用autoConvertToUTF8将数据从GBK转换为UTF-8
//                std::string decoded_data = autoConvertToUTF8(data);
//
//                if (headers.find("filename=") == std::string::npos) {
//                    auto name_pos = headers.find("name=");
//                    if (name_pos != std::string::npos) {
//                        std::string name = headers.substr(name_pos + 6);
//                        name = name.substr(0, name.find("\"", 1)); // Extract name between quotes
//                        if (name == "cve_id") cve_id = decoded_data;
//                        else if (name == "vul_name") vul_name = decoded_data;
//                        else if (name == "type") type = decoded_data;
//                        else if (name == "description") description = decoded_data;
//                        else if (name == "script_type") script_type = decoded_data;
//                    }
//                }
//            }
//        }
//
//        // 检查CVE_ID是否已存在
//        if (dbManager.isExistCVE(cve_id)) {
//            json::value response_data;
//            response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("CVE_ID already exists"));
//            http_response response(status_codes::BadRequest);
//            response.set_body(response_data);
//            request.reply(response);
//            return;
//        }
//
//        // 处理文件上传，使用已经读取的请求体
//        std::string filename = "";
//        std::string error_message = "";
//        std::string data = ""; //文件内容
//        if (!check_and_get_filename(body, content_type, filename, data, error_message))
//        {
//            //有文件上传
//            if(filename != "")
//                upload_file(filename, data);
//        }
//        else
//        {
//            http_response response;
//            json::value response_data;
//            response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("添加失败！文件名已存在，请修改！"));
//            response.set_status_code(status_codes::BadRequest);
//            response.set_body(response_data);
//            request.reply(response);
//            return;
//        }
//        
//        /*
//        if (!error_message.empty()) {
//            json::value response_data;
//            response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR(error_message));
//            http_response response(status_codes::BadRequest);
//            response.set_body(response_data);
//            request.reply(response);
//            return;
//        }
//        */
//
//        // 插入数据到数据库
//        bool success = dbManager.insertData(cve_id, vul_name, type, description, script_type, filename);
//
//        json::value response_data;
//        http_response response;
//        if (success) {
//            poc_list = dbManager.getAllData();  //更新POC列表
//            response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("添加成功！"));
//            response.set_status_code(status_codes::OK);
//        }
//        else {
//            response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("添加失败！"));
//            response.set_status_code(status_codes::BadRequest);
//        }
//        response.set_body(response_data);
//        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
//        response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
//        response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
//        request.reply(response);
//    }
//    catch (const std::exception& e) {
//        std::cerr << "General error during file upload: " << e.what() << std::endl;
//        json::value response_data;
//        response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("An error occurred during file upload: ") + utility::conversions::to_string_t(e.what()));
//        http_response response(status_codes::InternalError);
//        response.set_body(response_data);
//        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
//        response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
//        response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
//        request.reply(response);
//    }
//}
//
///*
void ServerManager::handle_put_update_data_by_id(http_request request)
{
    json::value response_data;
    http_response response;

    try {
        // 检查是否为multipart/form-data格式
        auto content_type = request.headers().content_type();
        if (content_type.find(_XPLATSTR("multipart/form-data")) == std::string::npos) {
            response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("Invalid content type. Expected multipart/form-data."));
            response.set_status_code(status_codes::BadRequest);
            response.set_body(response_data);
            request.reply(response);
            return;
        }

        // 将请求体保存到临时文件
        save_request_to_temp_file(request);

        POC poc;

        // 解析表单字段
        std::ifstream temp_file(CONFIG.getPocTempFile(), std::ios::binary);
        std::string body((std::istreambuf_iterator<char>(temp_file)), std::istreambuf_iterator<char>());
        temp_file.close();

        std::string mode, edit_filename, poc_content;
        std::string filename = "";  // 初始化 filename
        auto boundary_pos = content_type.find("boundary=");
        if (boundary_pos != std::string::npos) {
            std::string boundary = "--" + content_type.substr(boundary_pos + 9);
            size_t pos = 0, next_pos;
            while ((next_pos = body.find(boundary, pos)) != std::string::npos) {
                std::string part = body.substr(pos, next_pos - pos);
                pos = next_pos + boundary.length() + 2; // Skip boundary and CRLF

                auto header_end_pos = part.find("\r\n\r\n");
                if (header_end_pos == std::string::npos) continue;

                std::string headers = part.substr(0, header_end_pos);
                std::string part_data = part.substr(header_end_pos + 4, part.length() - header_end_pos - 6); // Exclude trailing CRLF

                std::string decoded_data = autoConvertToUTF8(part_data);

                if (headers.find("filename=") == std::string::npos) {
                    auto name_pos = headers.find("name=");
                    if (name_pos != std::string::npos) {
                        std::string name = headers.substr(name_pos + 6);
                        name = name.substr(0, name.find("\"", 1)); // Extract name between quotes
                        if (name == "id") poc.id = atoi(decoded_data.c_str());
                        else if (name == "cve_id") poc.vuln_id = decoded_data;
                        else if (name == "vul_name") poc.vul_name = decoded_data;
                        else if (name == "type") poc.type = decoded_data;
                        else if (name == "description") poc.description = decoded_data;
                        else if (name == "affected_infra") poc.affected_infra = decoded_data;
                        else if (name == "script_type") poc.script_type = decoded_data;
                        else if (name == "mode") mode = decoded_data;  // 获取操作模式
                        else if (name == "edit_filename") edit_filename = decoded_data; // 获取编辑文件名
                        else if (name == "poc_content") poc_content = decoded_data;    // 获取编辑后的POC内容
                    }
                }
            }
        }

        // 检索当前POC的原文件名
        std::string POC_filename = dbManager.searchPOCById(poc.id); // 原文件名
        std::string data; // 用于存储文件内容

        // 保持原来的逻辑，先给 poc.script 赋值为原文件名
        poc.script = POC_filename.substr(POC_filename.find_last_of('/') + 1);

        // 编辑逻辑
        if (mode == "edit") {
            // 检查 edit_filename 是否为空
            if (edit_filename.empty()) {
                response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("编辑失败！编辑的文件名不能为空。"));
                response.set_status_code(status_codes::BadRequest);
                response.set_body(response_data);
                request.reply(response);  // 提前回复
                return;
            }

            std::string full_file_path = CONFIG.getPocDirectory() + edit_filename;

            // 如果要更新的文件名与数据库中的不一致，检查文件是否已存在
            if (edit_filename != poc.script) {
                std::ifstream infile(full_file_path);
                if (infile.good()) {
                    response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("更新失败！文件名已存在，请修改！"));
                    response.set_status_code(status_codes::BadRequest);
                    response.set_body(response_data);
                    request.reply(response);
                    return;
                }
            }

            //写入新的文件内容
            std::ofstream outfile(full_file_path);
            if (outfile.is_open()) {
                outfile << poc_content;  // 写入编辑的POC内容
                outfile.close();
                filename = edit_filename;
            }
            else {
                response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("无法保存编辑后的文件内容。"));
                response.set_status_code(status_codes::InternalError);
                response.set_body(response_data);
                request.reply(response);  // 提前回复
                return;
            }

            // 删除原POC文件
            if (!POC_filename.empty() && edit_filename != poc.script) {
                if (!POC_filename.substr(POC_filename.find_last_of('/') + 1).empty()) {
                    if (std::remove(POC_filename.c_str()) != 0) {
                        std::cerr << "Error deleting file: " << POC_filename << std::endl;
                        response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("更新失败！删除原POC文件失败，请联系管理员！"));
                        response.set_status_code(status_codes::BadRequest);
                        response.set_body(response_data);
                        request.reply(response);
                        return;
                    }
                }
            }

            // 更新 poc.script 为新文件名
            poc.script = filename;
        }

        // 上传逻辑 - 只在 mode 为 "upload" 的情况下才执行
        if (mode == "upload") {
            std::string error_message = "";
            bool fileExist = check_and_get_filename(body, content_type, filename, data, error_message);

            if (filename != "") {
                // 有同名文件，且不是该POC记录的，报错
                if (fileExist && filename != poc.script) {
                    response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("更新失败！文件名已在其他漏洞的POC中存在，请修改！"));
                    response.set_status_code(status_codes::BadRequest);
                    response.set_body(response_data);
                    request.reply(response);
                    return;
                }

                // 删除原POC文件
                if (!POC_filename.empty()) {
                    // 判断是一个文件，而非目录
                    if (!POC_filename.substr(POC_filename.find_last_of('/') + 1).empty()) {
                        if (std::remove(POC_filename.c_str()) != 0) {
                            std::cerr << "Error deleting file: " << POC_filename << std::endl;
                            response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("更新失败！删除原POC文件失败，请联系管理员！"));
                            response.set_status_code(status_codes::BadRequest);
                            response.set_body(response_data);
                            request.reply(response);
                            return;
                        }
                    }
                }
                // 上传新文件
                upload_file(filename, data);
                // 更新 poc.script 为新文件名
                poc.script = filename;
            }
        }

        // 更新数据
        bool success = dbManager.updateDataById(poc.id, poc);
        if (success) {
            poc_list = dbManager.getAllData();  // 更新POC列表
            response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("更新成功"));
            response.set_status_code(status_codes::OK);
        }
        else {
            response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("更新失败"));
            response.set_status_code(status_codes::BadRequest);
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error while processing update data request: " << e.what() << std::endl;
        response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("An error occurred during the update process: ") + utility::conversions::to_string_t(e.what()));
        response.set_status_code(status_codes::InternalError);
    }

    response.set_body(response_data);
    response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
    response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
    response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
    request.reply(response);
}

//
//void ServerManager::handle_put_update_data_by_id(http_request request)
//{
//    try {
//        // 检查是否为multipart/form-data格式
//        auto content_type = request.headers().content_type();
//        if (content_type.find(_XPLATSTR("multipart/form-data")) == std::string::npos) {
//            json::value response_data;
//            response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("Invalid content type. Expected multipart/form-data."));
//            http_response response(status_codes::BadRequest);
//            response.set_body(response_data);
//            request.reply(response);
//            return;
//        }
//
//        // 将请求体保存到临时文件
//        save_request_to_temp_file(request);
//
//        POC poc;
//
//        // 解析表单字段
//        std::ifstream temp_file(TEMP_FILENAME, std::ios::binary);
//        std::string body((std::istreambuf_iterator<char>(temp_file)), std::istreambuf_iterator<char>());
//        temp_file.close();
//
//        auto boundary_pos = content_type.find("boundary=");
//        if (boundary_pos != std::string::npos) {
//            std::string boundary = "--" + content_type.substr(boundary_pos + 9);
//            size_t pos = 0, next_pos;
//            while ((next_pos = body.find(boundary, pos)) != std::string::npos) {
//                std::string part = body.substr(pos, next_pos - pos);
//                pos = next_pos + boundary.length() + 2; // Skip boundary and CRLF
//
//                auto header_end_pos = part.find("\r\n\r\n");
//                if (header_end_pos == std::string::npos) continue;
//
//                std::string headers = part.substr(0, header_end_pos);
//                std::string data = part.substr(header_end_pos + 4, part.length() - header_end_pos - 6); // Exclude trailing CRLF
//
//                //std::cout << "Headers: " << headers << std::endl;
//                //std::cout << "Data: " << data << std::endl;
//
//                if (headers.find("filename=") == std::string::npos) {
//                    auto name_pos = headers.find("name=");
//                    if (name_pos != std::string::npos) {
//                        std::string name = headers.substr(name_pos + 6);
//                        name = name.substr(0, name.find("\"", 1)); // Extract name between quotes
//                        if (name == "id") poc.id = atoi(data.c_str());
//                        else if (name == "cve_id") poc.cve_id = data;
//                        else if (name == "vul_name") poc.vul_name = data;
//                        else if (name == "type") poc.type = data;
//                        else if (name == "description") poc.description = data;
//                        else if (name == "script_type") poc.script_type = data;
//                    }
//                }
//            }
//        }
//
//
//        // 处理文件上传，使用已经读取的请求体
//        std::string filename = ""; //新文件名
//        std::string POC_filename = dbManager.searchPOCById(poc.id); //原文件名
//        std::string error_message = "";
//        std::string data = ""; //文件内容
//
//        //poc.script默认为原文件名
//        poc.script = POC_filename.substr(POC_filename.find_last_of('/')+1);
//
//        //文件名是否已经存在，并给filename赋值
//        bool fileExist = check_and_get_filename(body, content_type, filename, data, error_message);
//        
//        //新上传了文件
//        if (filename != "")
//        {
//            //有同名文件，且不是该POC记录的，报错
//            if (fileExist && filename != poc.script)
//            {
//                http_response response;
//                json::value response_data;
//                response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("更新失败！文件名已在其他漏洞的POC中存在，请修改！"));
//                response.set_status_code(status_codes::BadRequest);
//                response.set_body(response_data);
//                request.reply(response);
//                return;
//            }
//
//            // 删除原POC文件
//            if (!POC_filename.empty())
//            {
//                //判断是一个文件，而非目录
//                if (!POC_filename.substr(POC_filename.find_last_of('/') + 1).empty()) {
//                    if (std::remove(POC_filename.c_str()) != 0) {
//                        std::cerr << "Error deleting file: " << POC_filename << std::endl;
//
//                        http_response response;
//                        json::value response_data;
//                        response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("更新失败！删除原POC文件失败，请联系管理员！"));
//                        response.set_status_code(status_codes::BadRequest);
//                        response.set_body(response_data);
//                        request.reply(response);
//                        return;
//                    }
//                }
//            }
//            //上传新文件
//            upload_file(filename, data);
//            //更新poc路径
//            poc.script = filename;
//        }
//
//
//        // 更新数据
//        bool success = dbManager.updateDataById(poc.id, poc);
//
//        http_response response;
//        json::value response_data;
//        if (success) {
//            poc_list = dbManager.getAllData();  //更新POC列表
//            response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("更新成功"));
//            response.set_status_code(status_codes::OK);
//            response.set_body(response_data);
//        }
//        else {
//            response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("更新失败"));
//            response.set_status_code(status_codes::BadRequest);
//            response.set_body(response_data);
//        }
//        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
//        response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
//        response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
//        request.reply(response);
//    }
//    catch (const std::exception& e) {
//        std::cerr << "Error while processing update data request: " << e.what() << std::endl;
//        json::value response_data;
//        response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("An error occurred during the update process: ") + utility::conversions::to_string_t(e.what()));
//        http_response response(status_codes::InternalError);
//        response.set_body(response_data);
//        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
//        response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
//        response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
//        request.reply(response);
//    }
//}


void ServerManager::handle_delete_data_by_id(http_request request) {
    request.extract_json().then([this, &request](json::value body) mutable {
        bool dbSuccess = true, fileSuccess = true;

        if (body[_XPLATSTR("ids")].is_array()) {
            auto idsArray = body[_XPLATSTR("ids")].as_array();
            for (auto& val : idsArray) {
                int id = val.as_integer();
                std::string POC_filename = dbManager.searchPOCById(id);
                // 删除数据库信息
                if (!dbManager.deleteDataById(id)) {
                    dbSuccess = false;
                    break;
                }
                else
                {
                    // 删除本地POC文件
                    if (!POC_filename.empty()) {
                        if (!POC_filename.substr(POC_filename.find_last_of('/') + 1).empty())
                        {
                            if (std::remove(POC_filename.c_str()) != 0) {
                                std::cerr << "Error deleting file: " << POC_filename << std::endl;
                                fileSuccess = false;

                                http_response response;
                                json::value response_data;
                                response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("删除失败！删除POC文件失败，请联系管理员！"));
                                response.set_status_code(status_codes::BadRequest);
                                response.set_body(response_data);
                                request.reply(response);
                                return;
                            }
                        }
                    }
                }
            }
        }
        else {
            int id = body[_XPLATSTR("ids")].as_integer();
            std::string POC_filename = dbManager.searchPOCById(id);

            // 删除数据库信息
            if (!dbManager.deleteDataById(id)) {
                dbSuccess = false;
            }
            else {
                // 删除本地POC文件
                if (!POC_filename.empty()) {
                    if (!POC_filename.substr(POC_filename.find_last_of('/') + 1).empty())
                    {
                        if (std::remove(POC_filename.c_str()) != 0) {
                            std::cerr << "Error deleting file: " << POC_filename << std::endl;
                            fileSuccess = false;

                            http_response response;
                            json::value response_data;
                            response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("删除失败！删除POC文件失败，请联系管理员！"));
                            response.set_status_code(status_codes::BadRequest);
                            response.set_body(response_data);
                            request.reply(response);
                            return;
                        }
                    }
                }
            }

        }

        http_response response;
        json::value response_data;

        if (dbSuccess && fileSuccess) {
            poc_list = dbManager.getAllData();
            response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("删除成功"));
            response.set_status_code(status_codes::OK);
        }
        else if (!dbSuccess) {
            response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("数据库记录删除失败"));
            response.set_status_code(status_codes::BadRequest);
        }
        else { // 文件删除失败，但数据库操作成功
            response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("文件删除失败，数据库记录已删除"));
            response.set_status_code(status_codes::PartialContent); // 或选择适合的状态码
        }

        response.set_body(response_data);
        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
        request.reply(response);
        }).wait();
}

void ServerManager::handle_post_get_Nmap(http_request request)
{
    request.extract_json().then([this, &request](json::value body) {

        std::string ip = body[_XPLATSTR("ip")].as_string();

        user_logger->info("IP：{} 开始CVE-search漏洞扫描", ip);

        // 获取前端传来的 all_ports 参数，判断是否扫描全部端口
        bool allPorts = body.has_field(_XPLATSTR("all_ports")) ? body[_XPLATSTR("all_ports")].as_bool() : false;
        //bool allPorts = false;

        // 根据前端的选择，传递是否扫描所有端口的参数
        std::string outputPath = performPortScan(ip, allPorts);

        // 解析XML文件以获取扫描结果（多个主机）
        scan_host_result = parseXmlFile(outputPath);

        // 获取当前时间并记录到每个扫描结果中
        auto start = std::chrono::high_resolution_clock::now();

        std::string timestamp = getCurrentTimestamp(2);
        for (auto& scanHostResult : scan_host_result) {
            for (auto& port : scanHostResult.ports) {
                port_services[port.service_name] = port.portId;
            }
            scanHostResult.scan_time = timestamp;  // 记录当前扫描时间
        }

        // 比对历史数据
        // 使用从请求中获取的IP地址
        //ScanHostResult old_scan_host_result = dbHandler_.getScanHostResult(ip, pool);
        //if (!old_scan_host_result.scan_time.empty()) {
        //    // 对比历史数据和当前数据，并更新增量
        //    for (auto& scanHostResult : scan_host_result) {
        //        compareAndUpdateResults(old_scan_host_result, scanHostResult, 10);  // 这里传递一个限制 limit 值
        //    }
        //}
        //else {
        //    // 没有历史数据，直接查询并保存
        //    for (auto& scanHostResult : scan_host_result) {
        //        // 查询主机层面的 CPE（操作系统 CPE）
        //        std::vector<std::string> allCPEs;
        //        for (const auto& cpe_pair : scanHostResult.cpes) {
        //            allCPEs.push_back(cpe_pair.first);
        //        }
        //        fetch_and_padding_cves(scanHostResult.cpes, allCPEs, 10);  // 直接查询所有主机层面 CVE

        //        // 查询每个端口的 CPE
        //        for (auto& scanResult : scanHostResult.ports) {
        //            std::vector<std::string> portCPEs;
        //            for (const auto& cpe_pair : scanResult.cpes) {
        //                portCPEs.push_back(cpe_pair.first);
        //            }
        //            if (!portCPEs.empty()) {
        //                fetch_and_padding_cves(scanResult.cpes, portCPEs, 10);  // 查询端口层面 CVE
        //            }
        //        }
        //    }

        //}
        if (historicalData.data.find(ip) != historicalData.data.end()) {
            // 有历史数据，进行比对和增量扫描
            //改为判断数据库表中是否存在正在扫描的ip.有的话说明需要增量扫描
            ScanHostResult old_scan_host_result = historicalData.data[ip];

            // 对比历史数据和当前数据，并更新增量
            for (auto& scanHostResult : scan_host_result) {
                compareAndUpdateResults(old_scan_host_result, scanHostResult, 10);  // 这里传递一个限制 limit 值
            }
        }
        else {
            // 没有历史数据，直接查询并保存
            for (auto& scanHostResult : scan_host_result) {
                // 查询主机层面的 CPE（操作系统 CPE）
                std::vector<std::string> allCPEs;
                for (const auto& cpe_pair : scanHostResult.cpes) {
                    allCPEs.push_back(cpe_pair.first);
                }
                fetch_and_padding_cves(scanHostResult.cpes, allCPEs, 10);  // 直接查询所有主机层面 CVE

                // 查询每个端口的 CPE
                for (auto& scanResult : scanHostResult.ports) {
                    std::vector<std::string> portCPEs;
                    for (const auto& cpe_pair : scanResult.cpes) {
                        portCPEs.push_back(cpe_pair.first);
                    }
                    if (!portCPEs.empty()) {
                        fetch_and_padding_cves(scanResult.cpes, portCPEs, 10);  // 查询端口层面 CVE
                    }
                }
            }

        }

        //新增:最近一次扫描是否为全端口扫描
        scan_host_result[0].allPorts = allPorts;

        //搜索POC代码是否存在并装载。
        searchPOCs(scan_host_result[0], dbManager, dbHandler_, pool);

        // 将新的扫描结果保存为历史数据
        historicalData.data[ip] = scan_host_result[0];  // 目前只支持单个主机，取第一个
       
		scan_host_result[0].ip = ip;
        //getNmap的部分，始终会为存活状态
        dbHandler_.executeInsert(scan_host_result[0], pool);
        dbHandler_.executeUpdateOrInsert(scan_host_result[0], pool);

        // 获取结束时间（用于测试）
        auto end = std::chrono::high_resolution_clock::now();
        // 计算时间差（以毫秒为单位）
        std::chrono::duration<double, std::milli> elapsed = end - start;
        // 输出时间差
        user_logger->info("IP：{} cve-search漏洞扫描完成，代码执行时间: {} 毫秒", ip, elapsed.count());

        // 创建响应
        http_response response(status_codes::OK);
        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));

        json::value response_data;
        response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("Nmap 扫描完成并获取 CVE 数据。"));
        response_data[_XPLATSTR("scan_result")] = ScanHostResult_to_json(scan_host_result[0]);  // 返回扫描结果
        response.set_body(response_data);
        request.reply(response);

        }).wait();
}



//1.12日版本添加文件大小和文件后缀的检查
void ServerManager::handle_post_hydra(http_request request) {
    // 检查Content-Type
    auto content_type = request.headers().content_type();
    if (content_type.find("multipart/form-data") == std::string::npos) {
        json::value error_response = json::value::object();
        error_response[_XPLATSTR("error")] = json::value::string(_XPLATSTR("Content type must be multipart/form-data"));
        http_response response(status_codes::BadRequest);
        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
        response.set_body(error_response);
        request.reply(response);
        return;
    }

    // 检查请求大小
    auto content_length = request.headers().content_length();
    const size_t MAX_REQUEST_SIZE = 1 * 1024 * 1024; // 1MB
    if (content_length > MAX_REQUEST_SIZE) {
        json::value error_response = json::value::object();
        error_response[_XPLATSTR("error")] = json::value::string(_XPLATSTR("Request size exceeds maximum limit of 1MB"));
        http_response response(status_codes::BadRequest);
        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
        response.set_body(error_response);
        request.reply(response);
        return;
    }

    request.extract_vector().then([this, &request](std::vector<unsigned char> body) {
        try {
            MultipartFormData formData(body);

            // 验证必需字段
            if (!formData.has_field("ip") || !formData.has_field("service_name") || !formData.has_field("portId")) {
                throw std::runtime_error("Missing required fields");
            }

            std::string ip = formData.get_field("ip");
            std::string service_name = formData.get_field("service_name");
            std::string portId = formData.get_field("portId");

            // 检查端口是否为数字
            int port;
            try {
                port = std::stoi(portId);
            }
            catch (const std::exception& e) {
                throw std::runtime_error("Invalid port number");
            }

            // 默认文件路径
            std::string usernameFile = "/home/c/hydra/usernames.txt";
            std::string passwordFile = "/home/c/hydra/passwords.txt";

            // 检查文件扩展名函数
            auto is_txt_file = [](const std::string& filename) -> bool {
                if (filename.length() < 4) return false;
                std::string ext = filename.substr(filename.length() - 4);
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                return ext == ".txt";
                };

            // 处理上传的文件
            bool has_custom_files = false;

            if (formData.has_file("usernameFile")) {
                auto file = formData.get_file("usernameFile");
                // 检查文件类型
                if (!is_txt_file(file.filename)) {
                    throw std::runtime_error("Username file must be a .txt file");
                }
                std::string temp_path = "/tmp/usernames_" + generate_random_string() + ".txt";
                save_uploaded_file(temp_path, file.data);
                usernameFile = temp_path;
                has_custom_files = true;
            }

            if (formData.has_file("passwordFile")) {
                auto file = formData.get_file("passwordFile");
                // 检查文件类型
                if (!is_txt_file(file.filename)) {
                    throw std::runtime_error("Password file must be a .txt file");
                }
                std::string temp_path = "/tmp/passwords_" + generate_random_string() + ".txt";
                save_uploaded_file(temp_path, file.data);
                passwordFile = temp_path;
                has_custom_files = true;
            }


            // 清理临时文件的函数，以便在任何情况下都能清理
            auto cleanup_temp_files = [&]() {
                if (has_custom_files) {
                    if (formData.has_file("usernameFile")) {
                        remove_file(usernameFile);
                    }
                    if (formData.has_file("passwordFile")) {
                        remove_file(passwordFile);
                    }
                }
                };

            // 根据服务类型确定是TCP还是UDP
            bool is_udp_service = false;
            // 常见的UDP服务列表
            std::vector<std::string> udp_services = { "dns", "dhcp", "snmp", "tftp", "ntp" };
            for (const auto& udp_service : udp_services) {
                if (service_name == udp_service) {
                    is_udp_service = true;
                    break;
                }
            }

            // 构建nmap命令，根据服务类型增加相应选项
            std::string protocol_flag = is_udp_service ? "-sU" : "-sT";
            std::string nmap_command = "nmap " + protocol_flag + " -p " + portId + " " + ip + " -n -T4";

            // 执行nmap命令
            std::string nmap_output = exec(nmap_command.c_str());
            std::cout << "nmap output: " << nmap_output << std::endl;

            // 检查主机是否在线
            if (nmap_output.find("Host is up") == std::string::npos) {
                json::value error_response = json::value::object();
                error_response[_XPLATSTR("error")] = json::value::string(_XPLATSTR("目标主机未开启或不可达"));
                error_response[_XPLATSTR("message")] = json::value::string(_XPLATSTR(nmap_output));

                http_response response(status_codes::ServiceUnavailable);
                response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
                response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
                response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
                response.set_body(error_response);
                request.reply(response);

                // 清理临时文件
                cleanup_temp_files();
                return;
            }

            // 构建端口状态检查字符串
            std::string port_status = portId + "/" + (is_udp_service ? "udp" : "tcp") + " open";

            // 检查端口是否开放
            if (nmap_output.find(port_status) == std::string::npos) {
                // 没有找到"open"状态，表示端口未开放
                json::value error_response = json::value::object();
                error_response[_XPLATSTR("error")] = json::value::string(_XPLATSTR("目标服务未开启"));
                error_response[_XPLATSTR("message")] = json::value::string(_XPLATSTR("端口 " + portId + " 未开放或服务未运行"));

                http_response response(status_codes::ServiceUnavailable);
                response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
                response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
                response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
                response.set_body(error_response);
                request.reply(response);

                // 清理临时文件
                cleanup_temp_files();
                return;
            }

            // 验证服务是否存在
			// 服务名是否在服务列表中
            //if (port_services.find(service_name) != port_services.end()) {
            bool exists = isServiceExistByIp(ip, service_name, pool);
            if (true) {
                // 构建并执行hydra命令
                std::string command = "hydra -L " + usernameFile + " -P " + passwordFile + " -f " + service_name + "://" + ip;
                std::string output = exec_hydra(command.c_str());
                std::cout << output << endl;

                // 清理临时文件
                cleanup_temp_files();

                // 检查是否包含主机阻塞的错误信息
                if (output.find("Host") != std::string::npos &&
                    output.find("is blocked") != std::string::npos) {

                    json::value error_response = json::value::object();
                    error_response[_XPLATSTR("error")] = json::value::string(_XPLATSTR("MySQL连接错误"));
                    error_response[_XPLATSTR("message")] = json::value::string(_XPLATSTR(output));

                    http_response response(status_codes::ServiceUnavailable);
                    response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
                    response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
                    response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
                    response.set_body(error_response);
                    request.reply(response);
                    return;
                }

                std::string res = extract_login_info(output);

                std::regex pattern(R"(\[(\d+)\]\[([^\]]+)\] host:\s*([^\s]+)\s+login:\s*([^\s]+)\s+password:\s*([^\s]+))");
                std::smatch match;
                int port = 0;
                std::string service = "";
                std::string host = "";
                std::string login = "";
                std::string password = "";

                if (std::regex_search(res, match, pattern)) {
                    port = std::stoi(match[1].str());
                    service = match[2].str();
                    host = match[3].str();
                    login = match[4].str();
                    password = match[5].str();
                    // 保存弱口令结果到数据库
                    dbHandler_.saveWeakPasswordResult(host, port, service, login, password, pool);

                    // 构建返回对象，包含找到的弱口令信息
                    json::value json_obj = json::value::object();
                    json_obj[_XPLATSTR("port")] = json::value::number(port);
                    json_obj[_XPLATSTR("service")] = json::value::string(service);
                    json_obj[_XPLATSTR("host")] = json::value::string(host);
                    json_obj[_XPLATSTR("login")] = json::value::string(login);
                    json_obj[_XPLATSTR("password")] = json::value::string(password);

                    json::value json_array = json::value::array();
                    json_array[0] = json_obj;

                    http_response response(status_codes::OK);
                    response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
                    response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
                    response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
                    response.set_body(json_array);
                    request.reply(response);
                }
                else {
                    // 没有找到弱口令，返回相应的提示信息
                    json::value response_obj = json::value::object();
                    response_obj[_XPLATSTR("status")] = json::value::string(_XPLATSTR("no_weak_password"));
                    response_obj[_XPLATSTR("message")] = json::value::string(_XPLATSTR("未发现弱口令"));

                    http_response response(status_codes::OK); // 使用200状态码，表示请求成功但没有发现弱口令
                    response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
                    response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
                    response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
                    response.set_body(response_obj);
                    request.reply(response);
                }
            }
            else {
                json::value error_response = json::value::object();
                error_response[_XPLATSTR("error")] = json::value::string(_XPLATSTR("Service not found"));
                error_response[_XPLATSTR("service_name")] = json::value::string(service_name);

                http_response response(status_codes::NotFound);
                response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
                response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
                response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
                response.set_body(error_response);
                request.reply(response);

                // 清理临时文件
                cleanup_temp_files();
            }
        }
        catch (const std::exception& e) {
            std::cerr << "An error occurred: " << e.what() << std::endl;
            http_response response(status_codes::InternalError);
            response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
            json::value error_response = json::value::object();
            error_response[_XPLATSTR("error")] = json::value::string(_XPLATSTR("Internal server error"));
            error_response[_XPLATSTR("details")] = json::value::string(_XPLATSTR(e.what()));
            response.set_body(error_response);
            request.reply(response);
        }
        }).wait();
}


void ServerManager::handle_post_testWeak(http_request request)
{
    request.extract_json().then([this, &request](json::value body) {
        std::string password = body[_XPLATSTR("pd")].as_string();
        PasswordStrength strength = checkPasswordStrength(password);

        string message = passwordStrengthToString(strength);


        // 创建响应
        http_response response(status_codes::OK);
        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));

        json::value response_data;
        response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR(message));
        response.set_body(response_data);
        request.reply(response);

        }).wait();
}

void ServerManager::handle_post_classify_protect(http_request request) {
    request.extract_json().then([this, &request](json::value body) {
        try {
            // 清空现有数据
            vecScoreMeasure.clear();
            //传ip, vector<object>.
            // object包含 item_id, importantLevel, IsComplyLevel
            // 根据ip和item_id修改数据库中对应的IsComply结果
            // 检查 JSON 结构
            if (body.is_object() && body.has_field(_XPLATSTR("scoreMeasures")) && body.at(_XPLATSTR("scoreMeasures")).is_array()) {
                auto json_array = body.at(_XPLATSTR("scoreMeasures")).as_array();
                for (auto& item : json_array) {
                    if (item.is_object()) {
                        scoreMeasure measure;
                        measure.importantLevelJson = utility::conversions::to_utf8string(item.at(_XPLATSTR("importantLevelJson")).as_string());
                        measure.IsComplyLevel = utility::conversions::to_utf8string(item.at(_XPLATSTR("IsComplyLevel")).as_string());
                        vecScoreMeasure.push_back(measure);
                    }
                }
                int n = vecScoreMeasure.size(); // 项数
                double sum = 0.0;
                // 累加每一项的得分
                for (int k = 0; k < n; k++) {
                    double importantLevel = stod(vecScoreMeasure[k].importantLevelJson)/3;
                    double complyLevel = stod(vecScoreMeasure[k].IsComplyLevel);
                    sum += importantLevel * (1.0 - complyLevel);

                    // 输出每一项的计算值用于调试
                    std::cout << "Item " << k << ": importantLevel = " << importantLevel << ", complyLevel = " << complyLevel << ", partialSum = " << sum << std::endl;
                }

                // 输出总和用于调试
                std::cout << "Total sum: " << sum << std::endl;

                // 计算最终评分
                double M = 100.0 - (100.0 * sum / n);

                // 输出最终评分用于调试
                std::cout << "Final score (M): " << M << std::endl;
                // 构造响应消息
                json::value response_data;
                response_data[_XPLATSTR("message")] = json::value::string("Scores received and processed successfully");
                // 创建响应
                http_response response(status_codes::OK);
                response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
                response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
                response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
                response.set_body(response_data);

                // 发送响应
                request.reply(response);
            }
            else {
                // JSON 结构不符合预期
                json::value response_data;
                response_data[_XPLATSTR("message")] = json::value::string("Invalid JSON structure");

                http_response response(status_codes::BadRequest);
                response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
                response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
                response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
                response.set_body(response_data);

                request.reply(response);
            }
        }
        catch (const std::exception& e) {
            json::value response_data;
            response_data[_XPLATSTR("message")] = json::value::string("Exception occurred: " + std::string(e.what()));

            http_response response(status_codes::InternalError);
            response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
            response.set_body(response_data);

            request.reply(response);
        }
        }).wait();
}
void ServerManager::handle_get_classify_protect(http_request request) {
    // 创建 JSON 数组
    json::value json_array = json::value::array();

    // 填充 JSON 数组
    size_t index = 0;
    for (const auto& measure : vecScoreMeasure) {
        json::value json_object;
        json_object[_XPLATSTR("importantLevelJson")] = json::value::string(measure.importantLevelJson);
        json_object[_XPLATSTR("IsComplyLevel")] = json::value::string(measure.IsComplyLevel);
        json_array[index++] = json_object;
    }

    // 创建响应
    json::value response_data;
    response_data[_XPLATSTR("scoreMeasures")] = json_array;

    http_response response(status_codes::OK);
    response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
    response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
    response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
    response.set_body(response_data);

    // 发送响应
    request.reply(response);
}



json::value ServerManager::Vuln_to_json(const Vuln& vuln) {
    json::value result;
    result[_XPLATSTR("Vuln_id")] = json::value::string(vuln.Vuln_id);  // 使用 Vuln_id
    result[_XPLATSTR("vul_name")] = json::value::string(vuln.vul_name);
    result[_XPLATSTR("script")] = json::value::string(vuln.script);    // 新增插件名称字段
    result[_XPLATSTR("CVSS")] = json::value::string(vuln.CVSS);
    result[_XPLATSTR("summary")] = json::value::string(vuln.summary);
    result[_XPLATSTR("pocExist")] = json::value::boolean(vuln.pocExist);
    result[_XPLATSTR("ifCheck")] = json::value::boolean(vuln.ifCheck); // 添加 ifCheck 字段
    result[_XPLATSTR("vulExist")] = json::value::string(vuln.vulExist);
    return result;
}


json::value ServerManager::ScanResult_to_json(const ScanResult& scan_result) {
    json::value result;
    result[_XPLATSTR("portId")] = json::value::string(scan_result.portId);
    result[_XPLATSTR("protocol")] = json::value::string(scan_result.protocol);
    result[_XPLATSTR("status")] = json::value::string(scan_result.status);
    result[_XPLATSTR("service_name")] = json::value::string(scan_result.service_name);
    result[_XPLATSTR("product")] = json::value::string(scan_result.product);
    result[_XPLATSTR("version")] = json::value::string(scan_result.version);

    // 处理端口的 CPE 信息及对应的漏洞
    json::value cpes_json = json::value::object();
    for (const auto& cpe : scan_result.cpes) {
        json::value cves_json = json::value::array();
        int index = 0;
        for (const auto& cve : cpe.second) {
            cves_json[index++] = Vuln_to_json(cve);
        }
        cpes_json[cpe.first] = cves_json;
    }
    result[_XPLATSTR("cpes")] = cpes_json;

    // 处理端口漏洞扫描结果（vuln_result）
    json::value vuln_result_json = json::value::array();
    int index_vuln = 0;
    for (const auto& vuln : scan_result.vuln_result) {
        vuln_result_json[index_vuln++] = Vuln_to_json(vuln);
    }
    result[_XPLATSTR("vuln_result")] = vuln_result_json;

    // 添加是否合并的标识
    result[_XPLATSTR("is_merged")] = json::value::boolean(scan_result.is_merged);

    return result;
}


json::value ServerManager::ScanHostResult_to_json(const ScanHostResult& scan_host_result) {
    json::value result;
    result[_XPLATSTR("url")] = json::value::string(scan_host_result.url);
    result[_XPLATSTR("ip")] = json::value::string(scan_host_result.ip);
    result[_XPLATSTR("scan_time")] = json::value::string(scan_host_result.scan_time);

    // 新增：添加 os_list 字段（操作系统类别）
    json::value os_list_json = json::value::array();
    int index_os_list = 0;
    for (const auto& os : scan_host_result.os_list) {
        os_list_json[index_os_list++] = json::value::string(os);
    }
    result[_XPLATSTR("os_list")] = os_list_json;

    // 处理操作系统的详细匹配信息
    json::value os_matches_json = json::value::array();
    int index_os_matches = 0;
    for (const auto& os_match : scan_host_result.os_matches) {
        os_matches_json[index_os_matches++] = json::value::string(os_match);
    }
    result[_XPLATSTR("os_matches")] = os_matches_json;

    // 处理操作系统的 CPE 信息和其对应的漏洞
    json::value cpes_json = json::value::object();
    for (const auto& cpe : scan_host_result.cpes) {
        json::value cves_json = json::value::array();
        int index_cve = 0;
        for (const auto& cve : cpe.second) {
            cves_json[index_cve++] = Vuln_to_json(cve);
        }
        cpes_json[cpe.first] = cves_json;
    }
    result[_XPLATSTR("cpes")] = cpes_json;

    // 处理端口扫描结果
    json::value ports_json = json::value::array();
    int index_port = 0;
    for (const auto& port : scan_host_result.ports) {
        ports_json[index_port++] = ScanResult_to_json(port);
    }
    result[_XPLATSTR("ports")] = ports_json;

    // 新增：处理操作系统层的漏洞扫描结果
    json::value os_vuln_result_json = json::value::array();
    int index_os_vuln = 0;
    for (const auto& vuln : scan_host_result.vuln_result) {
        os_vuln_result_json[index_os_vuln++] = Vuln_to_json(vuln);
    }
    result[_XPLATSTR("os_vuln_result")] = os_vuln_result_json;

    // 添加是否合并的标识字段
    result[_XPLATSTR("is_merged")] = json::value::boolean(scan_host_result.is_merged);
    //最近一次扫描是否为全端口扫描（新增）
    result[_XPLATSTR("allPorts")] = json::value::boolean(scan_host_result.allPorts);

    return result;
}

json::value ServerManager::convertToJson(const std::vector<IpVulnerabilities>& vulns)
{
    web::json::value json_array = web::json::value::array();
    int index = 0;

    for (const auto& ip_vuln : vulns) {
        web::json::value ip_obj = web::json::value::object();

        // 设置IP
        ip_obj[_XPLATSTR("ip")] = web::json::value::string(utility::conversions::to_string_t(ip_vuln.ip));

        // 处理主机漏洞
        web::json::value host_vulns = web::json::value::array();
        int host_index = 0;
        // 处理主机漏洞
        for (const auto& vuln : ip_vuln.host_vulnerabilities) {
            web::json::value v = web::json::value::object();
            v[_XPLATSTR("vuln_id")] = web::json::value::string(utility::conversions::to_string_t(vuln.vuln_id));
            v[_XPLATSTR("vuln_name")] = web::json::value::string(utility::conversions::to_string_t(vuln.vuln_name));
            v[_XPLATSTR("cvss")] = web::json::value::string(utility::conversions::to_string_t(vuln.cvss));
            v[_XPLATSTR("summary")] = web::json::value::string(utility::conversions::to_string_t(vuln.summary));
            v[_XPLATSTR("vulExist")] = web::json::value::string(utility::conversions::to_string_t(vuln.vulExist));
            v[_XPLATSTR("softwareType")] = web::json::value::string(utility::conversions::to_string_t(vuln.softwareType));
            v[_XPLATSTR("vulType")] = web::json::value::string(utility::conversions::to_string_t(vuln.vulType));
            
            host_vulns[host_index++] = v;
        }
        ip_obj[_XPLATSTR("host_vulnerabilities")] = host_vulns;

        // 处理端口漏洞
        web::json::value port_vulns = web::json::value::array();
        int port_index = 0;
        for (const auto& vuln : ip_vuln.port_vulnerabilities) {
            web::json::value v = web::json::value::object();
            v[_XPLATSTR("port_id")] = web::json::value::number(vuln.port_id);
            v[_XPLATSTR("vuln_id")] = web::json::value::string(utility::conversions::to_string_t(vuln.vuln_id));
            v[_XPLATSTR("vuln_name")] = web::json::value::string(utility::conversions::to_string_t(vuln.vuln_name));
            v[_XPLATSTR("cvss")] = web::json::value::string(utility::conversions::to_string_t(vuln.cvss));
            v[_XPLATSTR("summary")] = web::json::value::string(utility::conversions::to_string_t(vuln.summary));
            v[_XPLATSTR("vulExist")] = web::json::value::string(utility::conversions::to_string_t(vuln.vulExist));
            v[_XPLATSTR("softwareType")] = web::json::value::string(utility::conversions::to_string_t(vuln.softwareType));
            v[_XPLATSTR("vulType")] = web::json::value::string(utility::conversions::to_string_t(vuln.vulType));
            v[_XPLATSTR("service_name")] = web::json::value::string(utility::conversions::to_string_t(vuln.service_name));
            port_vulns[port_index++] = v;
        }
        ip_obj[_XPLATSTR("port_vulnerabilities")] = port_vulns;

        json_array[index++] = ip_obj;
    }

    return json_array;
}

//POC列表转json
json::value ServerManager::poc_list_to_json(const std::vector<POC>& poc_list) {
    json::value all_data = json::value::array();
    for (size_t i = 0; i < poc_list.size(); i++) {
        json::value data;
        data[_XPLATSTR("id")] = json::value::number(poc_list[i].id);
        data[_XPLATSTR("vuln_id")] = json::value::string(utility::conversions::to_string_t(poc_list[i].vuln_id));
        data[_XPLATSTR("vul_name")] = json::value::string(utility::conversions::to_string_t(poc_list[i].vul_name));
        data[_XPLATSTR("type")] = json::value::string(utility::conversions::to_string_t(poc_list[i].type));
        data[_XPLATSTR("description")] = json::value::string(utility::conversions::to_string_t(poc_list[i].description));
        data[_XPLATSTR("affected_infra")] = json::value::string(utility::conversions::to_string_t(poc_list[i].affected_infra));
        data[_XPLATSTR("script_type")] = json::value::string(utility::conversions::to_string_t(poc_list[i].script_type));
        data[_XPLATSTR("script")] = json::value::string(utility::conversions::to_string_t(poc_list[i].script));
        data[_XPLATSTR("timestamp")] = json::value::string(utility::conversions::to_string_t(poc_list[i].timestamp));
        all_data[i] = data;
    }
    return all_data;
}


//检验文件是否存在，并获取文件名
bool ServerManager::check_and_get_filename(const std::string& body, const std::string& content_type, std::string& filename, std::string& data, std::string& error_message) {
    auto boundary_pos = content_type.find("boundary=");
    if (boundary_pos != std::string::npos) {
        std::string boundary = "--" + content_type.substr(boundary_pos + 9);
        size_t pos = 0, next_pos;
        while ((next_pos = body.find(boundary, pos)) != std::string::npos) {
            std::string part = body.substr(pos, next_pos - pos);
            pos = next_pos + boundary.length() + 2; // Skip boundary and CRLF

            auto header_end_pos = part.find("\r\n\r\n");
            if (header_end_pos == std::string::npos) continue;

            std::string headers = part.substr(0, header_end_pos);

            if (headers.find("filename=") != std::string::npos) {
                auto name_pos = headers.find("filename=");
                if (name_pos != std::string::npos) {
                    filename = headers.substr(name_pos + 10);  // 10 = length of 'filename="'
                    filename = filename.substr(0, filename.find("\""));  // Remove trailing quote
                    
                    // 测试所用
                    // std::cout << "Extracted filename: " << filename << std::endl;

                    // 构建文件路径
                    auto path = _XPLATSTR("../../../src/scan/scripts/") + utility::conversions::to_string_t(filename);

                    // 解析并返回文件内容
                    data = part.substr(header_end_pos + 4, part.length() - header_end_pos - 6);  // Exclude trailing CRLF

                    // 检查文件是否已经存在
                    std::ifstream infile(path);
                    if (infile.good() && filename != "") {
                        error_message = "File already exists";
                        return true;  // 文件已存在
                    }
                    return false;  // 文件不存在
                }
            }
        }
    }
    error_message = "No valid filename found in the request";
    return false;  // 文件不存在
}

//上传文件
void ServerManager::upload_file(const std::string& filename, const std::string& data) {
    // 构建文件路径
    auto path = _XPLATSTR("../../../src/scan/scripts/") + utility::conversions::to_string_t(filename);

    // 打开输出流并写入数据
    concurrency::streams::fstream::open_ostream(path).then([=](concurrency::streams::ostream outFile) mutable {
        auto fileStream = std::make_shared<concurrency::streams::ostream>(outFile);
        std::vector<uint8_t> file_data(data.begin(), data.end());  // 将string数据转换为字节数组
        auto buf = concurrency::streams::container_buffer<std::vector<uint8_t>>(std::move(file_data));
        fileStream->write(buf, buf.size()).then([=](size_t) {
            fileStream->close().get();  // 关闭文件流
            }).wait();
        }).wait();
}


//POC上传文件的工具函数
void ServerManager::save_request_to_temp_file(http_request request) {
    auto bodyStream = request.body();
    concurrency::streams::container_buffer<std::vector<uint8_t>> buffer;
    bodyStream.read_to_end(buffer).get();
    std::string body(buffer.collection().begin(), buffer.collection().end());

    // 写入临时文件（覆盖之前的内容）
    std::ofstream temp_file(CONFIG.getPocTempFile(), std::ios::binary | std::ios::trunc);
    if (!temp_file.is_open()) {
        throw std::runtime_error("Failed to open temporary file for writing");
    }
    temp_file.write(body.data(), body.size());
    temp_file.close();
}

//查看POC内容
void ServerManager::handle_get_poc_content(http_request request) {
    try {
        // 解析请求URL中的参数
        auto query = uri::split_query(request.request_uri().query());
        if (query.find(_XPLATSTR("id")) == query.end() && query.find(_XPLATSTR("vuln_id")) == query.end()) {
            request.reply(status_codes::BadRequest, _XPLATSTR("Missing 'id' or 'vuln_id' parameter"));
            return;
        }

        std::string poc_filename;
        json::value response_data;

        // 如果有 'id' 参数，根据 id 查询
        if (query.find(_XPLATSTR("id")) != query.end()) {
            int poc_id = std::stoi(query[_XPLATSTR("id")]);
            poc_filename = dbManager.searchPOCById(poc_id);
        }
        // 如果没有 'id' 而有 'vuln_id' 参数，根据 vuln_id 查询
        else if (query.find(_XPLATSTR("vuln_id")) != query.end()) {
            std::string vuln_id = query[_XPLATSTR("vuln_id")];
            poc_filename = dbManager.searchPOCById(vuln_id);

            // 使用 vuln_id 查询 POC 并提取 affected_infra 字段
            auto poc_data = dbManager.searchDataByCVE(vuln_id);
            if (!poc_data.empty()) {
                response_data[_XPLATSTR("affected_infra")] = json::value::string(utility::conversions::to_string_t(poc_data[0].affected_infra));
            }
        }

        if (poc_filename.empty()) {
            request.reply(status_codes::OK, _XPLATSTR("{\"content\": \"\"}"));
            return;
        }

        // 验证路径是否为文件
        if (is_directory(poc_filename)) {
            std::cerr << "The path is a directory, not a file (no POC file): " << poc_filename << std::endl;
            request.reply(status_codes::InternalError, _XPLATSTR("{\"error\": \"缺少POC文件\"}"));
            return;
        }

        // 读取文件内容
        std::ifstream file(poc_filename, std::ios::binary);
        if (!file.is_open()) {
            request.reply(status_codes::OK, _XPLATSTR("{\"content\": \"\"}"));
            return;
        }

        std::string file_content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        file.close();

        // 返回文件内容
        response_data[_XPLATSTR("content")] = json::value::string(utility::conversions::to_string_t(file_content));

        http_response response(status_codes::OK);
        response.set_body(response_data);
        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
        request.reply(response);
    }
    catch (const std::exception& e) {
        std::cerr << "Error while processing get POC content request: " << e.what() << std::endl;
        json::value response_data;
        response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("An error occurred while processing the request: ") + utility::conversions::to_string_t(e.what()));
        http_response response(status_codes::InternalError);
        response.set_body(response_data);
        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
        request.reply(response);
    }
}




//POC搜索
void ServerManager::handle_post_poc_search(http_request request) {
    try {
        // 执行 POC 搜索
        for (auto& scanHostResult : scan_host_result) {
            searchPOCs(scanHostResult, dbManager, dbHandler_, pool);
        }

        // 使用 handle_get_cve_scan 返回搜索结果
        handle_get_cve_scan(request);
    }
    catch (const std::exception& e) {
        std::cerr << "Error while processing POC search request: " << e.what() << std::endl;
        json::value response_data;
        response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("An error occurred during POC search: ") + utility::conversions::to_string_t(e.what()));
        http_response response(status_codes::InternalError);
        response.set_body(response_data);
        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
        request.reply(response);
    }
}

//POC验证
void ServerManager::handle_post_poc_verify(http_request request) {
    try {
        // 获取请求的 JSON 数据
        request.extract_json().then([this, &request](json::value body) {
            std::vector<std::string> cve_ids;
            for (const auto& id : body[_XPLATSTR("cve_ids")].as_array()) {
                cve_ids.push_back(id.as_string());
                std::cout << "cve_id:" << id.as_string() << std::endl;
            }

            // 设置 ifCheck 标志
            for (auto& scanHostResult : scan_host_result) {
                setIfCheckByIds(scanHostResult, cve_ids, true);
            }

            // 执行 POC 验证
            verifyPOCs(scan_host_result, dbHandler_, pool);

            // 重置 ifCheck 标志
            for (auto& scanHostResult : scan_host_result) {
                setIfCheckByIds(scanHostResult, cve_ids, false);
            }

            // 将新的扫描结果保存为历史数据
            string ip = scan_host_result[0].ip;
            historicalData.data[ip] = scan_host_result[0];  // 目前只支持单个主机，取第一个string ip = scan_host_result[0].ip;

            // 使用 handle_get_cve_scan 返回验证结果
            handle_get_cve_scan(request);
            
            //返回验证结果
            //handler_get_ScanHostResult(request);
            }).wait();
    }
    catch (const std::exception& e) {
        console->error("Error while processing POC verify request: {}", e.what());
        system_logger->error("Error while processing POC verify request: {}", e.what());

        json::value response_data;
        response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("An error occurred during POC verification: ") + utility::conversions::to_string_t(e.what()));
        http_response response(status_codes::InternalError);
        response.set_body(response_data);
        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
        request.reply(response);
    }
}
void ServerManager::handle_post_poc_verify_new(http_request request) {
    try {
        request.extract_json().then([this, &request](json::value body) {
            // ========== 第一步：检查 IP 参数 ==========
            if (!body.has_field(_XPLATSTR("ip"))) {
                json::value response_data;
                response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("Missing 'ip' field in request body."));
                http_response response(status_codes::BadRequest);
                response.set_body(response_data);
                response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
                response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
                response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
                request.reply(response);
                return;
            }

            std::string ip = body[_XPLATSTR("ip")].as_string();

            // ========== 第二步：从数据库中获取 scan_host_result ==========
            ScanHostResult result = dbHandler_.getScanHostResult(ip, pool);
            if (result.ports.empty()) {
                json::value response_data;
                string message = "No scan result found for IP: " +ip;
                response_data[_XPLATSTR("message")] = json::value::string(utility::conversions::to_string_t(message));
                http_response response(status_codes::NotFound);
                response.set_body(response_data);
                response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
                response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
                response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
                request.reply(response);
                return;
            }

            std::vector<ScanHostResult> scan_host_result_vec;
            scan_host_result_vec.push_back(result);  // 为兼容之前逻辑，转为 vector

            // ========== 第三步：处理 cve_ids ==========
            std::vector<std::string> cve_ids;
            for (const auto& id : body[_XPLATSTR("cve_ids")].as_array()) {
                cve_ids.push_back(id.as_string());
                std::cout << "cve_id: " << id.as_string() << std::endl;
            }

            // ========== 第四步：搜索POC代码是否存在并装载 ==========
            searchPOCs(scan_host_result_vec[0], dbManager, dbHandler_, pool);

            // ========== 第五步：设置 ifCheck ==========
            for (auto& scanHostResult : scan_host_result_vec) {
                setIfCheckByIds(scanHostResult, cve_ids, true);
            }

            // ========== 第六步：POC 验证 ==========
            verifyPOCs(scan_host_result_vec, dbHandler_, pool);

            // ========== 第七步：清除 ifCheck ==========
            for (auto& scanHostResult : scan_host_result_vec) {
                setIfCheckByIds(scanHostResult, cve_ids, false);
            }

           

            // ========== 第九步：返回验证结果 ==========
            json::value response_data;
            response_data[_XPLATSTR("message")] = json::value::string(utility::conversions::to_string_t("POC 验证完成"));
            response_data[_XPLATSTR("ScanHostResult")] = ScanHostResult_to_json(scan_host_result_vec[0]);

            http_response response(status_codes::OK);
            response.set_body(response_data);
            response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
            request.reply(response);

            }).wait();
    }
    catch (const std::exception& e) {
        console->error("Error while processing POC verify request: {}", e.what());
        system_logger->error("Error while processing POC verify request: {}", e.what());

        json::value response_data;
        response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("An error occurred during POC verification: ") + utility::conversions::to_string_t(e.what()));
        http_response response(status_codes::InternalError);
        response.set_body(response_data);
        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
        request.reply(response);
    }
}



// 设置需要执行POC验证的CVE条目
void ServerManager::setIfCheckByIds(ScanHostResult& hostResult, const std::vector<std::string>& cve_ids, bool value) {
    for (auto& cpe : hostResult.cpes) {
        for (auto& cve : cpe.second) {
            if (std::find(cve_ids.begin(), cve_ids.end(), cve.Vuln_id) != cve_ids.end()) {
                cve.ifCheck = value;
            }
        }
    }

    for (auto& port : hostResult.ports) {
        for (auto& cpe : port.cpes) {
            for (auto& cve : cpe.second) {
                if (std::find(cve_ids.begin(), cve_ids.end(), cve.Vuln_id) != cve_ids.end()) {
                    cve.ifCheck = value;
                }
            }
        }
    }
}

void ServerManager::update_poc_by_cve(http_request request) {
    json::value response_data;
    http_response response;

    try {
        // 检查是否为multipart/form-data格式
        auto content_type = request.headers().content_type();
        if (content_type.find(_XPLATSTR("multipart/form-data")) == std::string::npos) {
            response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("Invalid content type. Expected multipart/form-data."));
            response.set_status_code(status_codes::BadRequest);
            response.set_body(response_data);
            request.reply(response);
            return;
        }

        // 将请求体保存到临时文件
        save_request_to_temp_file(request);

        std::string cve_id, vul_name, affected_infra, mode, edit_filename, poc_content;
        std::string filename = "";  // 初始化 filename
        std::ifstream temp_file(CONFIG.getPocTempFile(), std::ios::binary);
        std::string body((std::istreambuf_iterator<char>(temp_file)), std::istreambuf_iterator<char>());
        temp_file.close();

        auto boundary_pos = content_type.find("boundary=");
        if (boundary_pos != std::string::npos) {
            std::string boundary = "--" + content_type.substr(boundary_pos + 9);
            size_t pos = 0, next_pos;
            while ((next_pos = body.find(boundary, pos)) != std::string::npos) {
                std::string part = body.substr(pos, next_pos - pos);
                pos = next_pos + boundary.length() + 2; // Skip boundary and CRLF

                auto header_end_pos = part.find("\r\n\r\n");
                if (header_end_pos == std::string::npos) continue;

                std::string headers = part.substr(0, header_end_pos);
                std::string part_data = part.substr(header_end_pos + 4, part.length() - header_end_pos - 6); // Exclude trailing CRLF

                std::string decoded_data = autoConvertToUTF8(part_data);

                if (headers.find("filename=") == std::string::npos) {
                    auto name_pos = headers.find("name=");
                    if (name_pos != std::string::npos) {
                        std::string name = headers.substr(name_pos + 6);
                        name = name.substr(0, name.find("\"", 1)); // Extract name between quotes
                        if (name == "cve_id") cve_id = decoded_data;
                        else if (name == "vul_name") vul_name = decoded_data;
                        else if (name == "affected_infra")  affected_infra = decoded_data;
                        else if (name == "mode") mode = decoded_data;  // 获取操作模式
                        else if (name == "edit_filename") edit_filename = decoded_data; // 获取编辑文件名
                        else if (name == "poc_content") poc_content = decoded_data;    // 获取编辑后的POC内容
                    }
                }
            }
        }

        // 查找数据库中是否存在该cve_id的POC记录
        std::vector<POC> poc_records = dbManager.searchDataByCVE(cve_id);
        bool isExistPOC = true; //是否存在CVE对应的POC记录
        POC existing_poc;
        if (poc_records.empty()) {
            isExistPOC = false;
            existing_poc.vuln_id = cve_id;
            existing_poc.vul_name = vul_name;
            existing_poc.affected_infra = affected_infra;
            existing_poc.script_type = "python";
        }
        else
        {
            existing_poc = poc_records[0];  // 假设只更新第一个找到的POC记录
        }

        // 编辑逻辑
        if (mode == "edit") {
            // 检查 edit_filename 是否为空
            if (edit_filename.empty()) {
                response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("编辑失败！编辑的文件名不能为空。"));
                response.set_status_code(status_codes::BadRequest);
                response.set_body(response_data);
                request.reply(response);
                return;
            }

            std::string full_file_path = CONFIG.getPocDirectory() + edit_filename;

            // 如果要更新的文件名与数据库中的不一致，检查文件是否已存在
            if (edit_filename != existing_poc.script) {
                std::ifstream infile(full_file_path);
                if (infile.good()) {
                    response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("更新失败！文件名已存在，请修改！"));
                    response.set_status_code(status_codes::BadRequest);
                    response.set_body(response_data);
                    request.reply(response);
                    return;
                }
            }

            //写入新的文件内容
            std::ofstream outfile(full_file_path);
            if (outfile.is_open()) {
                outfile << poc_content;  // 写入编辑的POC内容
                outfile.close();
                filename = edit_filename;
            }
            else {
                response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("无法保存编辑后的文件内容。"));
                response.set_status_code(status_codes::InternalError);
                response.set_body(response_data);
                request.reply(response);  // 提前回复
                return;
            }

            // 删除原POC文件
            if (!existing_poc.script.empty() && edit_filename != existing_poc.script) {
                std::string full_path = CONFIG.getPocDirectory() + existing_poc.script;
                if (std::remove(full_path.c_str()) != 0) {
                    std::cerr << "Error deleting file: " << full_path << std::endl;
                    response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("更新失败！删除原POC文件失败，请联系管理员！"));
                    response.set_status_code(status_codes::BadRequest);
                    response.set_body(response_data);
                    request.reply(response);
                    return;
                }
            }

            // 更新数据库的文件名
            existing_poc.script = filename;
        }

        // 上传逻辑 - 只在 mode 为 "upload" 的情况下才执行
        if (mode == "upload") {
            std::string error_message = "";
            std::string data = "";//存储文件内容
            bool fileExist = check_and_get_filename(body, content_type, filename, data, error_message);

            if (filename != "") {
                if (fileExist && filename != existing_poc.script) {
                    response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("文件名已在其他CVE的POC中存在，请修改！"));
                    response.set_status_code(status_codes::BadRequest);
                    response.set_body(response_data);
                    request.reply(response);
                    return;
                }

                // 删除原POC文件之前，构建文件路径
                if (!existing_poc.script.empty()) {
                    std::string base_path = CONFIG.getPocDirectory();
                    std::string file_path = base_path + existing_poc.script;  // 构建完整的文件路径

                    // 尝试删除文件
                    if (std::remove(file_path.c_str()) != 0) {
                        perror("Error deleting file");  // 输出删除文件失败的详细错误信息
                        std::cerr << "Error deleting file: " << file_path << std::endl;

                        response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("更新失败！删除原POC文件失败，请联系管理员！"));
                        response.set_status_code(status_codes::InternalError);
                        response.set_body(response_data);
                        request.reply(response);
                        return;
                    }
                }

                // 上传新文件
                upload_file(filename, data);
                existing_poc.script = filename;  // 更新文件名
            }
        }

        // 更新数据库记录
        bool success = false;
        if (isExistPOC)
            success = dbManager.updateDataById(existing_poc.id, existing_poc);
        else
            success = dbManager.insertData(existing_poc.vuln_id, existing_poc.vul_name, "", "", existing_poc.affected_infra, existing_poc.script_type, existing_poc.script);

        if (success) {
            response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("操作成功"));
            response.set_status_code(status_codes::OK);
        }
        else {
            response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("更新数据库失败"));
            response.set_status_code(status_codes::BadRequest);
        }

    }
    catch (const std::exception& e) {
        console->error("Error while processing POC upload request: {}", e.what());
        system_logger->error("Error while processing POC upload requestt: {}", e.what());

        response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("上传过程中发生错误：") + utility::conversions::to_string_t(e.what()));
        response.set_status_code(status_codes::InternalError);
    }

    response.set_body(response_data);
    request.reply(response);
}


////根据CVE编号添加POC代码、或更新已有的POC代码
//void ServerManager::update_poc_by_cve(http_request request) {
//    try {
//        // 检查是否为multipart/form-data格式
//        auto content_type = request.headers().content_type();
//        if (content_type.find(_XPLATSTR("multipart/form-data")) == std::string::npos) {
//            json::value response_data;
//            response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("Invalid content type. Expected multipart/form-data."));
//            http_response response(status_codes::BadRequest);
//            response.set_body(response_data);
//            request.reply(response);
//            return;
//        }
//
//        // 将请求体保存到临时文件
//        save_request_to_temp_file(request);
//
//        std::string cve_id;
//
//        // 解析表单字段
//        std::ifstream temp_file(TEMP_FILENAME, std::ios::binary);
//        std::string body((std::istreambuf_iterator<char>(temp_file)), std::istreambuf_iterator<char>());
//        temp_file.close();
//
//        auto boundary_pos = content_type.==("boundary=");
//        if (boundary_pos != std::string::npos) {
//            std::string boundary = "--" + content_type.substr(boundary_pos + 9);
//            size_t pos = 0, next_pos;
//            while ((next_pos = body.find(boundary, pos)) != std::string::npos) {
//                std::string part = body.substr(pos, next_pos - pos);
//                pos = next_pos + boundary.length() + 2; // Skip boundary and CRLF
//
//                auto header_end_pos = part.find("\r\n\r\n");
//                if (header_end_pos == std::string::npos) continue;
//
//                std::string headers = part.substr(0, header_end_pos);
//                std::string data = part.substr(header_end_pos + 4, part.length() - header_end_pos - 6); // Exclude trailing CRLF
//
//                if (headers.find("filename=") == std::string::npos) {
//                    auto name_pos = headers.find("name=");
//                    if (name_pos != std::string::npos) {
//                        std::string name = headers.substr(name_pos + 6);
//                        name = name.substr(0, name.find("\"", 1)); // Extract name between quotes
//                        if (name == "cve_id") cve_id = data;
//                    }
//                }
//            }
//        }
//
//        // 查找数据库中是否存在该cve_id的POC记录
//        std::vector<POC> poc_records = dbManager.searchDataByCVE(cve_id);
//        bool isExistPOC = true; //是否存在CVE对应的POC记录
//        POC existing_poc;
//        if (poc_records.empty()) {
//            isExistPOC = false;
//            existing_poc.cve_id = cve_id;
//            existing_poc.script_type = "python";
//        }
//        else
//        {
//            existing_poc = poc_records[0];  // 假设只更新第一个找到的POC记录
//        }
//
//        // 处理文件上传
//        std::string filename = "";  // 新文件名
//        std::string error_message = "";
//        std::string data = ""; // 文件内容
//
//        bool fileExist = check_and_get_filename(body, content_type, filename, data, error_message);
//
//        // 上传文件并更新poc记录
//        if (filename != "") {
//            if (fileExist && filename != existing_poc.script) {
//                json::value response_data;
//                response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("文件名已在其他CVE的POC中存在，请修改！"));
//                http_response response(status_codes::BadRequest);
//                response.set_body(response_data);
//                request.reply(response);
//                return;
//            }
//
//            // 删除原POC文件之前，构建文件路径
//            if (!existing_poc.script.empty()) {
//                std::string base_path = "../../../src/scan/scripts/";
//                std::string file_path = base_path + existing_poc.script;  // 构建完整的文件路径
//
//                // 尝试删除文件
//                if (std::remove(file_path.c_str()) != 0) {
//                    perror("Error deleting file");  // 输出删除文件失败的详细错误信息
//                    std::cerr << "Error deleting file: " << file_path << std::endl;
//
//                    // 返回错误响应
//                    json::value response_data;
//                    response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("更新失败！删除原POC文件失败，请联系管理员！"));
//                    http_response response(status_codes::InternalError);
//                    response.set_body(response_data);
//                    request.reply(response);
//                    return;
//                }
//                else {
//                    std::cout << "Successfully deleted file: " << file_path << std::endl;
//                }
//            }
//
//
//            // 上传新文件
//            upload_file(filename, data);
//            existing_poc.script = filename;
//
//            // 更新数据库中的POC数据
//            bool success = dbManager.updateDataById(existing_poc.id, existing_poc);
//
//            // 返回更新结果
//            json::value response_data;
//            if (success) {
//                response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("上传并更新成功"));
//                http_response response(status_codes::OK);
//                response.set_body(response_data);
//                request.reply(response);
//            }
//            else {
//                response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("更新数据库失败，POC路径更新失败"));
//                http_response response(status_codes::BadRequest);
//                response.set_body(response_data);
//                request.reply(response);
//            }
//        }
//        else {
//            json::value response_data;
//            response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("No file uploaded"));
//            http_response response(status_codes::BadRequest);
//            response.set_body(response_data);
//            request.reply(response);
//        }
//    }
//    catch (const std::exception& e) {
//        std::cerr << "Error while processing POC upload request: " << e.what() << std::endl;
//        json::value response_data;
//        response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("上传过程中发生错误：") + utility::conversions::to_string_t(e.what()));
//        http_response response(status_codes::InternalError);
//        response.set_body(response_data);
//        request.reply(response);
//    }
//}



//void ServerManager::handle_post_poc_excute(http_request request)
//{
//    request.extract_json().then([this, &request](json::value body) {
//        std::string CVE_id = body[_XPLATSTR("CVE_id")].as_string();
//        std::string script = findScriptByCveId(scan_host_result, CVE_id);
//        std::string portId = findPortIdByCveId(scan_host_result, CVE_id);
//        std::string ip = scan_host_result[0].ip;
//        std::string url = scan_host_result[0].url;
//
//        std::string result = runPythonWithOutput(script, url, ip, std::stoi(portId));
//
//        // 创建响应
//        http_response response(status_codes::OK);
//        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
//        response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
//        response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
//
//        json::value response_data;
//        response_data[_XPLATSTR("message")] = json::value::string(result);
//        response.set_body(response_data);
//        request.reply(response);
//
//        }).wait();
//}

void ServerManager::handle_post_poc_excute(http_request request)
{
    request.extract_json().then([this, &request](json::value body) {
        try {
            std::string CVE_id = body[_XPLATSTR("CVE_id")].as_string();

            // 使用新的函数获取CVE引用
            Vuln& cve = findCveByCveId(scan_host_result, CVE_id);

            // 从找到的CVE直接获取script
            std::string script = cve.script;
            std::string portId = findPortIdByCveId(scan_host_result, CVE_id);
            std::string ip = scan_host_result[0].ip;
            std::string url = scan_host_result[0].url;

            // 执行脚本
            std::string result = runPythonWithOutput(script, url, ip, std::stoi(portId));

            if (result.find("[!]") != std::string::npos) {
                cve.vulExist = "存在";
            }
            else if (result.find("[SAFE]") != std::string::npos) {
                cve.vulExist = "不存在";
            }
            else
            {
                cve.vulExist = "未验证";
            }
            dbHandler_.alterPortVulnResultAfterPocVerify(pool, cve, ip, portId);
            // 创建响应
            http_response response(status_codes::OK);
            response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
            json::value response_data;
            response_data[_XPLATSTR("message")] = json::value::string(result);
            response.set_body(response_data);
            request.reply(response);
        }
        catch (const std::runtime_error& e) {
            // 处理未找到CVE的情况
            http_response response(status_codes::BadRequest);
            response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
            json::value error_data;
            error_data[_XPLATSTR("error")] = json::value::string(e.what());
            response.set_body(error_data);
            request.reply(response);
        }
        catch (const std::exception& e) {
            // 处理其他可能的异常
            http_response response(status_codes::InternalError);
            response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
            json::value error_data;
            error_data[_XPLATSTR("error")] = json::value::string(e.what());
            response.set_body(error_data);
            request.reply(response);
        }
        }).wait();
}



// 记录 /poc_callback 路径的请求（待修改）
void ServerManager::log_poc_callback(const http_request& request) {
    // 获取当前时间戳
    std::time_t now = std::time(nullptr);
    char timestamp[100];
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

    // 记录到日志文件中
    std::ofstream log_file("poc_callback_log.txt", std::ios::app);
    log_file << "Timestamp: " << timestamp << "\n";
    log_file << "Request Method: " << request.method() << "\n";
    log_file << "Request Path: " << request.relative_uri().to_string() << "\n";
    log_file << "------------------------------\n";
    log_file.close();

    // 响应成功回显
    request.reply(status_codes::OK, _XPLATSTR("[!]POC callback received and logged"));
}

void ServerManager::handle_get_alive_hosts(http_request request)
{
    json::value response_data;
    http_response response;

    try {
        // 获取存活的主机
        std::vector<std::string> alive_hosts;
        dbHandler_.readAliveHosts(alive_hosts, pool);
		//需要重新ping一下，因为存活的主机可能已经不存活了
		for (auto& host : alive_hosts) {
			if (!pingIsAlive(host)) {
				//更改数据库中的存活状态
				alive_hosts.erase(std::remove(alive_hosts.begin(), alive_hosts.end(), host), alive_hosts.end());
                dbHandler_.updateAliveHosts(host, pool);
			}
		}
        // 构建响应数据
        json::value host_array = json::value::array();
        for (const auto& host : alive_hosts) {
            host_array[host_array.size()] = json::value::string(utility::conversions::to_string_t(host));
        }
        response_data[_XPLATSTR("alive_hosts")] = host_array;

        // 设置响应头并回复
        response.set_body(response_data);
        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
        response.set_status_code(status_codes::OK);  // 设置 HTTP 状态码
    }
    catch (const std::exception& e) {
        // 处理异常，返回 500 错误
        response.set_status_code(status_codes::InternalError);
        response.set_body(json::value::string(_XPLATSTR("Internal Server Error")));
    }

    request.reply(response);
}

// 处理插件化扫描请求
void ServerManager::handle_post_poc_scan(http_request request) {
    request.extract_json().then([=](json::value json_data) {
        try {

            // 提取 IP 地址
            if (!json_data.has_field(_XPLATSTR("ip"))) {
                throw std::runtime_error("Invalid request: Missing 'ip' field.");
            }
            std::string ip = json_data[_XPLATSTR("ip")].as_string();

            //user_logger->info("IP：{} 开始插件化漏洞扫描", ip);
            console->info("IP：{} 开始插件化漏洞扫描", ip);
            //测试所用
            //std::vector<POC> poc_list = dbManager.getAllData();

             //获取要执行的POC的id
            std::vector<int> ids;
            if (json_data.has_array_field(_XPLATSTR("ids"))) {
                auto id_array = json_data[_XPLATSTR("ids")].as_array();
                for (const auto& id_value : id_array) {
                    ids.push_back(id_value.as_integer());
                }
            }
            else {
                throw std::runtime_error("Invalid request: Missing 'ids' field.");
            }

            // 从数据库中获取指定 ID 的 POC 记录
            std::vector<POC> poc_list = dbManager.searchDataByIds(ids);

            // 获取历史扫描结果
            ScanHostResult scan_host_result = dbHandler_.getScanHostResult(ip, pool);

            if (!scan_host_result.ports.empty()) {
                console->info("IP：{} 使用历史端口扫描数据。", ip);
                user_logger->info("IP：{} 使用历史端口扫描数据。", ip);
            }
            else {
                // 执行端口扫描
                bool allPorts = json_data.has_field(_XPLATSTR("all_ports")) ? json_data[_XPLATSTR("all_ports")].as_bool() : false;
                std::string outputPath = performPortScan(ip, allPorts);

                // 解析 XML 文件获取扫描结果
                auto scan_host_results = parseXmlFile(outputPath);

                // 记录扫描时间并更新到历史数据
                auto timestamp = getCurrentTimestamp(2);
                for (auto& result : scan_host_results) {
                    result.scan_time = timestamp;
                    result.allPorts = allPorts; // 新增
                }
                scan_host_result = scan_host_results[0];
                historicalData.data[ip] = scan_host_result;


                console->info("IP：{} Nmap 扫描完成，更新历史数据。", ip);
            }

            //// 定义变量以存储扫描结果
            //ScanHostResult scan_host_result;

            //if (historicalData.data.find(ip) != historicalData.data.end()) {
            //    scan_host_result = historicalData.data[ip];
            //    
            //    console->info("IP：{} 使用历史端口扫描数据。", ip);
            //    user_logger->info("IP：{} 使用历史端口扫描数据。", ip);
            //}
            //else {
            //    // 执行端口扫描
            //    bool allPorts = json_data.has_field(_XPLATSTR("all_ports")) ? json_data[_XPLATSTR("all_ports")].as_bool() : false;
            //    std::string outputPath = performPortScan(ip, allPorts);

            //    // 解析 XML 文件获取扫描结果
            //    auto scan_host_results = parseXmlFile(outputPath);

            //    // 记录扫描时间并更新到历史数据
            //    auto timestamp = getCurrentTimestamp(2);
            //    for (auto& result : scan_host_results) {
            //        result.scan_time = timestamp;
            //        result.allPorts = allPorts; // 新增
            //    }
            //    scan_host_result = scan_host_results[0];
            //    historicalData.data[ip] = scan_host_result;


            //    user_logger->info("IP：{} Nmap 扫描完成，更新历史数据。", ip);
            //}
            //
            //更新扫描时间
            auto timestamp = getCurrentTimestamp(2);
            scan_host_result.scan_time = timestamp;

            //搜索POC代码是否存在并装载。
            searchPOCs(scan_host_result, dbManager, dbHandler_, pool);

            // 选择是否进行基础设施匹配
            bool match_infra = json_data.has_field(_XPLATSTR("match_infra")) ? json_data[_XPLATSTR("match_infra")].as_bool() : true;

            // 创建 PoC 任务，基于 match_infra 来选择使用哪个 create_poc_task
            std::map<std::string, std::vector<POCTask>> poc_tasks_by_port;
            if (match_infra) {
                poc_tasks_by_port = create_poc_task(poc_list, scan_host_result, true);  // 带基础设施匹配
            }
            else {
                poc_tasks_by_port = create_poc_task(poc_list, scan_host_result);  // 不进行基础设施匹配
            }

            // 执行 PoC 任务并更新结果（原版：非多进程，已弃用）
            //execute_poc_tasks(poc_tasks_by_port, scan_host_result, pool, dbHandler_);

           // 使用多进程版本的执行 PoC 任务并更新结果
            execute_poc_tasks_parallel(poc_tasks_by_port, scan_host_result, dbHandler_ , pool );

            // 将新的扫描结果保存为历史数据
            historicalData.data[ip] = scan_host_result;



            // 将结果转换为 JSON 格式并返回
            json::value result_json = ScanHostResult_to_json(scan_host_result);
            request.reply(status_codes::OK, result_json);
            cout << " 已经发送回响应了" << endl;
        }
        catch (const std::exception& e) {
            // 记录日志
            std::cerr << "Error: " << e.what() << std::endl;

            // 返回错误响应
            json::value error_response;
            error_response[_XPLATSTR("error")] = json::value::string("Error processing PoC scan request.");
            error_response[_XPLATSTR("details")] = json::value::string(e.what());
            request.reply(status_codes::BadRequest, error_response);
        }
        }).wait();
}




//合并两种漏洞扫描方法的结果
void ServerManager::handle_merge_vuln_results(http_request request) {
    request.extract_json().then([=](json::value json_data) {
        try {
            // 获取传递过来的 IP 地址
            if (!json_data.has_field(_XPLATSTR("ip"))) {
                throw std::runtime_error("Invalid request: Missing 'ip' field.");
            }
            std::string ip = json_data[_XPLATSTR("ip")].as_string();

            //// 在历史数据中找到对应 IP 的扫描结果
            //if (historicalData.data.find(ip) == historicalData.data.end()) {
            //    throw std::runtime_error("Scan result for the IP not found.");
            //}


            //ScanHostResult& scan_host_result = historicalData.data[ip];

            // 获取历史扫描结果
            ScanHostResult scan_host_result = dbHandler_.getScanHostResult(ip, pool);

            if (scan_host_result.ports.empty()) {
                throw std::runtime_error("Scan result for the IP not found.");
            }

            // 执行合并操作
            merge_vuln_results(scan_host_result);

            //更新到历史数据
            historicalData.data[ip] = scan_host_result;

            // 返回合并后的结果
            json::value result_json = ScanHostResult_to_json(scan_host_result);
            request.reply(status_codes::OK, result_json);
        }
        catch (const std::exception& e) {
            json::value error_response;
            error_response[_XPLATSTR("error")] = json::value::string("Error merging results.");
            error_response[_XPLATSTR("details")] = json::value::string(e.what());
            request.reply(status_codes::BadRequest, error_response);
        }
        }).wait();
}


// 自动选择POC
void ServerManager::handle_auto_select_poc(http_request request) {

    request.extract_json().then([=](json::value json_data) {
        std::string ip;
        try {

            // 提取 IP 地址
            if (!json_data.has_field(_XPLATSTR("ip"))) {
                throw std::runtime_error("Invalid request: Missing 'ip' field.");
            }
            ip = json_data[_XPLATSTR("ip")].as_string();

            user_logger->info("{} 开始自动选择POC...", ip);

            // 获取所有PoC 列表
            std::vector<POC> poc_list = dbManager.getAllData();  // 假设从数据库中提取所有可用的 POC
            //console->debug("[DEBUG] Retrieved {} POCs from the database.", poc_list.size());

            // 定义变量以存储扫描结果
            ScanHostResult scan_host_result;

            // 从历史数据中获取主机的扫描结果（或者执行新扫描）
            if (historicalData.data.find(ip) != historicalData.data.end()) {
                scan_host_result = historicalData.data[ip];
                //std::cout << "[DEBUG] Using historical scan data for IP: " << ip << std::endl;
            }
            else {
                //std::cout << "[DEBUG] No scan data available for the specified IP" << ip << std::endl;
                // 执行端口扫描
                bool allPorts = json_data.has_field(_XPLATSTR("all_ports")) ? json_data[_XPLATSTR("all_ports")].as_bool() : false;
                std::string outputPath = performPortScan(ip, allPorts);

                // 解析 XML 文件获取扫描结果
                auto scan_host_results = parseXmlFile(outputPath);

                // 记录扫描时间并更新到历史数据
                auto timestamp = getCurrentTimestamp(2);
                for (auto& result : scan_host_results) {
                    result.scan_time = timestamp;
                    result.allPorts = allPorts; // 新增
                }
                scan_host_result = scan_host_results[0];
                historicalData.data[ip] = scan_host_result;
                user_logger->info("{} Nmap 端口扫描（服务、版本）完成，更新历史数据。", ip);
            }

            // 自动选择匹配的 POC
            std::vector<POC> selected_pocs;

            for (const auto& poc : poc_list) {
                if (poc.script.empty()) {
                    user_logger->error("{} Skipping POC with ID {} due to missing script.", ip, poc.id);
                    continue;  // 如果 PoC 没有脚本，跳过
                }

                std::string infra_lower = poc.affected_infra;
                std::transform(infra_lower.begin(), infra_lower.end(), infra_lower.begin(), ::tolower);
                //std::cout << "[DEBUG] Checking POC ID " << poc.id << " with affected infrastructure: " << infra_lower << std::endl;

                bool matched = false;

                // 匹配操作系统
                for (const auto& os : scan_host_result.os_list) {
                    std::string os_lower = os;
                    std::transform(os_lower.begin(), os_lower.end(), os_lower.begin(), ::tolower);

                    if (os_lower.find(infra_lower) != std::string::npos) {
                        //std::cout << ip << " Matched OS: " << os << " with POC ID " << poc.id << std::endl;
                        selected_pocs.push_back(poc);
                        matched = true;
                        break;  // 如果已经匹配到，则跳出操作系统匹配循环
                    }
                }

                // 匹配协议或服务
                if (!matched) {
                    for (const auto& port : scan_host_result.ports) {
                        std::string service_lower = port.service_name;
                        std::string product_lower = port.product;
                        std::transform(service_lower.begin(), service_lower.end(), service_lower.begin(), ::tolower);
                        std::transform(product_lower.begin(), product_lower.end(), product_lower.begin(), ::tolower);

                        if (service_lower.find(infra_lower) != std::string::npos || product_lower.find(infra_lower) != std::string::npos) {
                            //std::cout << "[DEBUG] Matched service/product: " << port.service_name << "/" << port.product
                            //    << " with POC ID " << poc.id << std::endl;
                            selected_pocs.push_back(poc);
                            break;  // 如果匹配到服务或协议，跳出端口匹配循环
                        }
                    }
                }
            }

            user_logger->info("{} Total matched POCs: {}", ip, selected_pocs.size());

            // 将匹配的 PoC 列表返回给前端
            json::value result_json = poc_list_to_json(selected_pocs);
            request.reply(status_codes::OK, result_json);

            user_logger->info("{} Completed handling auto-select POC request.", ip);

        }
        catch (const std::exception& e) {
            // 错误处理
            user_logger->error("{} Error in auto-selecting PoC : {}", ip, e.what());

            json::value error_response;
            error_response[_XPLATSTR("error")] = json::value::string("Error in auto-selecting PoC.");
            error_response[_XPLATSTR("details")] = json::value::string(e.what());
            request.reply(status_codes::BadRequest, error_response);
        }
        }).wait();

}

void ServerManager::handle_get_all_assets_vuln_data(http_request request)
{
    // 获取存活的主机
    std::vector<std::string> alive_hosts;
    dbHandler_.readAliveHosts(alive_hosts, pool);
    std::vector<IpVulnerabilities> vulnerabilities = dbHandler_.getVulnerabilities(pool, alive_hosts);
    // 转换为JSON
    web::json::value json_data = convertToJson(vulnerabilities);
    request.reply(status_codes::OK, json_data);
}

//主机发现
void ServerManager::handle_host_discovery(http_request request) {
    std::string network;
    try {
        // 记录模块开始时间
        auto start_time = std::chrono::high_resolution_clock::now();

        // 从请求中提取查询参数
        auto query = uri::split_query(request.request_uri().query());
        auto it = query.find(_XPLATSTR("network"));
        if (it == query.end()) {
            request.reply(status_codes::BadRequest, _XPLATSTR("Missing 'network' parameter"));
            return;
        }
        network = utility::conversions::to_utf8string(it->second);

        // 检查输入是否为单个IP或网段
        if (isValidIP(network) || isValidCIDR(network)) {

            user_logger->info("[INFO] Performing host discovery for network/IP: {}", network);
            //HostDiscovery hostDiscovery(network);
            HostDiscovery hostDiscovery(network, globalThreadPool); // 用全局线程池
            auto aliveHosts = hostDiscovery.scan();
            //将存活主机存入scan_host_result表中
            dbHandler_.insertAliveHosts2scanHostResult(aliveHosts, pool);
            // 返回网段扫描结果
            sendHostDiscoveryResponse(request, aliveHosts);
        }
        else {
            request.reply(status_codes::BadRequest, _XPLATSTR("Invalid 'network' parameter format"));
        }

        // 记录模块结束时间并计算耗时
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();
        console->info("[INFO] Host discovery for network/IP: {} completed in {} ms", network, duration);

    }
    catch (const std::exception& e) {
        // 异常处理
        system_logger->error("network/IP: {} Host discovery failed: {}", network, e.what());
        request.reply(status_codes::InternalError, _XPLATSTR("Host discovery failed"));
    }
}

// 校验输入是否为有效的IP地址或CIDR网段
bool ServerManager::isValidIPOrCIDR(const std::string& input) {
    return isValidIP(input) || isValidCIDR(input);
}

// 校验IP地址格式
bool ServerManager::isValidIP(const std::string& ip) {
    std::regex ipRegex(
        R"(^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$)"
    );

    // 检查IP是否符合IPv4格式
    if (!std::regex_match(ip, ipRegex)) {
        return false;
    }

    // 检查是否是网络地址 (以 .0 结尾)
    if (ip.substr(ip.find_last_of('.') + 1) == "0") {
        return false;
    }

    // 检查是否是广播地址 (以 .255 结尾)
    if (ip.substr(ip.find_last_of('.') + 1) == "255") {
        return false;
    }

    return true;
}

// 校验CIDR网段格式
bool ServerManager::isValidCIDR(const std::string& network) {
    std::regex cidrRegex(
        R"(^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}0/([1-9]|1[0-9]|2[0-9]|3[0-2])$)"
    );
    return std::regex_match(network, cidrRegex);
}

//返回主机发现的响应
void ServerManager::sendHostDiscoveryResponse(http_request& request, const std::vector<std::string>& aliveHosts) {
    // 将结果转换为 JSON 格式
    web::json::value response = web::json::value::object();
    web::json::value hostArray = web::json::value::array();
    for (size_t i = 0; i < aliveHosts.size(); ++i) {
        hostArray[i] = web::json::value::string(utility::conversions::to_string_t(aliveHosts[i]));
    }
    response[_XPLATSTR("alive_hosts")] = hostArray;

    // 返回成功响应
    request.reply(status_codes::OK, response);
}
bool ServerManager::pingIsAlive(const std::string& network)
{
    HostDiscovery hostDiscovery(network, globalThreadPool); // 用全局线程池
    auto aliveHosts = hostDiscovery.scan();
	if (aliveHosts.size() > 0)
	{
		return true;
	}
    return false;
}
void ServerManager::handle_post_mysql_scan(http_request request)
{
    try {
        // 从请求中获取 JSON 数据
        request.extract_json()
            .then([=](json::value body) {
            try {
                // 检查必需的字段是否存在
                if (!body.has_field(_XPLATSTR("ip")) ||
                    !body.has_field(_XPLATSTR("username")) ||
                    !body.has_field(_XPLATSTR("password"))) {
                    request.reply(status_codes::BadRequest, _XPLATSTR("Missing required fields"));
                    return;
                }

                // 从 JSON 中提取值
                auto host = utility::conversions::to_utf8string(body.at(_XPLATSTR("ip")).as_string());
                auto username = utility::conversions::to_utf8string(body.at(_XPLATSTR("username")).as_string());
                auto password = utility::conversions::to_utf8string(body.at(_XPLATSTR("password")).as_string());

                // 可选参数，设置默认值
                int port = body.has_field(_XPLATSTR("port")) ? body.at(_XPLATSTR("port")).as_integer() : 33060;
                auto database = body.has_field(_XPLATSTR("database")) ?
                    utility::conversions::to_utf8string(body.at(_XPLATSTR("database")).as_string()) : "mysql";
                int init_size = body.has_field(_XPLATSTR("init_size")) ? body.at(_XPLATSTR("init_size")).as_integer() : 2;
                int max_size = body.has_field(_XPLATSTR("max_size")) ? body.at(_XPLATSTR("max_size")).as_integer() : 20;
                int timeout = body.has_field(_XPLATSTR("timeout")) ? body.at(_XPLATSTR("timeout")).as_integer() : 30;

                // 配置数据库连接池
                DBConfig config{
                    host,               // 数据库主机
                    port,               // 数据库端口
                    username,           // 数据库用户名
                    password,           // 数据库密码
                    database,           // 默认数据库
                    init_size,          // 初始连接池大小
                    max_size,           // 最大连接池大小
                    std::chrono::seconds(timeout)  // 连接超时
                };

                // 创建连接池实例
                std::shared_ptr<ConnectionPool> pool = std::make_shared<ConnectionPool>(config);

                // 创建 MySQL 扫描器实例
                MySQLScanner scanner(pool);

                // 执行扫描并捕获输出
                std::stringstream output;
                auto cout_buf = std::cout.rdbuf(); // 保存当前的输出缓冲区
                std::cout.rdbuf(output.rdbuf());   // 重定向标准输出到 stringstream

                scanner.scanAll();

                std::cout.rdbuf(cout_buf);  // 恢复标准输出

                // 创建响应 JSON
                json::value response;
                response[_XPLATSTR("status")] = json::value::string(_XPLATSTR("success"));
                response[_XPLATSTR("data")] = json::value::string(
                    utility::conversions::to_string_t(output.str())
                );

                // 发送响应
                request.reply(status_codes::OK, response);
            }
            catch (const json::json_exception& e) {
                request.reply(status_codes::BadRequest,
                    _XPLATSTR("Invalid JSON format: ") + utility::conversions::to_string_t(e.what()));
            }
            catch (const std::exception& e) {
                request.reply(status_codes::InternalError,
                    _XPLATSTR("Scan error: ") + utility::conversions::to_string_t(e.what()));
            }
                })
            .wait();
    }
    catch (const std::exception& e) {
        request.reply(status_codes::InternalError,
            _XPLATSTR("Request handling error: ") + utility::conversions::to_string_t(e.what()));
    }
}

void ServerManager::handle_get_vuln_types(http_request request)
{
    try {
        json::value response_data;
        std::vector<std::string> types = dbHandler_.getAllVulnTypes(pool);

        json::value type_array = json::value::array();
        for (size_t i = 0; i < types.size(); ++i) {
            type_array[i] = json::value::string(utility::conversions::to_string_t(types[i]));
        }

        response_data[_XPLATSTR("types")] = type_array;

        http_response response(status_codes::OK);
        response.set_body(response_data);
        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, OPTIONS"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
        request.reply(response);
    }
    catch (const std::exception& e) {
        std::cerr << "获取漏洞类型出错: " << e.what() << std::endl;
        json::value response_data;
        response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("服务器错误：") + utility::conversions::to_string_t(e.what()));

        http_response response(status_codes::InternalError);
        response.set_body(response_data);
        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, OPTIONS"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
        request.reply(response);
    }
}

//
void ServerManager::handle_edit_vuln_type(http_request request)
{
    request.extract_json().then([this, &request](json::value body) {
        try {
            //type是漏洞类型，action是增还是删（即"add"或"delete"）
            std::string type = utility::conversions::to_utf8string(body[_XPLATSTR("type")].as_string());
            std::string action = utility::conversions::to_utf8string(body[_XPLATSTR("action")].as_string());

            user_logger->info("接收到漏洞类型编辑请求：操作 = {}, 类型 = {}", action, type);

            bool result = dbHandler_.editVulnType(type, action, pool);

            json::value response_data;
            if (result) {
                response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("操作成功"));
                user_logger->info("漏洞类型操作成功：{}", type);
            }
            else {
                response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("操作失败，参数无效或数据库错误"));
                user_logger->warn("漏洞类型操作失败：{}", type);
            }

            http_response response(result ? status_codes::OK : status_codes::BadRequest);
            response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, OPTIONS"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
            response.set_body(response_data);
            request.reply(response);
        }
        catch (const std::exception& e) {
            user_logger->error("处理漏洞类型编辑请求失败：{}", e.what());

            json::value response_data;
            response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("请求处理出错：") + utility::conversions::to_string_t(e.what()));

            http_response response(status_codes::InternalError);
            response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, OPTIONS"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
            response.set_body(response_data);
            request.reply(response);
        }
        }).wait(); //与 handle_post_get_Nmap 一致
}

void ServerManager::handle_get_level3Result(http_request request)
{
    try {
        // 解析请求中的IP参数
        auto query = uri::split_query(request.request_uri().query());
        auto it = query.find(_XPLATSTR("ip"));
        if (it == query.end()) {
            request.reply(status_codes::BadRequest, _XPLATSTR("Missing 'ip' parameter"));
            return;
        }

        // 获取IP地址
        std::string ip = utility::conversions::to_utf8string(it->second);

        // 检查IP是否为空
        if (ip.empty()) {
            request.reply(status_codes::BadRequest, _XPLATSTR("Empty IP parameter"));
            return;
        }

        // 获取三级等保结果
        std::vector<event> check_results = dbHandler_.getLevel3SecurityCheckResults(ip, pool);

        // 定义合规等级映射表
        std::unordered_map<std::string, double> complyLevelMapping = {
            {"true", 1.0},
            {"false", 0.0},
            {"half_true", 0.5},
            {"pending", -1.0}  // pending状态可根据需要调整处理方式
        };

        // 计算评分
        int n = check_results.size(); // 项数
        double sum = 0.0;

        // 累加每一项的得分
        for (const auto& item : check_results) {
            double importantLevel = std::stod(item.importantLevel)/3;

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
        double M = 100.0 - (100.0 * sum / n);

        // 输出最终评分用于调试
        std::cout << "Final score (M): " << M << std::endl;

        // 构造响应消息
        json::value response_data;
        response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("三级等保评估结果"));
        response_data[_XPLATSTR("score")] = json::value::number(M);
        response_data[_XPLATSTR("ip")] = json::value::string(utility::conversions::to_string_t(ip));
        response_data[_XPLATSTR("totalItems")] = json::value::number(n);


        // 构造HTTP响应
        http_response response(status_codes::OK);
        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
        response.set_body(response_data);

        // 返回响应
        request.reply(response);
    }
    catch (const std::exception& e) {
        std::cerr << "处理三级等保结果请求时出错: " << e.what() << std::endl;

        json::value error_response;
        error_response[_XPLATSTR("error")] = json::value::string(utility::conversions::to_string_t("内部服务器错误: " + std::string(e.what())));

        http_response response(status_codes::InternalError);
        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
        response.set_body(error_response);

        request.reply(response);
    }
}

void ServerManager::handle_post_updateLevel3_protect(http_request request) {
    request.extract_json().then([this, &request](json::value body) {
        try {
            // 检查 JSON 结构，必须包含 ip 和 scoreMeasures 字段
            if (!body.is_object() || !body.has_field(_XPLATSTR("ip")) || !body.has_field(_XPLATSTR("scoreMeasures"))) {
                json::value response_data;
                response_data[_XPLATSTR("message")] = json::value::string("Missing required fields: ip and/or scoreMeasures");

                http_response response(status_codes::BadRequest);
                response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
                response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
                response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
                response.set_body(response_data);

                request.reply(response);
                return;
            }

            // 获取 IP 地址
            std::string ip = utility::conversions::to_utf8string(body.at(_XPLATSTR("ip")).as_string());

            // 检查 scoreMeasures 是否为数组
            if (!body.at(_XPLATSTR("scoreMeasures")).is_array()) {
                json::value response_data;
                response_data[_XPLATSTR("message")] = json::value::string("scoreMeasures must be an array");

                http_response response(status_codes::BadRequest);
                response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
                response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
                response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
                response.set_body(response_data);

                request.reply(response);
                return;
            }

            // 清空现有数据并解析 scoreMeasures 数组
            std::vector<scoreMeasure> vec_score;
            auto json_array = body.at(_XPLATSTR("scoreMeasures")).as_array();

            for (auto& item : json_array) {
                if (item.is_object()) {
                    scoreMeasure measure;

                    // 检查必需的字段
                    if (!item.has_field(_XPLATSTR("item_id")) ||
                        !item.has_field(_XPLATSTR("importantLevelJson")) ||
                        !item.has_field(_XPLATSTR("IsComplyLevel"))) {
                        std::cerr << "警告：scoreMeasure 对象缺少必需字段，跳过该项" << std::endl;
                        continue;
                    }

                    measure.item_id = item.at(_XPLATSTR("item_id")).as_integer();
                    measure.importantLevelJson = utility::conversions::to_utf8string(item.at(_XPLATSTR("importantLevelJson")).as_string());
                    measure.IsComplyLevel = utility::conversions::to_utf8string(item.at(_XPLATSTR("IsComplyLevel")).as_string());
                    vec_score.push_back(measure);
                }
            }

            // 检查是否有有效的评分数据
            if (vec_score.empty()) {
                json::value response_data;
                response_data[_XPLATSTR("message")] = json::value::string("No valid score measures found");

                http_response response(status_codes::BadRequest);
                response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
                response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
                response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
                response.set_body(response_data);

                request.reply(response);
                return;
            }

            // 调用数据库更新函数
            dbHandler_.updateLevel3SecurityCheckResult(ip, pool, vec_score);

            // 构造成功响应
            json::value response_data;
            response_data[_XPLATSTR("message")] = json::value::string("Level3 security check results updated successfully");
            response_data[_XPLATSTR("ip")] = json::value::string(utility::conversions::to_string_t(ip));
            response_data[_XPLATSTR("itemsUpdated")] = json::value::number(vec_score.size());

            // 创建响应
            http_response response(status_codes::OK);
            response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
            response.set_body(response_data);

            // 发送响应
            request.reply(response);
        }
        catch (const std::exception& e) {
            std::cerr << "处理updateLevel3_protect请求时出错: " << e.what() << std::endl;

            json::value response_data;
            response_data[_XPLATSTR("message")] = json::value::string("Exception occurred: " + std::string(e.what()));

            http_response response(status_codes::InternalError);
            response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
            response.set_body(response_data);

            request.reply(response);
        }
        }).wait();
}

void ServerManager::handle_get_baseLineResult(http_request  request)
{
    try {
        // 解析请求中的IP参数
        auto query = uri::split_query(request.request_uri().query());
        auto it = query.find(_XPLATSTR("ip"));
        if (it == query.end()) {
            request.reply(status_codes::BadRequest, _XPLATSTR("Missing 'ip' parameter"));
            return;
        }

        // 获取IP地址
        std::string ip = utility::conversions::to_utf8string(it->second);

        // 检查IP是否为空
        if (ip.empty()) {
            request.reply(status_codes::BadRequest, _XPLATSTR("Empty IP parameter"));
            return;
        }

        // 获取三级等保结果
        std::vector<event> check_results = dbHandler_.getSecurityCheckResults(ip, pool);

        // 定义合规等级映射表
        std::unordered_map<std::string, double> complyLevelMapping = {
            {"true", 1.0},
            {"false", 0.0},
            {"half_true", 0.5},
            {"pending", -1.0}  // pending状态可根据需要调整处理方式
        };

        // 计算评分
        int n = check_results.size(); // 项数
        double sum = 0.0;

        // 累加每一项的得分
        for (const auto& item : check_results) {
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
        double M = 100.0 - (100.0 * sum / n);

        // 输出最终评分用于调试
        std::cout << "Final score (M): " << M << std::endl;

        // 构造响应消息
        json::value response_data;
        response_data[_XPLATSTR("message")] = json::value::string(_XPLATSTR("基线检查评估结果"));
        response_data[_XPLATSTR("score")] = json::value::number(M);
        response_data[_XPLATSTR("ip")] = json::value::string(utility::conversions::to_string_t(ip));
        response_data[_XPLATSTR("totalItems")] = json::value::number(n);


        // 构造HTTP响应
        http_response response(status_codes::OK);
        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
        response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
        response.set_body(response_data);

        // 返回响应
        request.reply(response);
    }
    catch (const std::exception& e) {
        std::cerr << "处理基线检查结果请求时出错: " << e.what() << std::endl;

        json::value error_response;
        error_response[_XPLATSTR("error")] = json::value::string(utility::conversions::to_string_t("内部服务器错误: " + std::string(e.what())));

        http_response response(status_codes::InternalError);
        response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
        response.set_body(error_response);

        request.reply(response);
    }
}

void ServerManager::handle_post_updateBaseLine_protect(http_request request)
{
    request.extract_json().then([this, &request](json::value body) {
        try {
            // 检查 JSON 结构，必须包含 ip 和 scoreMeasures 字段
            if (!body.is_object() || !body.has_field(_XPLATSTR("ip")) || !body.has_field(_XPLATSTR("scoreMeasures"))) {
                json::value response_data;
                response_data[_XPLATSTR("message")] = json::value::string("Missing required fields: ip and/or scoreMeasures");

                http_response response(status_codes::BadRequest);
                response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
                response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
                response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
                response.set_body(response_data);

                request.reply(response);
                return;
            }

            // 获取 IP 地址
            std::string ip = utility::conversions::to_utf8string(body.at(_XPLATSTR("ip")).as_string());

            // 检查 scoreMeasures 是否为数组
            if (!body.at(_XPLATSTR("scoreMeasures")).is_array()) {
                json::value response_data;
                response_data[_XPLATSTR("message")] = json::value::string("scoreMeasures must be an array");

                http_response response(status_codes::BadRequest);
                response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
                response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
                response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
                response.set_body(response_data);

                request.reply(response);
                return;
            }

            // 清空现有数据并解析 scoreMeasures 数组
            std::vector<scoreMeasure> vec_score;
            auto json_array = body.at(_XPLATSTR("scoreMeasures")).as_array();

            for (auto& item : json_array) {
                if (item.is_object()) {
                    scoreMeasure measure;

                    // 检查必需的字段
                    if (!item.has_field(_XPLATSTR("item_id")) ||
                        !item.has_field(_XPLATSTR("importantLevelJson")) ||
                        !item.has_field(_XPLATSTR("IsComplyLevel"))) {
                        std::cerr << "警告：scoreMeasure 对象缺少必需字段，跳过该项" << std::endl;
                        continue;
                    }

                    measure.item_id = item.at(_XPLATSTR("item_id")).as_integer();
                    measure.importantLevelJson = utility::conversions::to_utf8string(item.at(_XPLATSTR("importantLevelJson")).as_string());
                    measure.IsComplyLevel = utility::conversions::to_utf8string(item.at(_XPLATSTR("IsComplyLevel")).as_string());
                    vec_score.push_back(measure);
                }
            }

            // 检查是否有有效的评分数据
            if (vec_score.empty()) {
                json::value response_data;
                response_data[_XPLATSTR("message")] = json::value::string("No valid score measures found");

                http_response response(status_codes::BadRequest);
                response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
                response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
                response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
                response.set_body(response_data);

                request.reply(response);
                return;
            }

            // 调用数据库更新函数
            dbHandler_.updateBaseLineSecurityCheckResult(ip, pool, vec_score);

            // 构造成功响应
            json::value response_data;
            response_data[_XPLATSTR("message")] = json::value::string("Level3 security check results updated successfully");
            response_data[_XPLATSTR("ip")] = json::value::string(utility::conversions::to_string_t(ip));
            response_data[_XPLATSTR("itemsUpdated")] = json::value::number(vec_score.size());

            // 创建响应
            http_response response(status_codes::OK);
            response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
            response.set_body(response_data);

            // 发送响应
            request.reply(response);
        }
        catch (const std::exception& e) {
            std::cerr << "处理updateLevel3_protect请求时出错: " << e.what() << std::endl;

            json::value response_data;
            response_data[_XPLATSTR("message")] = json::value::string("Exception occurred: " + std::string(e.what()));

            http_response response(status_codes::InternalError);
            response.headers().add(_XPLATSTR("Access-Control-Allow-Origin"), _XPLATSTR("*"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Methods"), _XPLATSTR("GET, POST, PUT, DELETE, OPTIONS"));
            response.headers().add(_XPLATSTR("Access-Control-Allow-Headers"), _XPLATSTR("Content-Type"));
            response.set_body(response_data);

            request.reply(response);
        }
        }).wait();
}

void ServerManager::start() {
    try {
        listener->open().then([&listener = listener]() {
            ucout << "Starting to listen at: " << listener->uri().to_string() << std::endl;
            }).wait();
    }
    catch (const std::exception& e) {
        std::cerr << "An error occurred: " << e.what() << std::endl;
    }
}

void ServerManager::stop() {
    try {
        listener->close().wait();
        ucout << "Stopped listening." << std::endl;
    }
    catch (const std::exception& e) {
        system_logger->error("An error occurred while stopping: {}", e.what());
    }
}