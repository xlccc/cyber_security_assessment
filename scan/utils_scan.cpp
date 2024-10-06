#include "utils_scan.h"
#include <rapidxml.hpp>
#include <rapidxml_utils.hpp>
#include <stdexcept>

// 解析XML文件以获取扫描结果
std::vector<ScanHostResult> parseXmlFile(const std::string& xmlFilePath) {
    std::vector<ScanHostResult> scanHostResults;

    // 尝试打开XML文件
    std::ifstream file(xmlFilePath);
    if (!file) {
        std::cerr << "Failed to open XML file: " << xmlFilePath << std::endl;
        return scanHostResults; // 返回空的结果
    }

    // 将XML文件内容读取到字符串中
    std::string xmlContent((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    // 创建RapidXML解析器
    rapidxml::xml_document<> xmlDoc;
    try {
        xmlDoc.parse<0>(&xmlContent[0]);
    }
    catch (rapidxml::parse_error& e) {
        std::cerr << "Failed to parse XML file: " << e.what() << std::endl;
        return scanHostResults; // 返回空的结果
    }

    // 获取根节点 "nmaprun"
    rapidxml::xml_node<>* rootNode = xmlDoc.first_node("nmaprun");
    if (!rootNode) {
        std::cerr << "No 'nmaprun' node found in XML file." << std::endl;
        return scanHostResults; // 返回空的结果
    }

    // 遍历每个主机节点 "host"
    for (rapidxml::xml_node<>* hostNode = rootNode->first_node("host"); hostNode; hostNode = hostNode->next_sibling("host")) {
        ScanHostResult hostResult;

        // 提取IP地址
        rapidxml::xml_node<>* addressNode = hostNode->first_node("address");
        if (addressNode) {
            rapidxml::xml_attribute<>* ipAttr = addressNode->first_attribute("addr");
            if (ipAttr) {
                hostResult.ip = ipAttr->value();
            }
        }


        // 提取操作系统的CPE信息，并初始化为空的CVE数组
        rapidxml::xml_node<>* osNode = hostNode->first_node("os");
        if (osNode) {
            for (rapidxml::xml_node<>* osMatchNode = osNode->first_node("osmatch"); osMatchNode; osMatchNode = osMatchNode->next_sibling("osmatch")) {
                
                //提取操作系统版本
                rapidxml::xml_attribute<>* osMatchAttr = osMatchNode->first_attribute("name");
                if (osMatchAttr)
                {
                    hostResult.os_matches.push_back(osMatchAttr->value());
                }

                for (rapidxml::xml_node<>* osClassNode = osMatchNode->first_node("osclass"); osClassNode; osClassNode = osClassNode->next_sibling("osclass")) {
                    for (rapidxml::xml_node<>* cpeNode = osClassNode->first_node("cpe"); cpeNode; cpeNode = cpeNode->next_sibling("cpe")) {
                        std::string cpe = cpeNode->value();
                        hostResult.cpes[cpe] = std::vector<CVE>(); // 初始化为空的CVE数组
                    }
                }
            }
        }

        // 提取端口扫描信息
        rapidxml::xml_node<>* portsNode = hostNode->first_node("ports");
        if (portsNode) {
            // 遍历每个端口节点 "port"
            for (rapidxml::xml_node<>* portNode = portsNode->first_node("port"); portNode; portNode = portNode->next_sibling("port")) {
                ScanResult scanResult;

                // 提取端口号
                rapidxml::xml_attribute<>* portIdAttr = portNode->first_attribute("portid");
                if (portIdAttr) {
                    scanResult.portId = portIdAttr->value();
                }

                // 提取协议类型
                rapidxml::xml_attribute<>* protocolAttr = portNode->first_attribute("protocol");
                if (protocolAttr) {
                    scanResult.protocol = protocolAttr->value();
                }

                // 提取端口状态
                rapidxml::xml_node<>* stateNode = portNode->first_node("state");
                if (stateNode) {
                    rapidxml::xml_attribute<>* stateAttr = stateNode->first_attribute("state");
                    if (stateAttr) {
                        scanResult.status = stateAttr->value();
                    }
                }

                // 提取服务信息
                rapidxml::xml_node<>* serviceNode = portNode->first_node("service");
                if (serviceNode) {
                    // 提取服务名称
                    rapidxml::xml_attribute<>* nameAttr = serviceNode->first_attribute("name");
                    if (nameAttr) {
                        scanResult.service_name = nameAttr->value();
                    }
                    // 提取服务版本
                    rapidxml::xml_attribute<>* versionAttr = serviceNode->first_attribute("version");
                    if (versionAttr) {
                        scanResult.version = versionAttr->value();
                    }

                    // 提取CPE信息，并初始化为空的CVE数组
                    for (rapidxml::xml_node<>* cpeNode = serviceNode->first_node("cpe"); cpeNode; cpeNode = cpeNode->next_sibling("cpe")) {
                        std::string cpe = cpeNode->value();
                        scanResult.cpes[cpe] = std::vector<CVE>(); // 初始化为空的CVE数组
                    }
                }

                // 将端口扫描结果添加到主机结果的端口列表中
                hostResult.ports.push_back(scanResult);
            }
        }

        // 将主机扫描结果添加到结果列表中
        scanHostResults.push_back(hostResult);
    }

    return scanHostResults; // 返回解析结果
}


//
//std::string runPythonScript(const std::string& scriptPath_extension, const std::string& url, const std::string& ip, int port) {
//    std::string result = "";
//
//    // Import the POC module
//    std::string scriptPath = removeExtension(scriptPath_extension); // 去掉文件名后缀
//
//    PyObject* poc_module = PyImport_ImportModule(scriptPath.c_str());
//    if (!poc_module) {
//        PyErr_Print();
//        std::cerr << "Failed to load script: " << scriptPath << std::endl;
//        return result;
//    }
//
//    // Get the check function from the module
//    PyObject* check_func = PyObject_GetAttrString(poc_module, "check");
//    if (!check_func || !PyCallable_Check(check_func)) {
//        PyErr_Print();
//        std::cerr << "Cannot find function 'check' in the script" << std::endl;
//        Py_DECREF(poc_module);
//        return result;
//    }
//
//    // Prepare arguments for the check function
//    PyObject* args = PyTuple_Pack(3, PyUnicode_FromString(url.c_str()), PyUnicode_FromString(ip.c_str()), PyLong_FromLong(port));
//
//    // Call the check function
//    PyObject* py_result = PyObject_CallObject(check_func, args);
//    Py_DECREF(args);
//    Py_DECREF(check_func);
//    Py_DECREF(poc_module);
//
//    if (py_result) {
//        if (py_result != Py_None) {
//            result = PyUnicode_AsUTF8(py_result);
//        }
//        Py_DECREF(py_result);
//    }
//    else {
//        PyErr_Print();
//        std::cerr << "Failed to call function 'check'" << std::endl;
//    }
//
//    return result;
//}





//// 返回完整的回显，和在Linux命令行内的一样
//std::string runPythonWithOutput(const std::string& scriptPath_extension, const std::string& url, const std::string& ip, int port) {
//    std::string result = "";
//
//    // 重定向stdout和stderr
//    PyObject* io = PyImport_ImportModule("io");
//    PyObject* string_io = PyObject_CallMethod(io, "StringIO", NULL);
//    if (!string_io) {
//        std::cerr << "Failed to create StringIO." << std::endl;
//        return result;
//    }
//    PyObject* sys = PyImport_ImportModule("sys");
//    PyObject_SetAttrString(sys, "stdout", string_io);
//    PyObject_SetAttrString(sys, "stderr", string_io);
//
//    // 导入POC模块
//    std::string scriptPath = removeExtension(scriptPath_extension);
//    PyObject* poc_module = PyImport_ImportModule(scriptPath.c_str());
//    if (!poc_module) {
//        PyErr_Print();
//        result += "Failed to load script: " + scriptPath + "\n";
//        return result;
//    }
//
//    // 获取check函数
//    PyObject* check_func = PyObject_GetAttrString(poc_module, "check");
//    if (!check_func || !PyCallable_Check(check_func)) {
//        PyErr_Print();
//        result += "Cannot find function 'check' in the script\n";
//        Py_DECREF(poc_module);
//        return result;
//    }
//
//    // 准备参数并调用check函数
//    PyObject* args = PyTuple_Pack(3, PyUnicode_FromString(url.c_str()), PyUnicode_FromString(ip.c_str()), PyLong_FromLong(port));
//    PyObject* py_result = PyObject_CallObject(check_func, args);
//    Py_DECREF(args);
//    Py_DECREF(check_func);
//    Py_DECREF(poc_module);
//
//    // 处理check函数的返回值
//    if (py_result) {
//        if (py_result != Py_None) {
//            result += PyUnicode_AsUTF8(py_result);
//        }
//        else {
//            result += "Function 'check' returned None.\n";
//        }
//        Py_DECREF(py_result);
//    }
//    else {
//        PyErr_Print();
//        result += "Failed to call function 'check'\n";
//    }
//
//    // 获取所有的stdout和stderr输出
//    PyObject* output = PyObject_CallMethod(string_io, "getvalue", NULL);
//    if (output) {
//        result += PyUnicode_AsUTF8(output);
//        Py_DECREF(output);
//    }
//    else {
//        result += "Failed to get output from StringIO.\n";
//    }
//
//    Py_DECREF(string_io);
//    Py_DECREF(io);
//
//    return result;
//}

std::string runPythonWithOutput(const std::string& scriptPath_extension, const std::string& url, const std::string& ip, int port) {
    std::string result = "";

    // 重定向stdout和stderr
    PyObject* io = PyImport_ImportModule("io");
    PyObject* string_io = PyObject_CallMethod(io, "StringIO", NULL);
    if (!string_io) {
        std::cerr << "Failed to create StringIO." << std::endl;
        return result;
    }
    PyObject* sys = PyImport_ImportModule("sys");
    PyObject_SetAttrString(sys, "stdout", string_io);
    PyObject_SetAttrString(sys, "stderr", string_io);

    // 导入POC模块
    std::string scriptPath = removeExtension(scriptPath_extension);
    PyObject* poc_module = PyImport_ImportModule(scriptPath.c_str());
    if (!poc_module) {
        PyErr_Print();
        result += "Failed to load script: " + scriptPath + "\n";
        return result;
    }

    // 获取类对象
    PyObject* poc_class = PyObject_GetAttrString(poc_module, "DemoPOC");
    if (!poc_class || !PyCallable_Check(poc_class)) {
        PyErr_Print();
        result += "Cannot find class 'DemoPOC' in the script\n";
        Py_DECREF(poc_module);
        return result;
    }

    // 实例化POC对象
    PyObject* poc_instance = PyObject_CallFunction(poc_class, "ssi", url.c_str(), ip.c_str(), port);
    if (!poc_instance) {
        PyErr_Print();
        result += "Failed to instantiate 'DemoPOC'\n";
        Py_DECREF(poc_class);
        Py_DECREF(poc_module);
        return result;
    }

    // 调用 _verify 方法
    PyObject* verify_func = PyObject_GetAttrString(poc_instance, "_verify");
    if (!verify_func || !PyCallable_Check(verify_func)) {
        PyErr_Print();
        result += "Cannot find method '_verify'\n";
        Py_DECREF(poc_instance);
        Py_DECREF(poc_class);
        Py_DECREF(poc_module);
        return result;
    }

    // 调用 _verify 方法
    PyObject* py_result = PyObject_CallObject(verify_func, NULL);
    Py_DECREF(verify_func);
    Py_DECREF(poc_instance);
    Py_DECREF(poc_class);
    Py_DECREF(poc_module);

    // 处理 _verify 方法的返回值
    if (py_result) {
        if (PyDict_Check(py_result)) {
            PyObject* verify_info = PyDict_GetItemString(py_result, "VerifyInfo");
            PyObject* error_info = PyDict_GetItemString(py_result, "Error");

            if (verify_info) {
                result += PyUnicode_AsUTF8(verify_info);
            }
            if (error_info) {
                result += "\n" + std::string(PyUnicode_AsUTF8(error_info));
            }
        }
        Py_DECREF(py_result);
    }
    else {
        PyErr_Print();
        result += "Failed to call method '_verify'\n";
    }

    // 获取所有的stdout和stderr输出
    PyObject* output = PyObject_CallMethod(string_io, "getvalue", NULL);
    if (output) {
        result += PyUnicode_AsUTF8(output);
        Py_DECREF(output);
    }
    else {
        result += "Failed to get output from StringIO.\n";
    }

    Py_DECREF(string_io);
    Py_DECREF(io);

    return result;
}




//根据CVE_Id查Script
std::string findScriptByCveId(std::vector<ScanHostResult>& scan_host_result, const std::string& cve_id) {
    // 遍历所有的 ScanHostResult
    for (const auto& hostResult : scan_host_result) {
        // 遍历主机的CPES
        for (const auto& cpe : hostResult.cpes) {
            for (const auto& cve : cpe.second) {
                if (cve.CVE_id == cve_id) {
                    return cve.script; // 找到匹配的CVE，返回script
                }
            }
        }

        // 遍历主机的端口
        for (const auto& port : hostResult.ports) {
            for (const auto& cpe : port.cpes) {
                for (const auto& cve : cpe.second) {
                    if (cve.CVE_id == cve_id) {
                        return cve.script; // 找到匹配的CVE，返回script
                    }
                }
            }
        }
    }

    return ""; // 如果没有找到，返回空字符串
}

//根据cve_id查portId
std::string findPortIdByCveId(std::vector<ScanHostResult>& scan_host_result, const std::string& cve_id) {
    // 遍历所有的 ScanHostResult
    for (const auto& hostResult : scan_host_result) {
        // 遍历主机扫描结果中的端口
        for (const auto& portResult : hostResult.ports) {
            // 遍历端口下的CPE条目
            for (const auto& cpeEntry : portResult.cpes) {
                // 遍历CPE条目中的CVE列表
                for (const auto& cve : cpeEntry.second) {
                    if (cve.CVE_id == cve_id) {
                        return portResult.portId; // 找到匹配的CVE_id，返回对应的portId
                    }
                }
            }
        }
    }

    return ""; // 如果没有找到，返回空字符串
}

// 判断 CPE 是否一致，返回不一致的 CPE
std::vector<std::string> compareCPEs(const std::map<std::string, std::vector<CVE>>& newCPEs, const std::map<std::string, std::vector<CVE>>& oldCPEs) {
    std::vector<std::string> changedCPEs;

    // 使用 C++14 兼容的方式遍历
    for (const auto& newCPE_pair : newCPEs) {
        const auto& newCPE = newCPE_pair.first;
        if (oldCPEs.find(newCPE) == oldCPEs.end()) {
            changedCPEs.push_back(newCPE); // 如果找不到对应的 CPE，说明该 CPE 发生了变化
        }
    }

    return changedCPEs; // 返回需要查询的 CPE 列表
}

// 比对并更新结果，根据端口信息和 CPE 信息来决定查询策略
void compareAndUpdateResults(const ScanHostResult& oldResult, ScanHostResult& newResult, int limit) {
    // 处理操作系统层面的增量扫描
    std::cout << "开始操作系统层面的增量扫描..." << std::endl;
    std::vector<std::string> osCPEsToQuery;  // 用于存储需要查询的操作系统 CPE

    for (auto& newCPE_pair : newResult.cpes) {
        const auto& newCPE = newCPE_pair.first;
        auto& newCVEList = newCPE_pair.second;

        if (oldResult.cpes.find(newCPE) != oldResult.cpes.end()) {
            // CPE 相同，复用历史的 CVE 数据
            std::cout << "操作系统 CPE " << newCPE << " 沿用历史 CVE 数据。" << std::endl;
            newCVEList = oldResult.cpes.at(newCPE); // 复用历史 CVE
        }
        else {
            // CPE 不同，记录需要查询的 CPE
            std::cout << "操作系统 CPE " << newCPE << " 信息有变化，记录查询。" << std::endl;
            osCPEsToQuery.push_back(newCPE);  // 记录新 CPE 以便批量查询
        }
    }

    // 一次性查询操作系统层面的所有新的 CPE 的 CVE
    if (!osCPEsToQuery.empty()) {
        fetch_and_padding_cves(newResult.cpes, osCPEsToQuery, limit);
    }

    // 处理端口层面的增量扫描
    std::cout << "开始端口层面的增量扫描..." << std::endl;
    std::unordered_map<std::string, ScanResult> oldPortsMap;

    // 将旧的端口信息存入 map，端口号作为 key
    for (const auto& oldPort : oldResult.ports) {
        oldPortsMap[oldPort.portId] = oldPort;
    }

    // 遍历新扫描的结果
    for (auto& newPort : newResult.ports) {
        std::vector<std::string> portCPEsToQuery;  // 用于存储每个端口需要查询的 CPE

        if (oldPortsMap.find(newPort.portId) != oldPortsMap.end()) {
            // 找到相同的端口，判断其他信息是否一致
            const auto& oldPort = oldPortsMap[newPort.portId];

            if (newPort.protocol == oldPort.protocol &&
                newPort.service_name == oldPort.service_name &&
                newPort.status == oldPort.status){

                // 其他信息一致，逐个 CPE 进行比对和处理
                for (auto& newCPE_pair : newPort.cpes) {
                    const auto& newCPE = newCPE_pair.first;
                    auto& newCVEList = newCPE_pair.second;

                    if (oldPort.cpes.find(newCPE) != oldPort.cpes.end()) {
                        // CPE 相同，复用历史的 CVE 数据
                        std::cout << "端口 " << newPort.portId << " 的 CPE " << newCPE << " 沿用历史 CVE 数据。" << std::endl;
                        newCVEList = oldPort.cpes.at(newCPE); // 复用历史 CVE
                    }
                    else {
                        // CPE 不同，记录需要查询的 CPE
                        std::cout << "端口 " << newPort.portId << " 的 CPE " << newCPE << " 信息有变化，记录查询。" << std::endl;
                        portCPEsToQuery.push_back(newCPE);  // 记录新 CPE 以便批量查询
                    }
                }

            }
            else {
                // 如果其他信息不一致，说明端口变化，重新查询所有 CPE 的 CVE
                std::cout << "端口 " << newPort.portId << " 信息发生变化，重新查询所有 CPE 的 CVE。" << std::endl;
                for (const auto& cpe_pair : newPort.cpes) {
                    portCPEsToQuery.push_back(cpe_pair.first);  // 记录所有 CPE
                }
            }
        }
        else {
            // 新增端口，查询所有 CPE
            std::cout << "端口 " << newPort.portId << " 是新端口，查询所有 CPE 的 CVE。" << std::endl;
            for (const auto& cpe_pair : newPort.cpes) {
                portCPEsToQuery.push_back(cpe_pair.first);  // 记录所有 CPE
            }
        }

        // 一次性查询端口层面的所有新的 CPE 的 CVE
        if (!portCPEsToQuery.empty()) {
            fetch_and_padding_cves(newPort.cpes, portCPEsToQuery, limit);
        }
    }
}


// CVE 查询函数
void fetch_and_padding_cves(std::map<std::string, std::vector<CVE>>& cpes, const std::vector<std::string>& cpes_to_query, int limit) {
    std::string base_url = "http://192.168.177.129:5000/api/cvefor";

    for (const auto& cpe_id : cpes_to_query) {
        auto& vecCVE = cpes[cpe_id];
        web::uri_builder builder(U(base_url));
        builder.append_path(U(cpe_id));
        if (limit > 0) {
            builder.append_query(U("limit"), limit);
        }

        web::http::client::http_client client(builder.to_uri());
        try {
            client.request(web::http::methods::GET)
                .then([&](web::http::http_response response) -> pplx::task<web::json::value> {
                if (response.status_code() == web::http::status_codes::OK) {
                    return response.extract_json();
                }
                else {
                    std::cerr << "Failed to fetch CVE data for CPE: " << cpe_id << ", Status code: " << response.status_code() << std::endl;
                    return pplx::task_from_result(web::json::value());
                }
                    }).then([&](web::json::value jsonObject) {
                        if (!jsonObject.is_null()) {
                            auto cve_array = jsonObject.as_array();
                            for (auto& cve : cve_array) {
                                CVE tmp;
                                tmp.CVE_id = cve[U("id")].as_string();
                                std::string cvss_str = "N/A";  // 默认值为 "N/A"
                                if (cve.has_field(U("cvss"))) {
                                    auto cvss_value = cve[U("cvss")];
                                    if (cvss_value.is_string()) {
                                        cvss_str = cvss_value.as_string();  // 处理字符串类型的 CVSS
                                    }
                                    else if (cvss_value.is_number()) {
                                        cvss_str = std::to_string(cvss_value.as_number().to_double());  // 处理数字类型的 CVSS
                                    }
                                    else {
                                        std::cerr << "Unexpected CVSS type for CPE: " << cpe_id << std::endl;
                                    }
                                }
                                else {
                                    std::cout << "CVSS field not present for CPE: " << cpe_id << std::endl;
                                }
                                tmp.CVSS = cvss_str;
                                if (cve.has_field(U("summary"))) {
                                    tmp.summary = cve[U("summary")].as_string();
                                    std::cout << "Summary: " << cve[U("summary")].as_string() << std::endl;
                                }
                                vecCVE.push_back(tmp);
                            }
                        }
                        }).wait();
        }
        catch (const std::exception& e) {
            std::cerr << "Exception occurred while fetching CVE data for CPE: " << cpe_id << ", Error: " << e.what() << std::endl;
        }
    }
}
