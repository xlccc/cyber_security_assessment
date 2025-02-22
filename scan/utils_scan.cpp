#include "utils_scan.h"
#include <rapidxml.hpp>
#include <rapidxml_utils.hpp>
#include <stdexcept>

// 解析XML文件以获取扫描结果
std::vector<ScanHostResult> parseXmlFile(const std::string& xmlFilePath) {
    std::vector<ScanHostResult> scanHostResults;

    // Open the XML file
    std::ifstream file(xmlFilePath);
    if (!file) {
        std::cerr << "Failed to open XML file: " << xmlFilePath << std::endl;
        return scanHostResults; // Return empty result
    }

    // Read the content of the XML file into a string
    std::string xmlContent((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    // Create a RapidXML parser
    rapidxml::xml_document<> xmlDoc;
    try {
        xmlDoc.parse<0>(&xmlContent[0]);
    }
    catch (rapidxml::parse_error& e) {
        std::cerr << "Failed to parse XML file: " << e.what() << std::endl;
        return scanHostResults; // Return empty result
    }

    // Get the root node "nmaprun"
    rapidxml::xml_node<>* rootNode = xmlDoc.first_node("nmaprun");
    if (!rootNode) {
        std::cerr << "No 'nmaprun' node found in XML file." << std::endl;
        return scanHostResults; // Return empty result
    }

    // Iterate over each host node
    for (rapidxml::xml_node<>* hostNode = rootNode->first_node("host"); hostNode; hostNode = hostNode->next_sibling("host")) {
        ScanHostResult hostResult;

        // Extract the IP address
        rapidxml::xml_node<>* addressNode = hostNode->first_node("address");
        if (addressNode) {
            rapidxml::xml_attribute<>* ipAttr = addressNode->first_attribute("addr");
            if (ipAttr) {
                hostResult.ip = ipAttr->value();
            }
        }

        // Extract OS family names and detailed matches from "osclass" and "osmatch"
        rapidxml::xml_node<>* osNode = hostNode->first_node("os");
        if (osNode) {
            for (rapidxml::xml_node<>* osMatchNode = osNode->first_node("osmatch"); osMatchNode; osMatchNode = osMatchNode->next_sibling("osmatch")) {

                // Extract detailed OS match information
                rapidxml::xml_attribute<>* osMatchAttr = osMatchNode->first_attribute("name");
                if (osMatchAttr) {
                    hostResult.os_matches.push_back(osMatchAttr->value());
                }

                // Extract general OS family information
                for (rapidxml::xml_node<>* osClassNode = osMatchNode->first_node("osclass"); osClassNode; osClassNode = osClassNode->next_sibling("osclass")) {
                    rapidxml::xml_attribute<>* osFamilyAttr = osClassNode->first_attribute("osfamily");
                    if (osFamilyAttr) {
                        hostResult.os_list.insert(osFamilyAttr->value());
                    }
                    for (rapidxml::xml_node<>* cpeNode = osClassNode->first_node("cpe"); cpeNode; cpeNode = cpeNode->next_sibling("cpe")) {
                        std::string cpe = cpeNode->value();
                        hostResult.cpes[cpe] = std::vector<Vuln>(); // Initialize empty CVE vector
                    }
                }
            }
        }

        // Extract port scan information
        rapidxml::xml_node<>* portsNode = hostNode->first_node("ports");
        if (portsNode) {
            for (rapidxml::xml_node<>* portNode = portsNode->first_node("port"); portNode; portNode = portNode->next_sibling("port")) {
                ScanResult scanResult;

                // Extract port number
                rapidxml::xml_attribute<>* portIdAttr = portNode->first_attribute("portid");
                if (portIdAttr) {
                    scanResult.portId = portIdAttr->value();
                }

                // Extract protocol type
                rapidxml::xml_attribute<>* protocolAttr = portNode->first_attribute("protocol");
                if (protocolAttr) {
                    scanResult.protocol = protocolAttr->value();
                }

                // Extract port state
                rapidxml::xml_node<>* stateNode = portNode->first_node("state");
                if (stateNode) {
                    rapidxml::xml_attribute<>* stateAttr = stateNode->first_attribute("state");
                    if (stateAttr) {
                        scanResult.status = stateAttr->value();
                    }
                }

                // Extract service information
                rapidxml::xml_node<>* serviceNode = portNode->first_node("service");
                if (serviceNode) {
                    // Extract service name
                    rapidxml::xml_attribute<>* nameAttr = serviceNode->first_attribute("name");
                    if (nameAttr) {
                        scanResult.service_name = nameAttr->value();
                        scanResult.softwareType = matchServiceType(scanResult.service_name, rules);
                    }
                    // Extract product name
                    rapidxml::xml_attribute<>* productAttr = serviceNode->first_attribute("product");
                    if (productAttr) {
                        scanResult.product = productAttr->value();
                        scanResult.softwareType = matchServiceType(scanResult.product, rules);
                    }
                    // Extract version
                    rapidxml::xml_attribute<>* versionAttr = serviceNode->first_attribute("version");
                    if (versionAttr) {
                        scanResult.version = versionAttr->value();
                    }

                    // Extract CPE information and initialize CVE vector
                    for (rapidxml::xml_node<>* cpeNode = serviceNode->first_node("cpe"); cpeNode; cpeNode = cpeNode->next_sibling("cpe")) {
                        std::string cpe = cpeNode->value();
                        scanResult.cpes[cpe] = std::vector<Vuln>(); // Initialize empty CVE vector
                    }
                }

                // Add the port scan result to the host result
                hostResult.ports.push_back(scanResult);
            }
        }

        // Add the host scan result to the result list
        scanHostResults.push_back(hostResult);
    }

    return scanHostResults; // Return the parsed results
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
    std::cout << "正在执行：" << scriptPath_extension << std::endl;

    // 去除文件扩展名
    std::string scriptPath = removeExtension(scriptPath_extension);
    std::cout << "去除后缀：" << scriptPath << std::endl;

    // 重定向 stdout 和 stderr
    PyObject* string_io = PyObject_CallMethod(global_io, "StringIO", NULL);
    if (!string_io) {
        std::cerr << "无法创建 StringIO。" << std::endl;
        return result;
    }
    PyObject* sys = PyImport_ImportModule("sys");
    PyObject_SetAttrString(sys, "stdout", string_io);
    PyObject_SetAttrString(sys, "stderr", string_io);
    Py_DECREF(sys); // 使用完毕后释放 sys

    // 导入 POC 模块
    PyObject* poc_module = PyImport_ImportModule(scriptPath.c_str());
    if (!poc_module) {
        PyErr_Print();
        result += "无法加载脚本：" + scriptPath + "\n";
        Py_DECREF(string_io);
        return result;
    }

    // 重新加载模块
    PyObject* reload_func = PyObject_GetAttrString(global_importlib, "reload");
    if (reload_func && PyCallable_Check(reload_func)) {
        PyObject* reloaded_module = PyObject_CallFunctionObjArgs(reload_func, poc_module, NULL);
        if (!reloaded_module) {
            PyErr_Print();
            result += "无法重新加载模块：" + scriptPath + "\n";
        }
        Py_XDECREF(reloaded_module);
    }
    Py_XDECREF(reload_func);
    std::cout << "模块成功加载或刷新" << std::endl;

    // 获取类对象 DemoPOC
    PyObject* poc_class = PyObject_GetAttrString(poc_module, "DemoPOC");
    if (!poc_class || !PyCallable_Check(poc_class)) {
        PyErr_Print();
        result += "找不到类 'DemoPOC'\n";
        Py_DECREF(poc_module);
        Py_DECREF(string_io);
        return result;
    }

    // 实例化 DemoPOC 对象
    PyObject* poc_instance = PyObject_CallFunction(poc_class, "ssi", url.c_str(), ip.c_str(), port);
    if (!poc_instance) {
        PyErr_Print();
        result += "无法实例化 'DemoPOC'\n";
        Py_DECREF(poc_class);
        Py_DECREF(poc_module);
        Py_DECREF(string_io);
        return result;
    }

    // 调用 _verify 方法
    PyObject* verify_func = PyObject_GetAttrString(poc_instance, "_verify");
    if (!verify_func || !PyCallable_Check(verify_func)) {
        PyErr_Print();
        result += "找不到 '_verify' 方法\n";
        Py_DECREF(poc_instance);
        Py_DECREF(poc_class);
        Py_DECREF(poc_module);
        Py_DECREF(string_io);
        return result;
    }

    // 执行 _verify 方法
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
        result += "调用 '_verify' 方法失败\n";
    }

    // 获取所有的 stdout 和 stderr 输出
    PyObject* output = PyObject_CallMethod(string_io, "getvalue", NULL);
    if (output) {
        result += PyUnicode_AsUTF8(output);
        Py_DECREF(output);
    }
    else {
        result += "无法从 StringIO 获取输出。\n";
    }

    Py_DECREF(string_io); // 释放 string_io
    std::cout << "运行结果：" << std::endl << result << std::endl;

    return result;
}


//// Python 任务执行函数（线程安全）
//std::string runPythonWithOutput(const std::string& scriptPath_extension, const std::string& url, const std::string& ip, int port) {
//    std::string result = "";
//
//    // 确保 GIL 在此线程中获取
//    PyGILState_STATE gstate;
//    gstate = PyGILState_Ensure();  // 获取GIL
//
//    std::cout << "正在执行：" << scriptPath_extension << std::endl;
//    PyObject* io = PyImport_ImportModule("io");
//    if (!io) {
//        std::cerr << "Failed to import io." << std::endl;
//        PyGILState_Release(gstate);  // 释放GIL
//        return result;
//    }
//
//    PyObject* string_io = PyObject_CallMethod(io, "StringIO", NULL);
//    if (!string_io) {
//        std::cerr << "Failed to create StringIO." << std::endl;
//        Py_DECREF(io);
//        PyGILState_Release(gstate);  // 释放GIL
//        return result;
//    }
//
//    PyObject* sys = PyImport_ImportModule("sys");
//    PyObject_SetAttrString(sys, "stdout", string_io);
//    PyObject_SetAttrString(sys, "stderr", string_io);
//
//    // 导入POC模块
//    std::string scriptPath = removeExtension(scriptPath_extension);
//    PyObject* poc_module = PyImport_ImportModule(scriptPath.c_str());
//    if (!poc_module) {
//        PyObject* ptype, * pvalue, * ptraceback;
//        PyErr_Fetch(&ptype, &pvalue, &ptraceback);
//        PyErr_NormalizeException(&ptype, &pvalue, &ptraceback);
//        PyObject* pStrErrorMessage = PyObject_Str(pvalue);
//        std::cerr << "Error message: " << PyUnicode_AsUTF8(pStrErrorMessage) << std::endl;
//        Py_DECREF(pStrErrorMessage);
//        Py_DECREF(io);
//        Py_DECREF(string_io);
//        PyGILState_Release(gstate);  // 释放GIL
//        return result;
//    }
//
//    PyObject* poc_class = PyObject_GetAttrString(poc_module, "DemoPOC");
//    PyObject* poc_instance = PyObject_CallFunction(poc_class, "ssi", url.c_str(), ip.c_str(), port);
//
//    PyObject* verify_func = PyObject_GetAttrString(poc_instance, "_verify");
//    PyObject* py_result = PyObject_CallObject(verify_func, NULL);
//
//    // 获取结果
//    if (py_result) {
//        if (PyDict_Check(py_result)) {
//            PyObject* verify_info = PyDict_GetItemString(py_result, "VerifyInfo");
//            if (verify_info) {
//                result += PyUnicode_AsUTF8(verify_info);
//            }
//        }
//        Py_DECREF(py_result);
//    }
//
//    // 获取 stdout 和 stderr
//    PyObject* output = PyObject_CallMethod(string_io, "getvalue", NULL);
//    if (output) {
//        result += PyUnicode_AsUTF8(output);
//        Py_DECREF(output);
//    }
//
//    Py_DECREF(string_io);
//    Py_DECREF(io);
//
//    // 释放 GIL
//    PyGILState_Release(gstate);
//
//    return result;
//}





//根据CVE_Id查Script
std::string findScriptByCveId(std::vector<ScanHostResult>& scan_host_result, const std::string& cve_id) {
    // 遍历所有的 ScanHostResult
    for (const auto& hostResult : scan_host_result) {
        // 遍历主机的CPES
        for (const auto& cpe : hostResult.cpes) {
            for (const auto& cve : cpe.second) {
                if (cve.Vuln_id == cve_id) {
                    return cve.script; // 找到匹配的CVE，返回script
                }
            }
        }

        // 遍历主机的端口
        for (const auto& port : hostResult.ports) {
            for (const auto& cpe : port.cpes) {
                for (const auto& cve : cpe.second) {
                    if (cve.Vuln_id == cve_id) {
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
                    if (cve.Vuln_id == cve_id) {
                        return portResult.portId; // 找到匹配的CVE_id，返回对应的portId
                    }
                }
            }
        }
    }

    return ""; // 如果没有找到，返回空字符串
}

// 判断 CPE 是否一致，返回不一致的 CPE
std::vector<std::string> compareCPEs(const std::map<std::string, std::vector<Vuln>>& newCPEs, const std::map<std::string, std::vector<Vuln>>& oldCPEs) {
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
void fetch_and_padding_cves(std::map<std::string, std::vector<Vuln>>& cpes, const std::vector<std::string>& cpes_to_query, int limit) {
    std::string base_url = "http://10.9.130.189:5000/api/cvefor";

    for (const auto& cpe_id : cpes_to_query) {
        auto& vecCVE = cpes[cpe_id];
        web::uri_builder builder(_XPLATSTR(base_url));
        builder.append_path(_XPLATSTR(cpe_id));
        if (limit > 0) {
            builder.append_query(_XPLATSTR("limit"), limit);
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
                                Vuln tmp;
                                tmp.Vuln_id = cve[_XPLATSTR("id")].as_string();
                                std::string cvss_str = "N/A";  // 默认值为 "N/A"
                                if (cve.has_field(_XPLATSTR("cvss"))) {
                                    auto cvss_value = cve[_XPLATSTR("cvss")];
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
                                if (cve.has_field(_XPLATSTR("summary"))) {
                                    tmp.summary = cve[_XPLATSTR("summary")].as_string();
                                    //插入漏洞类型
                                    tmp.vulnType = matchVulnType(tmp.summary, vulnTypes);
                                    std::cout << "Summary: " << cve[_XPLATSTR("summary")].as_string() << std::endl;
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



//创建POC任务
std::map<std::string, std::vector<POCTask>> create_poc_task(const std::vector<POC>& poc_list, const ScanHostResult& scan_host_result, bool match_infra) {
    std::map<std::string, std::set<POCTask>> temp_tasks_by_port;
    std::map<std::string, std::vector<POCTask>> poc_tasks_by_port;

    for (const auto& poc : poc_list) {
        // 如果 script 字段为空，则跳过该 POC
        if (poc.script.empty()) {
            continue;
        }

        std::string infra_lower = poc.affected_infra;
        std::transform(infra_lower.begin(), infra_lower.end(), infra_lower.begin(), ::tolower);

        // 操作系统匹配
        for (const auto& os : scan_host_result.os_list) {
            std::string os_lower = os;
            std::transform(os_lower.begin(), os_lower.end(), os_lower.begin(), ::tolower);

            if (os_lower.find(infra_lower) != std::string::npos) {
                POCTask task;
                task.url = scan_host_result.url;
                task.ip = scan_host_result.ip;
                task.port = ""; // 空字符串表示操作系统任务

                Vuln vuln;
                vuln.Vuln_id = poc.vuln_id;
                vuln.vul_name = poc.vul_name;
                vuln.script = poc.script;
                vuln.summary = poc.description;
                task.vuln = vuln;

                temp_tasks_by_port[task.port].insert(task);
                break;
            }
        }

        // 协议或应用匹配
        for (const auto& port : scan_host_result.ports) {
            std::string service_lower = port.service_name;
            std::string product_lower = port.product;
            std::transform(service_lower.begin(), service_lower.end(), service_lower.begin(), ::tolower);
            std::transform(product_lower.begin(), product_lower.end(), product_lower.begin(), ::tolower);

            if (service_lower.find(infra_lower) != std::string::npos || product_lower.find(infra_lower) != std::string::npos) {
                POCTask task;
                task.url = scan_host_result.url;
                task.ip = scan_host_result.ip;
                task.port = port.portId;

                Vuln vuln;
                vuln.Vuln_id = poc.vuln_id;
                vuln.vul_name = poc.vul_name;
                vuln.script = poc.script;
                vuln.summary = poc.description;
                task.vuln = vuln;

                temp_tasks_by_port[task.port].insert(task);
            }
        }
    }

    // 将去重后的任务转存到 std::vector 中
    for (auto it = temp_tasks_by_port.begin(); it != temp_tasks_by_port.end(); ++it) {
        const std::string& port = it->first;
        const std::set<POCTask>& task_set = it->second;
        poc_tasks_by_port[port] = std::vector<POCTask>(task_set.begin(), task_set.end());
    }

    return poc_tasks_by_port;
}

//创建POC任务
//POC扫描所有开放端口，不进行基础设施匹配的版本（使用两个参数）
std::map<std::string, std::vector<POCTask>> create_poc_task(const std::vector<POC>& poc_list, const ScanHostResult& scan_host_result) {
    std::map<std::string, std::set<POCTask>> temp_tasks_by_port;
    std::map<std::string, std::vector<POCTask>> poc_tasks_by_port;

    for (const auto& poc : poc_list) {
        // 如果 script 字段为空，则跳过该 POC
        if (poc.script.empty()) {
            continue;
        }

        // 针对每个端口生成任务（不进行基础设施匹配）
        for (const auto& port : scan_host_result.ports) {
            POCTask task;
            task.url = scan_host_result.url;
            task.ip = scan_host_result.ip;
            task.port = port.portId;

            Vuln vuln;
            vuln.Vuln_id = poc.vuln_id;
            vuln.vul_name = poc.vul_name;
            vuln.script = poc.script;
            vuln.summary = poc.description;
            task.vuln = vuln;

            temp_tasks_by_port[task.port].insert(task);
        }

        // 如果没有端口，针对操作系统生成任务
        if (scan_host_result.ports.empty()) {
            POCTask task;
            task.url = scan_host_result.url;
            task.ip = scan_host_result.ip;
            task.port = "";  // 空字符串表示操作系统任务

            Vuln vuln;
            vuln.Vuln_id = poc.vuln_id;
            vuln.vul_name = poc.vul_name;
            vuln.script = poc.script;
            vuln.summary = poc.description;
            task.vuln = vuln;

            temp_tasks_by_port[task.port].insert(task);
        }
    }

    // 将去重后的任务转存到 std::vector 中
    for (auto it = temp_tasks_by_port.begin(); it != temp_tasks_by_port.end(); ++it) {
        const std::string& port = it->first;
        const std::set<POCTask>& task_set = it->second;
        poc_tasks_by_port[port] = std::vector<POCTask>(task_set.begin(), task_set.end());
    }

    return poc_tasks_by_port;
}

void execute_poc_tasks(std::map<std::string, std::vector<POCTask>>& poc_tasks_by_port, ScanHostResult& scan_host_result, ConnectionPool& pool, DatabaseHandler& dbHandler) {

    // 记录开始时间
    auto start = std::chrono::high_resolution_clock::now();

    for (auto it = poc_tasks_by_port.begin(); it != poc_tasks_by_port.end(); ++it) {
        const std::string& key = it->first;
        std::vector<POCTask>& tasks = it->second;

        for (auto& task : tasks) {
            //std::cout << "运行脚本：" << task.vuln.script << std::endl;

            task.vuln.script =  task.vuln.script;
            //std::cout << "脚本路径：" << task.vuln.script << std::endl;
            std::string result = runPythonWithOutput(task.vuln.script, task.url, task.ip, key.empty() ? 0 : std::stoi(key));

            if (result.find("[!]") != std::string::npos) {
                task.vuln.vulExist = "存在";
            }
            else if (result.find("[SAFE]") != std::string::npos) {
                task.vuln.vulExist = "不存在";
            }
            else {
                task.vuln.vulExist = "未验证"; 
            }
            dbHandler.alterVulnAfterPocTask(pool, task);
            if (key.empty()) {
                scan_host_result.vuln_result.insert(task.vuln);
            }
            else {
                auto port_it = std::find_if(scan_host_result.ports.begin(), scan_host_result.ports.end(),
                    [&key](const ScanResult& port) { return port.portId == key; });
                if (port_it != scan_host_result.ports.end()) {
                    port_it->vuln_result.insert(task.vuln);
                }
            }
        }
    }
    // 记录结束时间
    auto end = std::chrono::high_resolution_clock::now();

    // 计算时间差并输出到控制台
    std::chrono::duration<double> elapsed = end - start;
    std::cout << "POC tasks executed in " << elapsed.count() << " seconds." << std::endl;
}
// 
//void execute_poc_tasks(std::map<std::string, std::vector<POCTask>>& poc_tasks_by_port, ScanHostResult& scan_host_result) {
//    // 记录开始时间
//    auto start = std::chrono::high_resolution_clock::now();
//
//    // 使用线程池执行POC任务
//    std::vector<std::future<void>> futures;
//    std::mutex result_mutex;  // 用于保护 scan_host_result 的并发访问
//
//    for (auto it = poc_tasks_by_port.begin(); it != poc_tasks_by_port.end(); ++it) {
//        const std::string& key = it->first;
//        std::vector<POCTask>& tasks = it->second;
//
//        // 使用线程池执行每个任务
//        futures.emplace_back(std::async(std::launch::async, [&tasks, &scan_host_result, &key, &result_mutex]() {
//            for (auto& task : tasks) {
//                std::string result;
//                try {
//                    result = runPythonWithOutput(task.vuln.script, task.url, task.ip, key.empty() ? 0 : std::stoi(key));
//                }
//                catch (const std::exception& e) {
//                    std::cerr << "POC execution error: " << e.what() << std::endl;
//                    result = "[ERROR]";
//                }
//
//                // 更新漏洞存在状态
//                if (result.find("[!]") != std::string::npos) {
//                    task.vuln.vulExist = "存在";
//                }
//                else if (result.find("[SAFE]") != std::string::npos) {
//                    task.vuln.vulExist = "不存在";
//                }
//                else {
//                    task.vuln.vulExist = "未验证";
//                }
//
//                // 使用锁保护对 scan_host_result 的并发修改
//                std::lock_guard<std::mutex> lock(result_mutex);
//
//                if (key.empty()) {
//                    scan_host_result.vuln_result.insert(task.vuln);  // 针对操作系统的漏洞插入
//                }
//                else {
//                    auto port_it = std::find_if(scan_host_result.ports.begin(), scan_host_result.ports.end(),
//                        [&key](const ScanResult& port) { return port.portId == key; });
//                    if (port_it != scan_host_result.ports.end()) {
//                        port_it->vuln_result.insert(task.vuln);  // 针对端口的漏洞插入
//                    }
//                }
//            }
//            }));
//    }
//
//    // 设置超时并等待所有线程完成
//    for (auto& future : futures) {
//        try {
//            if (future.valid()) {
//                future.wait_for(std::chrono::seconds(task_timeout_seconds));
//            }
//        }
//        catch (const std::future_error& e) {
//            std::cerr << "Error waiting for task completion: " << e.what() << std::endl;
//        }
//    }
//
//    // 记录结束时间
//    auto end = std::chrono::high_resolution_clock::now();
//
//    // 计算时间差并输出到控制台
//    std::chrono::duration<double> elapsed = end - start;
//    std::cout << "POC tasks executed in " << elapsed.count() << " seconds." << std::endl;
//}

//合并 漏洞库匹配、插件化扫描两种方式的扫描结果
void merge_vuln_results(ScanHostResult& host_result) {
    std::cout << "开始合并操作系统漏洞..." << std::endl;

    // 合并操作系统漏洞
    std::set<Vuln> merged_os_vulns;

    // 插入插件化扫描的漏洞，忽略“未验证”的漏洞
    for (const auto& poc_vuln : host_result.vuln_result) {
        std::cout << "检查插件化扫描漏洞: " << poc_vuln.vul_name
            << " (ID: " << poc_vuln.Vuln_id << "), 状态: " << poc_vuln.vulExist << std::endl;

        if (poc_vuln.vulExist != "未验证") {
            merged_os_vulns.insert(poc_vuln);  // 插入插件化扫描的漏洞
            std::cout << "已添加插件化扫描漏洞: " << poc_vuln.vul_name << std::endl;
        }
        else {
            std::cout << "跳过未验证的漏洞: " << poc_vuln.vul_name << std::endl;
        }
    }

    // 插入漏洞库匹配中的漏洞（如果插件化扫描中没有）
    for (const auto& cpe_entry : host_result.cpes) {
        for (const auto& cpe_vuln : cpe_entry.second) {
            if (merged_os_vulns.find(cpe_vuln) == merged_os_vulns.end()) {
                merged_os_vulns.insert(cpe_vuln);  // 插入漏洞库匹配中的漏洞
                std::cout << "已添加漏洞库匹配中的漏洞: " << cpe_vuln.vul_name
                    << " (ID: " << cpe_vuln.Vuln_id << ")" << std::endl;
            }
            else {
                std::cout << "漏洞库匹配中的漏洞已存在，跳过: " << cpe_vuln.vul_name << std::endl;
            }
        }
    }

    // 更新操作系统漏洞结果
    host_result.vuln_result = merged_os_vulns;
    std::cout << "操作系统漏洞合并完成，漏洞总数: " << host_result.vuln_result.size() << std::endl;

    // 合并端口漏洞
    for (auto& port : host_result.ports) {
        std::cout << "开始合并端口: " << port.portId << " 的漏洞..." << std::endl;
        std::set<Vuln> merged_port_vulns;

        // 插入插件化扫描中的漏洞，忽略“未验证”的漏洞
        for (const auto& poc_vuln : port.vuln_result) {
            std::cout << "检查端口插件化扫描漏洞: " << poc_vuln.vul_name
                << " (ID: " << poc_vuln.Vuln_id << "), 状态: " << poc_vuln.vulExist << std::endl;

            if (poc_vuln.vulExist != "未验证") {
                merged_port_vulns.insert(poc_vuln);
                std::cout << "已添加端口插件化扫描漏洞: " << poc_vuln.vul_name << std::endl;
            }
            else {
                std::cout << "跳过未验证的端口漏洞: " << poc_vuln.vul_name << std::endl;
            }
        }

        // 插入漏洞库匹配中的漏洞（如果插件化扫描中没有）
        for (const auto& cpe_entry : port.cpes) {
            for (const auto& cpe_vuln : cpe_entry.second) {
                if (merged_port_vulns.find(cpe_vuln) == merged_port_vulns.end()) {
                    merged_port_vulns.insert(cpe_vuln);
                    std::cout << "已添加端口漏洞库匹配中的漏洞: " << cpe_vuln.vul_name
                        << " (ID: " << cpe_vuln.Vuln_id << ")" << std::endl;
                }
                else {
                    std::cout << "端口漏洞库匹配中的漏洞已存在，跳过: " << cpe_vuln.vul_name << std::endl;
                }
            }
        }

        // 更新端口漏洞结果
        port.vuln_result = merged_port_vulns;
        std::cout << "端口 " << port.portId << " 的漏洞合并完成，漏洞总数: " << port.vuln_result.size() << std::endl;
    }
    std::cout << "所有漏洞合并完成！" << std::endl;
}

