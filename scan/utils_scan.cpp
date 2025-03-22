#include "utils_scan.h"
#include <rapidxml.hpp>
#include <rapidxml_utils.hpp>
#include <stdexcept>

#define MAX_PROCESSES 4;

//// 声明一个全局变量来保存 Redis 连接（用于插件化扫描的多进程的进程通信、任务分配）
//redisContext* redis_client = nullptr;

// 解析XML文件以获取扫描结果
std::vector<ScanHostResult> parseXmlFile(const std::string& xmlFilePath) {
    std::vector<ScanHostResult> scanHostResults;

    // Open the XML file
    std::ifstream file(xmlFilePath);
    if (!file) {
        system_logger->error("Failed to open XML file: {}", xmlFilePath);
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
        system_logger->error("Failed to parse XML file: {}", e.what());
        return scanHostResults; // Return empty result
    }

    // Get the root node "nmaprun"
    rapidxml::xml_node<>* rootNode = xmlDoc.first_node("nmaprun");
    if (!rootNode) {
        system_logger->error("No 'nmaprun' node found in XML file.");
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
    system_logger->info("Executing script: {}", scriptPath_extension);
    console->info("Executing script: {}", scriptPath_extension);

    // 清除 Python 解释器的错误状态
    PyErr_Clear();

    // 去除文件扩展名
    std::string scriptPath = removeExtension(scriptPath_extension);
    system_logger->info("Removed extension: {}", scriptPath);
    console->info("Removed extension: {}", scriptPath);

    if (!global_io || !PyModule_Check(global_io)) {
        console->error("global_io is invalid , reloading now");
        PyObject* io_module = PyImport_ImportModule("io");
        if (io_module) {
            global_io = Py_BuildValue("O", io_module);
            Py_DECREF(io_module);
            console->error("global_io is reloaded now");
        }
        else {
            system_logger->error("Failed to import 'io' module.");
            console->error("Failed to import 'io' module.");
            return "";
        }
    }
    
    PyObject* sys = PyImport_ImportModule("sys");
    // 保存原始的 sys.stdout 和 sys.stderr
    PyObject* original_stdout = PyObject_GetAttrString(sys, "stdout");
    PyObject* original_stderr = PyObject_GetAttrString(sys, "stderr");

    // 重定向 stdout 和 stderr
    PyObject* string_io = PyObject_CallMethod(global_io, "StringIO", NULL);
    if (!string_io) {
        system_logger->error("Failed to create StringIO.");
        console->error("Failed to create StringIO.");
        Py_DECREF(sys);
        return result;
    }
    PyObject_SetAttrString(sys, "stdout", string_io);
    PyObject_SetAttrString(sys, "stderr", string_io);
    Py_DECREF(sys);


    
    // 导入 POC 模块
    PyObject* poc_module = PyImport_ImportModule(scriptPath.c_str());
    if (!poc_module) {
        PyObject* type, * value, * traceback;
        PyErr_Fetch(&type, &value, &traceback);
        PyErr_NormalizeException(&type, &value, &traceback);

        if (value) {
            PyObject* str_value = PyObject_Str(value);
            if (str_value) {
                const char* utf8_str = PyUnicode_AsUTF8(str_value);
                std::string error_msg = utf8_str ? utf8_str : "";
                result += "无法加载脚本：" + scriptPath + "，错误信息：" + error_msg;
                console->error("无法加载脚本：{} , 错误信息：{} ", scriptPath, error_msg);;
                Py_DECREF(str_value);
            }
        }
        Py_XDECREF(type);
        Py_XDECREF(value);
        Py_XDECREF(traceback);
        Py_DECREF(string_io);
        return result;
    }
    
    /*旧版：错误信息不完整
    if (!poc_module) {
        PyErr_Print();
        system_logger->error("无法加载脚本：{}",scriptPath);
        result += "无法加载脚本：" + scriptPath + "\n";
        Py_DECREF(string_io);
        return result;
    }*/


    // 重新加载模块
    PyObject* reload_func = PyObject_GetAttrString(global_importlib, "reload");
    if (reload_func && PyCallable_Check(reload_func)) {
        PyObject* reloaded_module = PyObject_CallFunctionObjArgs(reload_func, poc_module, NULL);
        if (!reloaded_module) {
            PyObject* type, * value, * traceback;
            PyErr_Fetch(&type, &value, &traceback);
            PyErr_NormalizeException(&type, &value, &traceback);

            if (value) {
                PyObject* str_value = PyObject_Str(value);
                if (str_value) {
                    const char* utf8_str = PyUnicode_AsUTF8(str_value);
                    std::string error_msg = utf8_str ? utf8_str : "";
                    result += "无法重新加载模块：" + scriptPath + "，错误信息：" + error_msg;
                    console->error("无法重新加载模块：{}，错误信息：{}", scriptPath, error_msg);
                    Py_DECREF(str_value);
                }
            }
            Py_XDECREF(type);
            Py_XDECREF(value);
            Py_XDECREF(traceback);
            return result;
        }
        Py_XDECREF(reloaded_module);
    }
    /*旧版：错误信息不完整
    if (reload_func && PyCallable_Check(reload_func)) {
        PyObject* reloaded_module = PyObject_CallFunctionObjArgs(reload_func, poc_module, NULL);
        if (!reloaded_module) {
            PyErr_Print();
            system_logger->error("无法重新加载模块：{}", scriptPath);
            result += "无法重新加载模块：" + scriptPath + "\n";
        }
        Py_XDECREF(reloaded_module);
    }
    */

    Py_XDECREF(reload_func);
    system_logger->info("Module successfully loaded or refreshed.");
    console->info("Module successfully loaded or refreshed.");
    

    // 获取类对象 DemoPOC
    PyObject* poc_class = PyObject_GetAttrString(poc_module, "DemoPOC");
    if (!poc_class || !PyCallable_Check(poc_class)) {
        PyErr_Print();
        system_logger->error("找不到类 'DemoPOC");
        console->error("找不到类 'DemoPOC");
        result += "找不到类 'DemoPOC'\n";
        Py_DECREF(poc_module);
        Py_DECREF(string_io);
        return result;
    }

    // 实例化 DemoPOC 对象
    PyObject* poc_instance = PyObject_CallFunction(poc_class, "ssi", url.c_str(), ip.c_str(), port);
    if (!poc_instance) {
        PyErr_Print();
        system_logger->error("无法实例化 'DemoPOC'");
        console->error("无法实例化 'DemoPOC'");
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
        system_logger->error("找不到 '_verify' 方法");
        console->error("找不到 '_verify' 方法");
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
                const char* verify_utf8 = PyUnicode_AsUTF8(verify_info);
                result += verify_utf8 ? verify_utf8 : "";
            }
            if (error_info) {
                const char* error_utf8 = PyUnicode_AsUTF8(error_info);
                std::string error_msg = error_utf8 ? error_utf8 : "";
                result += "\n" + error_msg;;
            }
        }
        Py_DECREF(py_result);
    }
    else {
        PyErr_Print();
        result += "调用 '_verify' 方法失败\n";
        console->error("调用 '_verify' 方法失败");
    }

    // 获取所有的 stdout 和 stderr 输出
    PyObject* output = PyObject_CallMethod(string_io, "getvalue", NULL);
    if (output) {
        const char* output_utf8 = PyUnicode_AsUTF8(output);
        result += output_utf8 ? output_utf8 : "";
        Py_DECREF(output);
    }
    else {
        console->error("无法从 StringIO 获取输出。\n");
        result += "无法从 StringIO 获取输出。\n";
    }

    // 恢复原始的 sys.stdout 和 sys.stderr
    PyObject_SetAttrString(sys, "stdout", original_stdout);
    PyObject_SetAttrString(sys, "stderr", original_stderr);
    Py_DECREF(original_stdout);
    Py_DECREF(original_stderr);

    Py_DECREF(string_io); // 释放 string_io
    console->debug("Execution result:\n{}", result);

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

Vuln& findCveByCveId(std::vector<ScanHostResult>& scan_host_result, const std::string& cve_id)
{
	// 遍历所有的 ScanHostResult
	for (auto& hostResult : scan_host_result) {
		// 遍历主机的CPES
		for (auto& cpe : hostResult.cpes) {
			for (auto& cve : cpe.second) {
				if (cve.Vuln_id == cve_id) {
					return cve; // 找到匹配的CVE，返回引用
				}
			}
		}

		// 遍历主机的端口
		for (auto& port : hostResult.ports) {
			for (auto& cpe : port.cpes) {
				for (auto& cve : cpe.second) {
					if (cve.Vuln_id == cve_id) {
						return cve; // 找到匹配的CVE，返回引用
					}
				}
			}
		}
	}

	throw std::runtime_error("CVE ID not found: " + cve_id); // 如果没有找到，抛出异常
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
    system_logger->info("开始操作系统层面的增量扫描...");
    std::vector<std::string> osCPEsToQuery;  // 用于存储需要查询的操作系统 CPE
    
    for (auto& newCPE_pair : newResult.cpes) {
        const auto& newCPE = newCPE_pair.first;
        auto& newCVEList = newCPE_pair.second;

        if (oldResult.cpes.find(newCPE) != oldResult.cpes.end()) {
            // CPE 相同，复用历史的 CVE 数据vs
            //console_logger->info("OS CPE {} uses historical CVE data.", newCPE);
            newCVEList = oldResult.cpes.at(newCPE); // 复用历史 CVE
        }
        else {
            // CPE 不同，记录需要查询的 CPE
            //console_logger->info("操作系统 CPE {} 信息有变化，查询可能的CVE漏洞", newCPE);
            osCPEsToQuery.push_back(newCPE);  // 记录新 CPE 以便批量查询
        }
    }

    // 一次性查询操作系统层面的所有新的 CPE 的 CVE
    if (!osCPEsToQuery.empty()) {
        fetch_and_padding_cves(newResult.cpes, osCPEsToQuery, limit);
    }

    // 处理端口层面的增量扫描
    system_logger->info("开始端口层面的增量扫描...");

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

                        //console_logger->info("端口 {} 的 CPE {} 沿用历史 CVE 数据。", newPort.portId, newCPE);
                        newCVEList = oldPort.cpes.at(newCPE); // 复用历史 CVE
                    }
                    else {
                        // CPE 不同，记录需要查询的 CPE
                        //console_logger->info("端口 {}的 CPE {} 信息有变化，查询可能的CVE漏洞", newPort.portId, newCPE);

                        portCPEsToQuery.push_back(newCPE);  // 记录新 CPE 以便批量查询
                    }
                }

            }
            else {
                // 如果其他信息不一致，说明端口变化，重新查询所有 CPE 的 CVE
                //console_logger->info("端口 {} 信息发生变化，重新查询所有 CPE 的 CVE。", newPort.portId);
                for (const auto& cpe_pair : newPort.cpes) {
                    portCPEsToQuery.push_back(cpe_pair.first);  // 记录所有 CPE
                }
            }
        }
        else {
            // 新增端口，查询所有 CPE
            //console_logger->info("端口 {} 是新端口，查询所有 CPE 的 CVE。", newPort.portId);
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
    std::string base_url = "http://192.168.136.128:5000/api/cvefor";

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
                    system_logger->error("Failed to fetch CVE data for CPE: {}, Status code: {}", cpe_id, response.status_code());
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
                                        system_logger->error("Unexpected CVSS type for CPE: {}", cpe_id);
                                    }
                                }
                                else {
                                    system_logger->warn("CVSS field not present for CPE: {}", cpe_id);
                                }
                                tmp.CVSS = cvss_str;
                                if (cve.has_field(_XPLATSTR("summary"))) {
                                    tmp.summary = cve[_XPLATSTR("summary")].as_string();
                                    //插入漏洞类型
                                    tmp.vulnType = matchVulnType(tmp.summary, vulnTypes);
                                    //console->info("CVE summary: {}", cve[_XPLATSTR("summary")].as_string());
                                }
                                vecCVE.push_back(tmp);
                            }
                        }
                        }).wait();
        }
        catch (const std::exception& e) {
            system_logger->error("Exception occurred while fetching CVE data for CPE: {}, Error: {}", cpe_id, e.what());

        }
    }
}



//创建POC任务
std::map<std::string, std::vector<POCTask>> create_poc_task(const std::vector<POC>& poc_list, const ScanHostResult& scan_host_result, bool match_infra) {
    int seq = 0; //任务序号，递增
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
                vuln.pocExist = true;
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
                vuln.pocExist = true;
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
            vuln.pocExist = true;
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
            vuln.pocExist = true;
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

//获取任务计数变量的专属ID
std::string generate_unique_task_id() {
    auto now = std::chrono::system_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    return "TASK_" + std::to_string(getpid()) + "_" + std::to_string(duration.count());
}

//初始化任务计数
void initialize_task_count(redisContext* redis_client, int task_count, std::string unique_key) {
    std::string task_count_key = "TASK_COUNT_" + unique_key;
    redisReply* reply = (redisReply*)redisCommand(redis_client, "SET %s %d", task_count_key.c_str(), task_count);
    if (!reply || reply->type == REDIS_REPLY_ERROR) {
        console->error("[Parent Process] Failed to initialize task count: {}", redis_client->errstr);
    }
    else {
        console->info("[Parent Process] Task count initialized to {} for key {}", task_count, task_count_key);
    }
    freeReplyObject(reply);
}

//清除任务计数变量
void cleanup_task_count(redisContext* redis_client, std::string unique_key) {
    std::string task_count_key = "TASK_COUNT_" + unique_key;
    redisReply* reply = (redisReply*)redisCommand(redis_client, "DEL %s", task_count_key.c_str());
    if (!reply || reply->type == REDIS_REPLY_ERROR) {
        console->error("[Parent Process] Failed to delete task count key: {}", task_count_key);
    }
    else {
        console->info("[Parent Process] Task count key {} deleted.", task_count_key);
    }
    freeReplyObject(reply);
}


// 多进程执行 POC 任务
void execute_poc_tasks_parallel(std::map<std::string, std::vector<POCTask>>& poc_tasks_by_port, ScanHostResult& scan_host_result, DatabaseHandler& dbHandler, ConnectionPool& pool) {

    system_logger->info("Executing poc tasks parallelly");
    console->info("Total CPU cores: {}", std::thread::hardware_concurrency());

    // 记录开始时间
    auto start = std::chrono::high_resolution_clock::now();

    std::vector<pid_t> child_pids;
    redisContext* redis_client = get_redis_client();  // 获取 Redis 客户端（父进程）

    // 加上超时设置
    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
    redisSetTimeout(redis_client, timeout);

    //// 在父进程中初始化 Python 环境
    //Py_Initialize();
    system_logger->info("[Parent Process] Python environment initialized.");

    int total_task_count = 0;

    // 发布任务到 Redis 队列
    for (auto& entry : poc_tasks_by_port) {
        const std::string& key = entry.first;
        std::vector<POCTask>& tasks = entry.second;

        for (auto& task : tasks) {
            std::string task_data = serialize_task_data(key, task);  // 将任务序列化为字符串
            push_task_to_redis(redis_client, task_data);  // 发布任务到 Redis 队列
            
            total_task_count++;//任务计数+1
        }
    }

    //初始化任务计数变量
    std::string unique_task_id = generate_unique_task_id();
    initialize_task_count(redis_client, total_task_count, unique_task_id);

    // 获取列表所有元素
    redisReply* reply = (redisReply*)redisCommand(redis_client, "LRANGE POC_TASK_QUEUE 0 -1");
    if (reply == NULL) {
        std::cout << "执行 LRANGE 命令失败" << std::endl;
    }
    std::cout << "父进程。列表元素: ";
    for (size_t i = 0; i < reply->elements; i++) {
        std::cout << reply->element[i]->str << " ";
    }
    cout << endl;
    freeReplyObject(reply);

    // 父进程不再直接执行任务，而是等待子进程处理 Redis 队列中的任务
    for (int i = 0; i < 3; i++) {
        pid_t pid = fork();

        if (pid == 0) {

            console->info("process {} start ", getpid());

            // 让子进程独立建立 Redis 连接
            redisContext* child_redis_client = get_redis_client();
            if (!child_redis_client || child_redis_client->err) {
                fprintf(stderr, "[ERROR] Child Process %d: Failed to connect to Redis! %s\n", getpid(), child_redis_client ? child_redis_client->errstr : "NULL");
                _exit(1);
            }

            // 加上超时设置
            struct timeval timeout;
            timeout.tv_sec = 2;
            timeout.tv_usec = 0;
            redisSetTimeout(child_redis_client, timeout);

            console->info("[Child Process {}] Redis connection initialized.", getpid());

            //子进程初始化python解释器
            initializePython();


            system_logger->info("[Child Process] Redis connection initialized/get.");

            // 执行任务的循环
            while (true) {
                std::string task_data = pop_task_from_redis(child_redis_client, unique_task_id);
                cout << "process :" << getpid() << " task_data : " << task_data << endl;
                cout << "task_data.empty: " << task_data.empty() << endl;
                if (task_data.empty()) {
                    console->info("[Child Process] No tasks in Redis, exiting. process {}",getpid());
                    system_logger->info("[Child Process] No tasks in Redis, exiting.");
                    
                    //释放python解释器
                    Py_Finalize();

                    redisFree(child_redis_client);  // 子进程完成后关闭连接

                    cout << "process :" << getpid() << " 关闭redis链接。。。。 " << endl;
                    _exit(0);  // 子进程完成后退出
                }

                // 反序列化任务并获取 key
                auto task = deserialize_task_data(task_data);  // 任务已经包含了 key 和 POCTask
                std::string key = task.first;  // 获取 key

                // 执行任务
                execute_poc_task(key, task.second, child_redis_client, dbHandler, pool);  // 正确传递 key 和任务

            }
        }
        else if (pid > 0) {
            // 父进程：记录子进程 PID
            child_pids.push_back(pid);
            system_logger->info("[Parent Process] Forked child process with PID: {}", pid);
        }
        else {
            system_logger->error("Fork failed for task.");
        }
    }

    sleep(2);

    // 等待所有子进程完成
    for (pid_t pid : child_pids) {
        int status;
        while (true) {
            pid_t terminated_pid = waitpid(pid, &status, WNOHANG);
            if (terminated_pid > 0) {
                if (WIFEXITED(status)) {
                    console->info("[Parent Process] Child process {} exited normally with status {}", terminated_pid, WEXITSTATUS(status));
                }
                else if (WIFSIGNALED(status)) {
                    console->error("[Parent Process] Child process {} was terminated by signal {}", terminated_pid, WTERMSIG(status));
                }
                break;
            }
            else if (terminated_pid == 0) {
                console->info("[Parent Process] Waiting for child process {}...", pid);
                sleep(1);
            }
            else if (errno == ECHILD) {
                console->info("[Parent Process] No more child processes to wait for.");
                break;
            }
        }
    }



    // 父进程读取 Redis 中的任务结果
    while (true) {
        std::string result_data = pop_result_from_redis(redis_client);
        if (result_data.empty()) break;  // 如果队列为空，退出循环

        std::pair<std::string, Vuln> result = deserialize_task_result(result_data);
        std::string portId = result.first;
        Vuln vuln = result.second;

        console->info("[Parent Process] Received result from port: {}, Vuln ID: {}", portId, vuln.Vuln_id);

        if (portId.empty()) {
            // 查找是否已经存在相同的漏洞信息
            auto it = scan_host_result.vuln_result.find(vuln);

            if (it != scan_host_result.vuln_result.end()) {
                // 移除已有的漏洞信息
                scan_host_result.vuln_result.erase(it);
            }
            // 插入新的漏洞信息，实现覆盖效果
            scan_host_result.vuln_result.insert(vuln);
            dbHandler.alterHostVulnResultAfterPocVerify(pool, vuln, scan_host_result.ip);
            console->info("[Parent Process] Overwritten OS-level vuln ID: {} in scan_host_result", vuln.Vuln_id);
        }
        else {

            auto port_it = std::find_if(scan_host_result.ports.begin(), scan_host_result.ports.end(),
                [&portId](const ScanResult& port) { return port.portId == portId; });

            if (port_it != scan_host_result.ports.end()) {
                // 查找端口的漏洞信息中是否已经存在相同的漏洞
                auto vuln_it = port_it->vuln_result.find(vuln);
                if (vuln_it != port_it->vuln_result.end()) {
                    // 移除已有的漏洞信息
                    port_it->vuln_result.erase(vuln_it);
                }
                // 插入新的漏洞信息，实现覆盖效果
                port_it->vuln_result.insert(vuln);
                console->info("[Parent Process] Overwritten port-level vuln ID: {} into port: {}", vuln.Vuln_id, portId);
                // 将更新后的漏洞信息同步到数据库
                dbHandler.alterPortVulnResultAfterPocVerify(pool, vuln, scan_host_result.ip, portId);
            }
            else {
                console->error("[Parent Process]: Port ID {} not found in scan_host_result.", portId);
                system_logger->error("[Parent Process]: Port ID {} not found in scan_host_result.", portId);
            }
        }
    }

    //// 在父进程中清理 Python 环境
    //Py_Finalize();
    system_logger->info("[Parent Process] Python environment finalized.");

    //清除任务计数
    cleanup_task_count(redis_client, unique_task_id);


    // 记录结束时间
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;
    system_logger->info("Parallel POC tasks executed in {} seconds.", elapsed.count());

    console->info("[Parent Process] execute pocs task paralelly compelete !");
}

//多进程版本的单个POC任务执行
void execute_poc_task(const std::string& key, POCTask& task, redisContext* redis_client, DatabaseHandler& dbHandler, ConnectionPool& pool) {

    // 执行 Python 脚本并获取输出
    std::string result = runPythonWithOutput(task.vuln.script, task.url, task.ip, key.empty() ? 0 : std::stoi(key));

    // 根据结果判断漏洞是否存在
    if (result.find("[!]") != std::string::npos) {
        task.vuln.vulExist = "存在";
    }
    else if (result.find("[SAFE]") != std::string::npos) {
        task.vuln.vulExist = "不存在";
    }
    else {
        task.vuln.vulExist = "未验证";
    }
    //if(key.empty()){
    //    dbHandler.alterHostVulnResultAfterPocVerify(pool, task.vuln, task.ip);
    //}
    //else {
    //    dbHandler.alterPortVulnResultAfterPocVerify(pool, task.vuln, task.ip, key);
    //}
    
    // 将任务结果序列化为 JSON
    std::string serialized_result = serialize_task_result(task.vuln, key);

    // 发布到 Redis 结果队列
    push_result_to_redis(redis_client, serialized_result);

}


////非多进程版本
//void execute_poc_tasks(std::map<std::string, std::vector<POCTask>>& poc_tasks_by_port, ScanHostResult& scan_host_result) {
//
//    // 记录开始时间
//    auto start = std::chrono::high_resolution_clock::now();
//
//    for (auto it = poc_tasks_by_port.begin(); it != poc_tasks_by_port.end(); ++it) {
//        const std::string& key = it->first;
//        std::vector<POCTask>& tasks = it->second;
//
//        for (auto& task : tasks) {
//            //std::cout << "运行脚本：" << task.vuln.script << std::endl;
//
//            task.vuln.script =  task.vuln.script;
//            //std::cout << "脚本路径：" << task.vuln.script << std::endl;
//            std::string result = runPythonWithOutput(task.vuln.script, task.url, task.ip, key.empty() ? 0 : std::stoi(key));
//
//            if (result.find("[!]") != std::string::npos) {
//                task.vuln.vulExist = "存在";
//            }
//            else if (result.find("[SAFE]") != std::string::npos) {
//                task.vuln.vulExist = "不存在";
//            }
//            else {
//                task.vuln.vulExist = "未验证"; 
//            }
//
//            if (key.empty()) {
//                scan_host_result.vuln_result.insert(task.vuln);
//            }
//            else {
//                auto port_it = std::find_if(scan_host_result.ports.begin(), scan_host_result.ports.end(),
//                    [&key](const ScanResult& port) { return port.portId == key; });
//                if (port_it != scan_host_result.ports.end()) {
//                    port_it->vuln_result.insert(task.vuln);
//                }
//            }
//        }
//    }
//    // 记录结束时间
//    auto end = std::chrono::high_resolution_clock::now();
//
//    // 计算时间差并输出到控制台
//    std::chrono::duration<double> elapsed = end - start;
//    std::cout << "POC tasks executed in " << elapsed.count() << " seconds." << std::endl;
//}

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
    console->info("开始合并操作系统漏洞...");
    system_logger->info("IP : {} 开始合并操作系统漏洞...", host_result.ip);

    // 合并操作系统漏洞
    std::set<Vuln> merged_os_vulns;

    // 插入插件化扫描的漏洞，忽略“未验证”的漏洞
    for (const auto& poc_vuln : host_result.vuln_result) {
        //console->info("检查插件化扫描漏洞: {} (ID: {}), Status: {}", poc_vuln.vul_name, poc_vuln.Vuln_id, poc_vuln.vulExist);

        if (poc_vuln.vulExist != "未验证") {
            merged_os_vulns.insert(poc_vuln);  // 插入插件化扫描的漏洞
            //console->info("已添加插件化扫描漏洞: {}", poc_vuln.vul_name);
        }
        else {
            //console->info("跳过未验证的漏洞: {}", poc_vuln.vul_name);
        }
    }

    // 插入漏洞库匹配中的漏洞（如果插件化扫描中没有）
    for (const auto& cpe_entry : host_result.cpes) {
        for (const auto& cpe_vuln : cpe_entry.second) {
            if (merged_os_vulns.find(cpe_vuln) == merged_os_vulns.end()) {
                merged_os_vulns.insert(cpe_vuln);  // 插入漏洞库匹配中的漏洞

                //console_logger->info("已添加漏洞库匹配中的漏洞: {} (ID: {})", cpe_vuln.vul_name, cpe_vuln.Vuln_id);
            }
            else {
                //console_logger->info("漏洞库匹配中的漏洞已存在，跳过: {}", cpe_vuln.vul_name);
            }
        }
    }

    // 更新操作系统漏洞结果
    host_result.vuln_result = merged_os_vulns;
    console->info("操作系统漏洞合并完成，漏洞总数: {}", host_result.vuln_result.size());
    system_logger->info("操作系统漏洞合并完成，漏洞总数: {}", host_result.vuln_result.size());

    // 合并端口漏洞
    for (auto& port : host_result.ports) {
        console->info("IP : {} 开始合并端口 {} 的漏洞...", host_result.ip, port.portId);
        system_logger->info("IP : {} 开始合并端口 {} 的漏洞...", host_result.ip,port.portId);
        std::set<Vuln> merged_port_vulns;

        // 插入插件化扫描中的漏洞，忽略“未验证”的漏洞
        for (const auto& poc_vuln : port.vuln_result) {

            //console->info("检查端口插件化扫描漏洞: {} (POC ID: {}), Status: {}", poc_vuln.vul_name, poc_vuln.Vuln_id, poc_vuln.vulExist);

            if (poc_vuln.vulExist != "未验证") {
                merged_port_vulns.insert(poc_vuln);
                //console->info("已添加端口插件化扫描漏洞: {}", poc_vuln.vul_name);
            }
            else {
                //console->info("跳过未验证的端口漏洞: {}", poc_vuln.vul_name);
            }
        }

        // 插入漏洞库匹配中的漏洞（如果插件化扫描中没有）
        for (const auto& cpe_entry : port.cpes) {
            for (const auto& cpe_vuln : cpe_entry.second) {
                if (merged_port_vulns.find(cpe_vuln) == merged_port_vulns.end()) {
                    merged_port_vulns.insert(cpe_vuln);

                    //console->info("已添加端口漏洞库匹配中的漏洞: {} (ID:{})", cpe_vuln.vul_name, cpe_vuln.Vuln_id);
                }
                else {
                    //console->info("端口漏洞库匹配中的漏洞已存在，跳过:  {}", cpe_vuln.vul_name);

                }
            }
        }

        // 更新端口漏洞结果
        port.vuln_result = merged_port_vulns;

        console->info("端口 {} 的漏洞合并完成，漏洞总数: {}", port.portId, port.vuln_result.size());
    }

    system_logger->info("IP : {} 所有漏洞合并完成！", host_result.ip);
}


// 将 Vuln 对象序列化为 JSON 字符串，包含完整字段和端口标识
std::string serialize_task_result(const Vuln& vuln, const std::string& portId) {
    json j;
    j["portId"] = portId;
    j["Vuln_id"] = vuln.Vuln_id;
    j["vul_name"] = vuln.vul_name;
    j["script"] = vuln.script;
    j["CVSS"] = vuln.CVSS;
    j["summary"] = vuln.summary;
    j["pocExist"] = vuln.pocExist;
    j["ifCheck"] = vuln.ifCheck;
    j["vulExist"] = vuln.vulExist;
    return j.dump();
}

// 从 JSON 字符串反序列化为 Vuln 对象，包含完整字段和端口标识
std::pair<std::string, Vuln> deserialize_task_result(const std::string& data) {
    try
    {
        json j = json::parse(data);
        std::string portId = j.value("portId", "");

        Vuln vuln;
        // 安全获取各个字段的值
        vuln.Vuln_id = j.value("Vuln_id", "");
        vuln.vul_name = j.value("vul_name", "");
        vuln.script = j.value("script", "");
        vuln.CVSS = j.value("CVSS", "");
        vuln.summary = j.value("summary", "");
        vuln.pocExist = j.value("pocExist", false);
        vuln.ifCheck = j.value("ifCheck", false);
        vuln.vulExist = j.value("vulExist", "");

        return std::make_pair(portId, vuln);
    }
    catch (const nlohmann::json::parse_error& e) {
        std::cerr << "JSON parse error: " << e.what() << std::endl;
        // 返回默认值
        return std::make_pair("", Vuln());
    } catch (const std::exception& e) {
        std::cerr << "Unexpected error: " << e.what() << std::endl;
        // 返回默认值
        return std::make_pair("", Vuln());
    }
}

redisContext* get_redis_client() {
    struct timeval timeout;
    timeout.tv_sec = 2;
    timeout.tv_usec = 0;

    redisContext* ctx = redisConnectWithTimeout("127.0.0.1", 6379, timeout);
    if (ctx == nullptr || ctx->err) {
        std::cerr << "Error connecting to Redis: "
            << (ctx ? ctx->errstr : "null") << std::endl;
        exit(1);
    }

    // 设置命令超时
    redisSetTimeout(ctx, timeout);
    return ctx;
}

//// 获取 Redis 客户端连接（如果已经创建过，则复用）
//redisContext* get_redis_client() {
//    if (redis_client == nullptr) {
//        // 如果没有连接，则创建新的连接
//        redis_client = redisConnect("127.0.0.1", 6379);
//        if (redis_client == nullptr || redis_client->err) {
//            system_logger->error("Error connecting to Redis: {}", redis_client->errstr);
//            exit(1);
//        }
//    }
//    return redis_client;
//}

// 序列化 POCTask 数据
std::string serialize_task_data(const std::string& key, const POCTask& task) {
    nlohmann::json j;

    // 序列化 POCTask 中的字段
    j["url"] = task.url;
    j["ip"] = task.ip;
    j["port"] = task.port;

    // 序列化 Vuln 对象
    nlohmann::json vuln_json;
    vuln_json["Vuln_id"] = task.vuln.Vuln_id;
    vuln_json["vul_name"] = task.vuln.vul_name;
    vuln_json["script"] = task.vuln.script;
    vuln_json["CVSS"] = task.vuln.CVSS;
    vuln_json["summary"] = task.vuln.summary;
    vuln_json["pocExist"] = task.vuln.pocExist;
    vuln_json["ifCheck"] = task.vuln.ifCheck;
    vuln_json["vulExist"] = task.vuln.vulExist;


    cout << task.vuln.script << endl;

    // 将 Vuln 序列化后的数据嵌入 POCTask
    j["vuln"] = vuln_json;

    // 包含 key 信息
    nlohmann::json result;
    result["key"] = key;
    result["task"] = j;

    // 返回 JSON 字符串
    return result.dump();
}

/// 反序列化 POCTask 数据
std::pair<std::string, POCTask> deserialize_task_data(const std::string& task_data) {
    try {
        // 解析 JSON 字符串
        json j = json::parse(task_data);

        // 提取 key
        std::string key = j.value("key", "");
        if (key.empty()) {
            console->error("Error deserializing task data: 'key' not found in JSON.");
            system_logger->error("Error deserializing task data: 'key' not found in JSON.");
        }

        POCTask task;
        // 提取 task 信息
        auto task_json = j.value("task", json::object());
        task.url = task_json.value("url", "");
        task.ip = task_json.value("ip", "");
        task.port = task_json.value("port", "");

        // 反序列化 Vuln 对象
        auto vuln_json = task_json.value("vuln", json::object());
        // 直接赋值，无需转换
        task.vuln.Vuln_id = vuln_json.value("Vuln_id", "");
        task.vuln.vul_name = vuln_json.value("vul_name", "");
        task.vuln.script = vuln_json.value("script", "");
        task.vuln.CVSS = vuln_json.value("CVSS", "");
        task.vuln.summary = vuln_json.value("summary", "");
        task.vuln.pocExist = vuln_json.value("pocExist", false);
        task.vuln.ifCheck = vuln_json.value("ifCheck", false);
        // 获取字符串类型的值
        task.vuln.vulExist = vuln_json.value("vulExist", "未验证");

        return { key, task };  // 返回 key 和任务
    }
    catch (const std::exception& e) {
        console->error("Error deserializing task data: {}", e.what());
        system_logger->error("Error deserializing task data: {}", e.what());
        return { "", POCTask() };  // 处理异常并返回默认值
    }
}



// 发布任务到 Redis 队列
void push_task_to_redis(redisContext* c, const std::string& task_data) {
    redisReply* reply = (redisReply*)redisCommand(c, "LPUSH POC_TASK_QUEUE %s", task_data.c_str());
    if (reply == nullptr) {
        console->error("Error pushing task to Redis.");
        system_logger->error("Error pushing task to Redis.");
    }
    console->info("[Parent Process] Pushed task to Redis: {}", task_data);
    freeReplyObject(reply);
}

std::string getRedisReplyType(int type) {
    switch (type) {
    case REDIS_REPLY_STRING: return "REDIS_REPLY_STRING (字符串)";
    case REDIS_REPLY_ARRAY: return "REDIS_REPLY_ARRAY (数组)";
    case REDIS_REPLY_INTEGER: return "REDIS_REPLY_INTEGER (整数)";
    case REDIS_REPLY_NIL: return "REDIS_REPLY_NIL (空值)";
    case REDIS_REPLY_STATUS: return "REDIS_REPLY_STATUS (状态)";
    case REDIS_REPLY_ERROR: return "REDIS_REPLY_ERROR (错误)";
    default: return "UNKNOWN_REPLY_TYPE (未知类型)";
    }
}

void printReplyType(redisReply* reply) {
    if (!reply) {
        std::cout << "[ERROR] Redis reply is NULL" << std::endl;
        return;
    }
    std::cout << "reply->type : " << getRedisReplyType(reply->type) << " process : " << getpid() << std::endl;
}
std::string pop_task_from_redis(redisContext* redis_client, const std::string& unique_key) {
    int pid = getpid();

    std::string lua_script = R"(
        local task_count_key = KEYS[1]
        local queue_key = KEYS[2]
        local pid = ARGV[1]

        redis.log(redis.LOG_NOTICE, "[" .. pid .. "] Start Lua task pop")

        local count = redis.call('GET', task_count_key)
        redis.log(redis.LOG_NOTICE, "[" .. pid .. "] Task count: " .. (count or "nil"))
        if not count or tonumber(count) <= 0 then
            redis.log(redis.LOG_NOTICE, "[" .. pid .. "] No tasks available -- task_count nil or <= 0")
            return nil
            end

            local task = redis.call('RPOP', queue_key)
            if task then
                redis.call('DECR', task_count_key)
                redis.log(redis.LOG_NOTICE, "[" ..pid .. "] Task found and task_count decremented")
                return task
            else
                redis.log(redis.LOG_NOTICE, "[" ..pid .. "] RPOP returned nil, not decrementing")
                return nil
                end
                )";

        redisReply * reply = (redisReply*)redisCommand(redis_client,
            "EVAL %s 2 TASK_COUNT_%s POC_TASK_QUEUE %d", lua_script.c_str(), unique_key.c_str(), pid);

        cout << "执行完EVAL脚本返回了：" << pid << endl;

        
        if (!reply) {
            if (redis_client->err == REDIS_ERR_TIMEOUT) {
                std::cout << "[PID " << getpid() << "] Redis command timeout: " << redis_client->errstr << std::endl;
            }
            else {
                std::cout << "[PID " << getpid() << "] Redis command failed: " << redis_client->errstr << std::endl;
                //std::cout << "[" << pid << "] Redis command failed (null reply)" << std::endl;
            }
            return "";
        }

        cout << "不是NULL ：" << pid << endl;

        std::string task_data = "";

        if (!reply) {
        cout << " Popped task failed : " << getpid() << endl;
        return "";
        }

        switch (reply->type) {
        case REDIS_REPLY_STRING:
            if (reply->str) {
                task_data = reply->str;
                console->info("{} [pop_task_from_redis] Popped task data: {}", pid, task_data);
            }
            else {
                console->warn("{} [pop_task_from_redis] Reply string is null", pid);
            }
            break;
        case REDIS_REPLY_NIL:
            console->info("{} [pop_task_from_redis] No task in Redis (NIL)", pid);
            break;
        default:
            console->warn("{} [pop_task_from_redis] Unexpected reply type: {}, raw value: {}",
                pid,
                reply->type,
                (reply->type == REDIS_REPLY_INTEGER) ? std::to_string(reply->integer)
                : (reply->str ? reply->str : "null"));
            break;
        }

        freeReplyObject(reply);
        return task_data;
}


//之前一个半可用的版本
//// 从 Redis 队列获取任务
//std::string pop_task_from_redis(redisContext* redis_client, std::string unique_key) {
//    // 获取列表所有元素
//    /*
//    redisReply* reply = (redisReply*)redisCommand(redis_client, "LRANGE POC_TASK_QUEUE 0 -1");
//    if (reply == NULL) {
//        std::cout << "执行 LRANGE 命令失败" << std::endl;
//        return "";
//    }
//    std::cout << "列表元素: ";
//    for (size_t i = 0; i < reply->elements; i++) {
//        std::cout << reply->element[i]->str << " ";
//    }
//    cout << endl;
//    */
//
//    int pid = getpid(); // 获取当前进程的 PID
//
//    // Lua 脚本，增加 `pid` 作为 `ARGV[1]`
//    std::string lua_script = R"(
//        local task_count_key = KEYS[1]
//        local queue_key = KEYS[2]
//        local pid = ARGV[1]  -- 从参数获取 C++ 进程 PID
//
//        redis.log(redis.LOG_NOTICE, "[" .. pid .. "] Executing Lua script")
//        local task_count = redis.call('GET', task_count_key)
//        redis.log(redis.LOG_NOTICE, "[" .. pid .. "] Task count: " .. (task_count or "nil"))
//
//        if not task_count or tonumber(task_count) <= 0 then
//            redis.log(redis.LOG_NOTICE, "[" .. pid .. "] Task count is 0 or nil, returning nil")
//            return nil
//        end
//
//        local task = redis.call('RPOP', queue_key)
//        redis.log(redis.LOG_NOTICE, "[" .. pid .. "] RPOP task: " .. (task or "nil"))
//
//        if task then
//            redis.call('DECR', task_count_key)
//            redis.log(redis.LOG_NOTICE, "[" .. pid .. "] Decrementing task count")
//            return task
//        end
//
//        return nil
//    )";
//
//    // 传递 `PID` 作为 `ARGV[1]`
//    redisReply* reply = (redisReply*)redisCommand(redis_client,
//        "EVAL %s 2 TASK_COUNT_%s POC_TASK_QUEUE %d", lua_script.c_str(), unique_key.c_str(), pid);
//
//
//    if (!reply || reply->type == REDIS_REPLY_NIL) {
//        //console->info("{} [pop_task_from_redis] No task found or task count is 0.", getpid());
//        //system_logger->info("{} [pop_task_from_redis] No task found or task count is 0.", getpid());
//
//        cout << " 准备退出 ：" << getpid() << endl;
//        if(reply)
//            freeReplyObject(reply);
//
//        cout << " 成功退出 ：" << getpid() << endl;
//        return "";
//    }
//
//    //处理 `RPOP` 直接返回字符串的情况
//    if (reply->type == REDIS_REPLY_STRING && reply->str != nullptr) {
//        std::string task_data(reply->str);
//        console->info("{} [pop_task_from_redis] Popped task data: {}", getpid(), task_data);
//        freeReplyObject(reply);
//        return task_data;
//    }
//
//    printReplyType(reply);
//
//    if(reply->type == REDIS_REPLY_INTEGER)
//        cout << "整数类型：" << reply->integer << endl;
//
//    freeReplyObject(reply);
//    return "";
//}




// 将任务结果推送到 Redis 结果队列
void push_result_to_redis(redisContext* c, const std::string& result_data) {
    redisReply* reply = (redisReply*)redisCommand(c, "LPUSH POC_RESULT_QUEUE %s", result_data.c_str());
    cout << "没卡住" << getpid() << endl;
    if (reply == nullptr) {
        console->error("Error pushing result to Redis.");
        system_logger->error("Error pushing result to Redis.");
    }
    console->info("[Child Process] Pushed result to Redis: {}", result_data);
    freeReplyObject(reply);
}

// 从 Redis 获取任务结果
std::string pop_result_from_redis(redisContext* c) {
    console->info("[DEBUG] Attempting to pop result from Redis...");

    redisReply* reply = (redisReply*)redisCommand(c, "RPOP POC_RESULT_QUEUE");

    // 检查 Redis 命令是否成功执行
    if (reply == nullptr) {
        console->error("[ERROR] Redis command failed, reply is nullptr.");
        system_logger->error("[ERROR] Redis command failed, reply is nullptr.");
        return "";
    }

    // 检查返回的数据是否为空
    if (reply->type == REDIS_REPLY_NIL) {
        console->info("[DEBUG] No result in the Redis queue (RPOP returned NIL).");
        freeReplyObject(reply);
        return "";
    }

    // 这里需要额外检查 reply->str 是否为 nullptr
    if (reply->type == REDIS_REPLY_STRING && reply->str == nullptr) {
        console->error("[ERROR] Redis reply string is null although type is REDIS_REPLY_STRING.");
        system_logger->error("[ERROR] Redis reply string is null although type is REDIS_REPLY_STRING.");
        freeReplyObject(reply);
        return "";
    }

    // 再次检查 reply->str 是否为 nullptr
    if (reply->str == nullptr) {
        console->error("[ERROR] Redis reply string is null, returning empty string.");
        system_logger->error("[ERROR] Redis reply string is null, returning empty string.");
        freeReplyObject(reply);
        return "";
    }

    // 输出调试信息：打印返回的任务结果
    console->info("[DEBUG] Popped result: {}", reply->str);

    // 获取任务结果并释放 Redis 回复对象
    std::string result_data(reply->str);
    freeReplyObject(reply);

    return result_data;
}

