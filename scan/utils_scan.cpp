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



//std::string runPythonScript(const std::string& scriptPath_extension, const std::string& url, const std::string& ip, int port) {
//    std::string result = "";
//
//    // Initialize the Python interpreter
//    Py_Initialize();
//
//    // Set sys.argv for the script
//    //sys.path是Python解释器用来查找模块的搜索路径列表。
//    //执行一个导入语句时，Python会按照sys.path中的路径顺序查找模块。如果没有找到模块，就会抛出ImportError。
//    //脚本尝试进行相对导入，但Python不知道相对导入的父包路径。所以需要确保sys.path包含这些父包路径。
//    PyObject* sys = PyImport_ImportModule("sys");
//    PyObject* sys_path = PyObject_GetAttrString(sys, "path");
//    PyList_Append(sys_path, PyUnicode_FromString("/root/.vs/cyber_seproject/6731b597-df0c-4866-ab56-292bdcaceae0/src/scan/scripts"));
//    PyList_Append(sys_path, PyUnicode_FromString("/root/.vs/cyber_seproject/6731b597-df0c-4866-ab56-292bdcaceae0/src/scan"));
//    PyList_Append(sys_path, PyUnicode_FromString("/root/.vs/cyber_seproject/6731b597-df0c-4866-ab56-292bdcaceae0/src"));
//
//
//    //用于测试：打印sys.path，看是否正确设置了
//    PyObject* path_str = PyObject_Str(sys_path);
//    const char* path_cstr = PyUnicode_AsUTF8(path_str);
//    std::cout << "sys.path: " << path_cstr << std::endl;
//    Py_DECREF(path_str);
//
//    // Import the POC module
//    // 以库的形式加载POC插件
//    std::string scriptPath = removeExtension(scriptPath_extension); //去掉文件名后缀
//
//    PyObject* poc_module = PyImport_ImportModule(scriptPath.c_str());
//    if (!poc_module) {
//        PyErr_Print();
//        std::cerr << "Failed to load script: " << scriptPath << std::endl;
//        Py_Finalize();
//        return result;
//    }
//
//    // Get the check function from the module
//    PyObject* check_func = PyObject_GetAttrString(poc_module, "check");
//    if (!check_func || !PyCallable_Check(check_func)) {
//        PyErr_Print();
//        std::cerr << "Cannot find function 'check' in the script" << std::endl;
//        Py_DECREF(poc_module);
//        Py_Finalize();
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
//    // Finalize the Python interpreter
//    Py_Finalize();
//
//    return result;
//
//}

std::string runPythonScript(const std::string& scriptPath_extension, const std::string& url, const std::string& ip, int port) {
    std::string result = "";

    // Import the POC module
    std::string scriptPath = removeExtension(scriptPath_extension); // 去掉文件名后缀

    PyObject* poc_module = PyImport_ImportModule(scriptPath.c_str());
    if (!poc_module) {
        PyErr_Print();
        std::cerr << "Failed to load script: " << scriptPath << std::endl;
        return result;
    }

    // Get the check function from the module
    PyObject* check_func = PyObject_GetAttrString(poc_module, "check");
    if (!check_func || !PyCallable_Check(check_func)) {
        PyErr_Print();
        std::cerr << "Cannot find function 'check' in the script" << std::endl;
        Py_DECREF(poc_module);
        return result;
    }

    // Prepare arguments for the check function
    PyObject* args = PyTuple_Pack(3, PyUnicode_FromString(url.c_str()), PyUnicode_FromString(ip.c_str()), PyLong_FromLong(port));

    // Call the check function
    PyObject* py_result = PyObject_CallObject(check_func, args);
    Py_DECREF(args);
    Py_DECREF(check_func);
    Py_DECREF(poc_module);

    if (py_result) {
        if (py_result != Py_None) {
            result = PyUnicode_AsUTF8(py_result);
        }
        Py_DECREF(py_result);
    }
    else {
        PyErr_Print();
        std::cerr << "Failed to call function 'check'" << std::endl;
    }

    return result;
}





// 返回完整的回显，和在Linux命令行内的一样
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

    // 获取check函数
    PyObject* check_func = PyObject_GetAttrString(poc_module, "check");
    if (!check_func || !PyCallable_Check(check_func)) {
        PyErr_Print();
        result += "Cannot find function 'check' in the script\n";
        Py_DECREF(poc_module);
        return result;
    }

    // 准备参数并调用check函数
    PyObject* args = PyTuple_Pack(3, PyUnicode_FromString(url.c_str()), PyUnicode_FromString(ip.c_str()), PyLong_FromLong(port));
    PyObject* py_result = PyObject_CallObject(check_func, args);
    Py_DECREF(args);
    Py_DECREF(check_func);
    Py_DECREF(poc_module);

    // 处理check函数的返回值
    if (py_result) {
        if (py_result != Py_None) {
            result += PyUnicode_AsUTF8(py_result);
        }
        else {
            result += "Function 'check' returned None.\n";
        }
        Py_DECREF(py_result);
    }
    else {
        PyErr_Print();
        result += "Failed to call function 'check'\n";
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