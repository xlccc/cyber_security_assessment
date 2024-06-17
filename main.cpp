#include<iostream>
#include<libssh/libssh.h>
#include<vector>
#include"Login.h"
#include"Padding.h"
#include<stdio.h>
#include<string>
#include"database/db.h"
#include"scan/portScan.h"	
#include"utils_scan.h"
#include <cpprest/http_client.h>
#include <cpprest/filestream.h>   // 文件流库
#include <cpprest/json.h>         // JSON 库
#include <iostream>
using namespace utility;          // Common utilities like string conversions
using namespace web;              // Common features like URIs.
using namespace web::http;        // Common HTTP functionality
using namespace web::http::client;// HTTP client features
using namespace concurrency::streams; // Asynchronous streams
using namespace std;

void print_usage() {
    std::cout << "Usage: ./program <cpe_id>" << std::endl;
}

void fetch_and_padding_cves(map<std::string, vector<CVE>> & cpes, int limit = 10) {
    // 替换为实际的 API 基础 URL
    std::string base_url = "http://192.168.29.129:5000/api/cvefor";

    std::string cpe_id = "";
    for (auto& cpe : cpes) {
        cpe_id = cpe.first;
        auto& vecCVE = cpe.second;
        uri_builder builder(U(base_url));

        builder.append_path(U(cpe_id));
        if (limit > 0) {
            builder.append_query(U("limit"), limit);
        }

        // 创建 HTTP 客户端对象
        http_client client(builder.to_uri());

        try {
            client.request(methods::GET)
                .then([&](http_response response) -> pplx::task<json::value> {
                if (response.status_code() == status_codes::OK) {
                    return response.extract_json();
                }
                else {
                    std::cerr << "Failed to fetch CVE data for CPE: " << cpe_id << ", Status code: " << response.status_code() << std::endl;
                    return pplx::task_from_result(json::value());
                }
                    })
                .then([&](json::value jsonObject) {
                        if (!jsonObject.is_null()) {
                            auto cve_array = jsonObject.as_array();
                            for (auto& cve : cve_array) {
                                CVE tmp;
                                tmp.CVE_id = cve[U("id")].as_string();
                                std::cout << "CVE ID: " << cve[U("id")].as_string() << std::endl;
                                std::string cvss_str = "N/A";
                                if (cve.has_field(U("cvss"))) {
                                    auto cvss_value = cve[U("cvss")];
                                    if (cvss_value.is_string()) {
                                        cvss_str = cvss_value.as_string();
                                        std::cout << "CVSS Score: " << cvss_value.as_string() << std::endl;
                                    }
                                    else if (cvss_value.is_number()) {
                                        cvss_str = std::to_string(cvss_value.as_number().to_double());
                                        std::cout << "CVSS Score: " << cvss_value.as_number().to_double() << std::endl;
                                    }
                                    else {
                                        std::cout << "CVSS Score: N/A" << std::endl;
                                    }
                                }
                                else {
                                    std::cout << "CVSS Score: N/A" << std::endl;
                                }
                                tmp.CVSS = cvss_str;
                                if (cve.has_field(U("summary"))) {
                                    
                                    std::cout << "Summary: " << cve[U("summary")].as_string() << std::endl;
                                }
                                vecCVE.push_back(tmp);
                            }
                        }
                    })
                        .wait();
        }
        catch (const std::exception& e) {
            std::cerr << "Exception occurred while fetching CVE data for CPE: " << cpe_id << ", Error: " << e.what() << std::endl;
        }
    }
   
}

//int main() {
//
//    std::string cpe_id = "cpe:/o:linux:linux_kernel:2.6.32";
//    try {
//        fetch_and_print_cves(cpe_id);
//    }
//    catch (const std::exception& e) {
//        std::cerr << "Error: " << e.what() << std::endl;
//        return 1;
//    }
//    ScanHostResult tmp;
//    return 0;
//}

// 将 CVE 转换为 JSON
web::json::value CVE_to_json(const CVE& cve) {
    web::json::value result;
    result[U("CVE_id")] = web::json::value::string(cve.CVE_id);
    result[U("CVSS")] = web::json::value::string(cve.CVSS);
    result[U("pocExist")] = web::json::value::boolean(cve.pocExist);
    result[U("vulExist")] = web::json::value::string(cve.vulExist);
    return result;
}

// 将 ScanResult 转换为 JSON
web::json::value ScanResult_to_json(const ScanResult& scan_result) {
    web::json::value result;
    result[U("portId")] = web::json::value::string(scan_result.portId);
    result[U("protocol")] = web::json::value::string(scan_result.protocol);
    result[U("status")] = web::json::value::string(scan_result.status);
    result[U("service_name")] = web::json::value::string(scan_result.service_name);
    result[U("version")] = web::json::value::string(scan_result.version);

    web::json::value cpes_json = web::json::value::object();
    for (const auto& cpe : scan_result.cpes) {
        web::json::value cves_json = web::json::value::array();
        int index = 0;
        for (const auto& cve : cpe.second) {
            cves_json[index++] = CVE_to_json(cve);
        }
        cpes_json[cpe.first] = cves_json;
    }
    result[U("cpes")] = cpes_json;
    return result;
}

// 将 ScanHostResult 转换为 JSON
web::json::value ScanHostResult_to_json(const ScanHostResult& scan_host_result) {
    web::json::value result;
    result[U("ip")] = web::json::value::string(scan_host_result.ip);

    web::json::value cpes_json = web::json::value::object();
    for (const auto& cpe : scan_host_result.cpes) {
        web::json::value cves_json = web::json::value::array();
        int index = 0;
        for (const auto& cve : cpe.second) {
            cves_json[index++] = CVE_to_json(cve);
        }
        cpes_json[cpe.first] = cves_json;
    }
    result[U("cpes")] = cpes_json;

    web::json::value ports_json = web::json::value::array();
    int index = 0;
    for (const auto& port : scan_host_result.ports) {
        ports_json[index++] = ScanResult_to_json(port);
    }
    result[U("ports")] = ports_json;

    return result;
}
void handle_get(const web::http::http_request& request, const std::vector<ScanHostResult>& scan_host_results) {
    web::json::value result = web::json::value::array();
    int index = 0;
    for (const auto& scan_host_result : scan_host_results) {
        result[index++] = ScanHostResult_to_json(scan_host_result);
    }
    request.reply(web::http::status_codes::OK, result);
}
int main()
{
	//测试SQLite POC数据库
	//POC_db();

	/*char cwd[10000];
	if (getcwd(cwd, sizeof(cwd)) != nullptr) {
		std::cout << "Current working directory: " << cwd << std::endl;
	}
	else {
		std::cerr << "Error getting current working directory" << std::endl;
	}*/

	//测试端口扫描
	std::string outputPath = performPortScan("192.168.29.129");
    cout << outputPath << endl;
    std::vector<ScanHostResult> scan_host_result = parseXmlFile(outputPath);
    
	//std::vector<ScanHostResult> scan_host_result = parseXmlFile("../../output_nmap/output_192.168.29.129_2024-06-01_21_56_41.xml");

    for (auto& scanHostResult : scan_host_result) {
        //操作系统的cpes填充
        //map<std::string, std::vector<CVE>> cpes; 第一个参数是cpe,第二个参数是cpe对应的CVE
        auto& cpes = scanHostResult.cpes;
        fetch_and_padding_cves(cpes);
        auto& ports = scanHostResult.ports;
        for (auto& scanResult : ports) {
            fetch_and_padding_cves(scanResult.cpes);
        }
        
    }
    
 //   ScanHostResult tmp = scan_host_result[0];
	//for (auto& item : tmp.cpes) {
	//	cout << item.first << endl;
	//}

    web::http::experimental::listener::http_listener listener(U("http://192.168.29.129:8080/cveScan"));

    listener.support(web::http::methods::GET, [&scan_host_result](const web::http::http_request& request) {
        handle_get(request, scan_host_result);
        });

    try {
        listener
            .open()
            .then([&listener]() { std::cout << L"Starting to listen at: " << listener.uri().to_string() << std::endl; })
            .wait();

        std::string line;
        std::getline(std::cin, line);
    }
    catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << std::endl;
    }

	std::cout << "wait.." << endl;
	return 0;
}










//std::string exec(const char* cmd) {
//    char buffer[128];
//    std::string result = "";
//    file* pipe = _popen(cmd, "r");
//    if (!pipe) throw std::runtime_error("popen() failed!");
//    try {
//        while (fgets(buffer, sizeof(buffer), pipe) != null) {
//            result += buffer;
//        }
//    }
//    catch (...) {
//        _pclose(pipe);
//        throw;
//    }
//    _pclose(pipe);
//    return result;
//}
//
////测试nmap
//int main() {
//    // 执行nmap扫描命令
//    std::string output = exec("nmap -sv 192.168.117.1");
//
//    // 解析nmap扫描结果
//    // 这里你可以编写代码来提取所需的信息，例如开放端口和服务版本号
//    // 这里只是简单地将nmap的输出打印到控制台
//    std::cout << "nmap scan result:" << std::endl;
//    std::cout << output << std::endl;
//
//    system("pause");
//    return 0;
//}
//
////测试ssh链接+基线检测
////int main(int argc, char** argv)
////{
////    //若以root登录，需配置/etc/ssh/sshd_config中的PermitRootLogin yes
////    ssh_session session = initialize_ssh_session("192.168.117.129", "root", "123456");
////    if (session == NULL)
////    {
////        return -1;
////    }
////    vector<event> Event;
////    fun(Event, session);
////    //cout << Event[0].result << endl;
////    ssh_disconnect(session);
////    ssh_free(session);
////
////
////    system("pause");
////    return 0;
////}
//
