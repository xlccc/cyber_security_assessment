#include"portScan.h"
#include"../utils/utils.h"
#include<unistd.h>
#include<algorithm>



std::string executeCommand(const std::string& command) {
    std::string result;
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    int status = pclose(pipe);
    if (status == -1) {
        std::cerr << "Failed to close command stream: " << command << std::endl;
    }
    else if (status != 0) {
        std::cerr << "Command failed with status " << status << ": " << command << std::endl;
    }
    return result;
}


std::string performPortScan(const std::string& targetHost) {

    std::string timeStamp = getCurrentTimestamp();
    // 替换冒号、空格为下划线
    std::replace(timeStamp.begin(), timeStamp.end(), ':', '_');
    std::replace(timeStamp.begin(), timeStamp.end(), ' ', '_');
    

    std::cout << timeStamp << std::endl;

    std::string outputFileName = "output_" + targetHost + "_" + timeStamp + ".xml";
    //输出到/home/c/projects/nmap_output
    std::string outputPath = "../../output_nmap/" + outputFileName;

    //替换斜杠为下划线
    std::replace(outputFileName.begin(), outputFileName.end(), '/', '_');

    std::string command1 = "sudo nmap -A -O " + targetHost + " -oX " + outputPath;
    std::string command2 = "sudo chown root:root " + outputPath;
    std::string command3 = "sudo chmod 666 " + outputPath;
    

    std::cout << "Execute nmap port scan at " + targetHost << std::endl;

    try {
        executeCommand(command1);
        executeCommand(command2);
        executeCommand(command3);
    }
    catch (const std::exception& e) {
        std::cerr << "Exception caught: " << e.what() << std::endl;
        throw;
    }

    // 检查文件是否存在
    if (access(outputPath.c_str(), F_OK) != -1) {
        std::cout << "File exists after scan: " << outputPath << std::endl;
    }
    else {
        std::cerr << "File does not exist after scan: " << outputPath << std::endl;
    }

    std::cout << "nmap result saved to: " + outputFileName << std::endl;

    return outputPath;
}

extern "C" const char* executePortScan(const char* targetHost) {
    try {
        std::string outputFileName = performPortScan(targetHost);
        return outputFileName.c_str();
    }
    catch (...) {
        std::cerr << "Unknown exception caught." << std::endl;
        return nullptr;
    }
}