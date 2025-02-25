#include"portScan.h"
#include"../utils/utils.h"
#include<unistd.h>
#include<algorithm>
#include"config.h"


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
        system_logger->error("Failed to close command stream: {}", command);
    }
    else if (status != 0) {
        system_logger->error("Command failed with status {}: {}", status, command);
    }
    return result;
}


std::string performPortScan(const std::string& targetHost, bool allPorts) {
    std::string timeStamp = getCurrentTimestamp();
    std::replace(timeStamp.begin(), timeStamp.end(), ':', '_');
    std::replace(timeStamp.begin(), timeStamp.end(), ' ', '_');

    std::string outputFileName = "output_" + targetHost + "_" + timeStamp + ".xml";
    std::string outputPath = "../../output_nmap/" + outputFileName;
    std::replace(outputFileName.begin(), outputFileName.end(), '/', '_');

    std::string command1 = "";
    // 根据前端的选择决定是否扫描所有端口
    if (allPorts) {
        command1 = "sudo nmap -A -O -p 1-65535 " + targetHost + " -oX " + outputPath;
    }
    else {
        command1 = "sudo nmap -A -O " + targetHost + " -oX " + outputPath;
    }

    std::string command2 = "sudo chown c:c " + outputPath;
    std::string command3 = "sudo chmod 666 " + outputPath;

    system_logger->info("Execute nmap port scan at {}", targetHost);

    try {
        executeCommand(command1);
        executeCommand(command2);
        executeCommand(command3);
    }
    catch (const std::exception& e) {
        system_logger->error("Exception caught: {}", e.what());
        throw;
    }

    if (access(outputPath.c_str(), F_OK) != -1) {
        user_logger->info("File exists after scan: {}", outputPath);
    }
    else {
        system_logger->error("File does not exist after scan: {}", outputPath);
    }

    //console->info("nmap result saved to: {}", outputFileName);

    return outputPath;
}


/*/
extern "C" const char* executePortScan(const char* targetHost) {
    try {
        std::string outputFileName = performPortScan(targetHost);
        return outputFileName.c_str();
    }
    catch (...) {
        std::cerr << "Unknown exception caught." << std::endl;
        return nullptr;
    }

}*/