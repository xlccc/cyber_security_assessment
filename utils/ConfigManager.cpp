#include "ConfigManager.h"
#include <fstream>
#include <sstream>
#include <stdexcept>

ConfigManager& ConfigManager::getInstance() {
    static ConfigManager instance;
    return instance;
}

void ConfigManager::load(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("ConfigManager: Failed to open config file: " + path);
    }

    try {
        std::stringstream buffer;
        buffer << file.rdbuf();
        root = nlohmann::json::parse(buffer.str());
    }
    catch (const std::exception& e) {
        throw std::runtime_error(std::string("ConfigManager: Failed to parse JSON: ") + e.what());
    }
}

bool ConfigManager::isLoaded() const {
    return !root.is_null();
}

void ConfigManager::ensureLoaded() const {
    if (!isLoaded()) {
        throw std::runtime_error("ConfigManager: Config not loaded. Call load() before accessing values.");
    }
}

std::vector<std::string> ConfigManager::getPythonPaths() const {
    ensureLoaded();
    std::vector<std::string> paths;
    for (const auto& item : root["python"]["paths"]) {
        paths.push_back(item.get<std::string>());
    }
    return paths;
}

std::string ConfigManager::getServerUrl() const {
    ensureLoaded();
    return root["server"]["url"].get<std::string>();
}
std::string ConfigManager::getServerIp() const {
    ensureLoaded();
    return root["server"]["ip"].get<std::string>();
}

std::string ConfigManager::getDbHost() const {
    ensureLoaded();
    return root["database"]["host"].get<std::string>();
}

std::string ConfigManager::getDbUser() const {
    ensureLoaded();
    return root["database"]["user"].get<std::string>();
}

std::string ConfigManager::getDbPassword() const {
    ensureLoaded();
    return root["database"]["password"].get<std::string>();
}

int ConfigManager::getDbPort() const {
    ensureLoaded();
    return root["database"]["port"].get<int>();
}

std::string ConfigManager::getDbSchema() const {
    ensureLoaded();
    return root["database"]["schema"].get<std::string>();
}

std::string ConfigManager::getCveApiBaseUrl() const {
    ensureLoaded();
    return root["cve_api"]["base_url"].get<std::string>();
}

std::string ConfigManager::getPocTempFile() const {
    ensureLoaded();
    return root["poc"]["temp_file"].get<std::string>();
}

std::string ConfigManager::getPocDirectory() const {
    ensureLoaded();
    return root["poc"]["directory"].get<std::string>();
}
std::string ConfigManager::getPocDatabasePath() const {
    ensureLoaded();
    return root["pocDatabase"]["path"].get<std::string>();
}
int ConfigManager::getMaxThreads(int defaultVal) const {
    ensureLoaded();
    return root["scan"].value("max_threads", defaultVal);
}

int ConfigManager::getTaskTimeout(int defaultVal) const {
    ensureLoaded();
    return root["scan"].value("task_timeout", defaultVal);
}

int ConfigManager::getThreadCount(int defaultVal) const {
    ensureLoaded();
    return root["scan"].value("thread_count", defaultVal);
}
