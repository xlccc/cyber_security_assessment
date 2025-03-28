#pragma once

#include <string>
#include <vector>
#include <nlohmann/json.hpp>

class ConfigManager {
public:
    static ConfigManager& getInstance();

    void load(const std::string& path);
    bool isLoaded() const;

    // Python
    std::vector<std::string> getPythonPaths() const;

    // Server
    std::string getServerUrl() const;

    // Database
    std::string getDbHost() const;
    std::string getDbUser() const;
    std::string getDbPassword() const;
    int getDbPort() const;
    std::string getDbSchema() const;

    // CVE API
    std::string getCveApiBaseUrl() const;

    // POC
    std::string getPocTempFile() const;
    std::string getPocDirectory() const;
    std::string getPocDatabasePath() const;

    // Scan
    int getMaxThreads(int defaultVal = 20) const;
    int getTaskTimeout(int defaultVal = 5) const;
    int getThreadCount(int defaultVal = 4) const;

private:
    ConfigManager() = default;
    nlohmann::json root;

    void ensureLoaded() const;
};
