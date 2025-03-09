#include"log.h"

//����ȫ����־����
std::shared_ptr<spdlog::logger> system_logger;
std::shared_ptr<spdlog::logger> user_logger;
std::shared_ptr<spdlog::logger> console;

// ��ȡ��־·��
std::string get_log_path(const std::string& log_type) {
    fs::path log_dir("logs");
    if (!fs::exists(log_dir)) {
        fs::create_directory(log_dir);
    }
    return (log_dir / (log_type + ".log")).string();
}

//��ʼ����־ϵͳ
void init_logs() {
    try {
        // ���ÿ���̨��־
        console = spdlog::stdout_color_mt("console");
        console->set_pattern("%^[%Y-%m-%d %H:%M:%S] [thread %t] [%l] %v%$");

        // ����ϵͳ��ά��־����ת��־��ÿ���ļ����5MB����ౣ��3���ļ���
        system_logger = spdlog::rotating_logger_mt("system_logger", get_log_path("system"), 1024 * 1024 * 5, 3);
        system_logger->set_pattern("[%Y-%m-%d %H:%M:%S] [thread %t] [%l] %v");

        // �����û����־����ת��־��
        user_logger = spdlog::rotating_logger_mt("user_logger", get_log_path("user"), 1024 * 1024 * 5, 3);
        user_logger->set_pattern("[%Y-%m-%d %H:%M:%S] [thread %t] [%l] %v");

        // ������־����
        spdlog::set_level(spdlog::level::info);

        // ʾ����־
        system_logger->info("System logging initialized.");
        user_logger->info("User activity logging initialized.");
        console->info("Logging initialized.");

        // ȷ����־��ʼ���ɹ�
        if (!system_logger || !user_logger || !console) {
            std::cerr << "Log initialization failed: Unable to create one or more loggers!" << std::endl;
            exit(1);  // �˳�����
        }
    }
    catch (const spdlog::spdlog_ex& ex) {
        std::cerr << "Log initialization failed: " << ex.what() << std::endl;
        exit(1);  // �˳�����
    }
}