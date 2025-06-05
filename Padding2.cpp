#include"Event.h"
#include"EventChecker.h"
#include"Command_Excute.h"
#include<libssh/libssh.h>
#include"Padding2.h"
void fun2( const string& host, const string& username, const string& password, 
	ConnectionPool& mysqlPool, DatabaseHandler& dbHandler, const vector<int>& ids ) {
	auto start = std::chrono::high_resolution_clock::now();
	try {
        // 创建局部变量，避免使用全局变量
        vector<event> localEvent;

		// 创建ssh连接池 数量为4
		SSHConnectionPool pool(host, username, password, 4);

		// 创建线程池 数量为4
		EventChecker checker(4, pool);

		// 运行检测项
		checker.checkEvents(localEvent,ids);
		for (auto& e : localEvent) {
			dbHandler.saveSecurityCheckResult(host, e, mysqlPool);//tmp_import
		}

	}
	catch (const std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}

	// 获取结束时间（用于测试）
	auto end = std::chrono::high_resolution_clock::now();
	// 计算时间差（以毫秒为单位）
	std::chrono::duration<double, std::milli> elapsed = end - start;
	// 输出时间差
	std::cout << "代码执行时间: " << elapsed.count() << " 毫秒" << std::endl;

}

void level3Fun(const string& host, const string& username, const string& password,
	ConnectionPool& mysqlPool, DatabaseHandler& dbHandler, const vector<int>& ids) {
	auto start = std::chrono::high_resolution_clock::now();
	try {
		// 创建局部变量，避免使用全局变量
		vector<event> localEvent;

		// 创建ssh连接池 数量为4
		SSHConnectionPool pool(host, username, password, 4);

		// 创建线程池 数量为4
		EventChecker checker(4, pool);

		// 运行检测项
		checker.checkLevel3Events(localEvent, ids);
		for (auto& e : localEvent) {
			dbHandler.saveLevel3SecurityCheckResult(host, e, mysqlPool);//
		}

	}
	catch (const std::exception& e) {
		std::cerr << "Error: " << e.what() << std::endl;
	}

	// 获取结束时间（用于测试）
	auto end = std::chrono::high_resolution_clock::now();
	// 计算时间差（以毫秒为单位）
	std::chrono::duration<double, std::milli> elapsed = end - start;
	// 输出时间差
	std::cout << "代码执行时间: " << elapsed.count() << " 毫秒" << std::endl;

}
void ServerInfo_Padding2(ServerInfo& info, const std::string ip, SSHConnectionPool& pool, ConnectionPool& mysqlPool, DatabaseHandler& dbHandler) {
    SSHConnectionGuard guard(pool);
    ssh_session session = guard.get();
    string hostname = "hostname | tr -d \"\\n\"";
    info.hostname = execute_commands(session, hostname);
    string Arch = "arch | tr -d \"\\n\"";
    info.arch = execute_commands(session, Arch);
    string Cpu = "cat /proc/cpuinfo | grep name | sort | uniq | awk -F \":\" '{print $2}' | xargs | tr -d \"\\n\"";
    info.cpu = execute_commands(session, Cpu);
    string CpuPhysical = "cat /proc/cpuinfo | grep \"physical id\" | sort | uniq | wc -l| tr -d \"\\n\"";
    info.cpuPhysical = execute_commands(session, CpuPhysical);
    string CpuCore = "cat /proc/cpuinfo | grep \"core id\" | sort | uniq | wc -l| tr -d \"\\n\"";
    info.cpuCore = execute_commands(session, CpuCore);

    // 获取操作系统名称
    string osName = "cat /etc/os-release | grep \"PRETTY_NAME\" | cut -d= -f2 | tr -d \"\\n\"";
    info.osName = execute_commands(session, osName);

    string type_os;//Debian还是RPM;
    type_os = execute_commands(session, "command -v apt >/dev/null 2>&1 && echo \"Debian\" || (command -v yum >/dev/null 2>&1 && echo \"RPM\" || echo \"Unknown\")| tr -d \"\\n\"");
    if (type_os == "RPM") {
        string Version = "rpm -q centos-release";
        info.version = execute_commands(session, Version);
    }
    else {
        string Version = "lsb_release -a 2>/dev/null | grep 'Release' | awk '{print $2}'| tr -d \"\\n\"";
        info.version = execute_commands(session, Version);
    }
    string ProductName = "dmidecode -t system | grep 'Product Name' | awk -F \":\" '{print $2}' | xargs| tr -d \"\\n\"";
    info.ProductName = execute_commands(session, ProductName);
    //string free = "free -g | grep Mem | awk '{print $2}'| tr -d \"\\n\"";
    string free = "free | grep Mem | awk '{printf \"%.1f\", $2/1024/1024}' | tr -d \"\\n\"";
    info.free = execute_commands(session, free) + " GB";
    std::cout << info.free << endl;
    // 获取完信息后，调用数据库插入函数
    dbHandler.insertServerInfo(info, ip, mysqlPool);
}
