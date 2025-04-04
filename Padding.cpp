#include"Event.h"
#include"Command_Excute.h"
#include<libssh/libssh.h>
#include"Padding.h"
void fun(vector<event>& Event, ssh_session session) {
	string type_os;//Debian还是RPM;
	type_os = execute_commands(session, "command -v apt >/dev/null 2>&1 && echo \"Debian\" || (command -v yum >/dev/null 2>&1 && echo \"RPM\" || echo \"Unknown\")");
	// 查找最后一个不是换行符(\n)的字符
	size_t pos = type_os.find_last_not_of('\n');
	if (pos != string::npos) {
		// 从开头到最后一个非换行符的字符复制字符串
		type_os = type_os.substr(0, pos + 1);
	}
	else {
		// 如果没有找到，说明没有换行符，直接复制原始字符串
		type_os = type_os;
	}

	string command_Iscomply;//执行这个命令后返回true或者false

	//备用命令和结果
	string command_result2;
	string command_result3;
	int num1;
	int num2;



	//2.1检查口令生存周期
	event password_lifetime;
	password_lifetime.description = "检查口令生存周期";
	password_lifetime.basis = "<=90";
	password_lifetime.command = "cat /etc/login.defs | grep PASS_MAX_DAYS | grep -v ^# | awk '{print $2}' ";
	password_lifetime.result = execute_commands(session, password_lifetime.command);
	password_lifetime.recommend = "口令生存周期为不大于3个月的时间";
	password_lifetime.importantLevel = "3";
	pos = password_lifetime.result.find_last_not_of('\n');
	if (pos != string::npos) {
		
		// 从开头到最后一个非换行符的字符复制字符串
		password_lifetime.result = password_lifetime.result.substr(0, pos + 1);
	}
	else {
		// 如果没有找到，说明没有换行符，直接复制原始字符串
		password_lifetime.result = password_lifetime.result;
	}

	//将生存周期转为Int来比较
	int num = atoi(password_lifetime.result.c_str());
	if (password_lifetime.result.compare(""))
	{
		if (num <= 90)
		{
			password_lifetime.IsComply = "true";
		}
		else {
			password_lifetime.IsComply = "false";
		}

	}
	else
	{
		password_lifetime.result = "未开启";
		password_lifetime.recommend = "开启口令生存周期要求";
	}


	Event.push_back(password_lifetime);

	//2.2检查口令最小长度
	event password_min_length;
	password_min_length.description = "检查口令最小长度";
	password_min_length.basis = ">=8";
	password_min_length.command = "cat /etc/login.defs | grep PASS_MIN_LEN | grep -v ^# | awk '{print $2}' ";
	password_min_length.result = execute_commands(session, password_min_length.command);
	password_min_length.recommend = "口令最小长度不小于8";
	password_min_length.importantLevel = "3";
	num = atoi(password_min_length.result.c_str());
	if (password_min_length.result.compare(""))
	{
		if (num >= 8)
		{
			password_lifetime.IsComply = "true";

		}
		else {
			password_lifetime.IsComply = "false";
		}
	}
	else
	{
		password_min_length.result = "未开启";
		password_min_length.recommend = "开启口令最小长度要求";
	}

	Event.push_back(password_min_length);

	//2.3检查口令过期前警告天数
	event password_warn_days;
	password_warn_days.description = "检查口令过期前警告天数";
	password_warn_days.basis = ">=30";
	password_warn_days.command = "cat /etc/login.defs | grep PASS_WARN_AGE | grep -v ^#| awk '{print $2}' ";
	password_warn_days.result = execute_commands(session, password_min_length.command);
	password_warn_days.recommend = "口令过期前应至少提前30天警告";
	password_warn_days.importantLevel = "3";
	num = atoi(password_warn_days.result.c_str());
	if (password_warn_days.result.compare(""))
	{
		if (num >= 8)
		{
			password_warn_days.IsComply = "true";
		}
		else {
			password_warn_days.IsComply = "false";
		}

	}
	else
	{
		password_warn_days.result = "未开启";
		password_warn_days.recommend = "开启口令过期前警告天数要求";
	}

	Event.push_back(password_warn_days);

	//2.4检查设备密码复杂度策略
	event password_complex;

	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	string fileIsExist;
	bool findFile = false;

	password_complex.description = "检查设备密码复杂度策略";
	password_complex.basis = "至少包含1个大写字母、1个小写字母、1个数字、1个特殊字符";
	password_complex.recommend = "密码至少包含1个大写字母、1个小写字母、1个数字、1个特殊字符";
	password_complex.importantLevel = "3";
	//此部分要求不一，检查/etc/pam.d/system-auth和/etc/security/pwquality.conf
	//先检查/etc/pam.d/system-auth
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "cat /etc/pam.d/system-auth 2>&1 | grep cat: ";
	fileIsExist = execute_commands(session, fileIsExist);

	if (fileIsExist.compare("") == 0)
	{
		findFile = true;

		//password_complex.command = "cat /etc/pam.d/system-auth | grep password | grep requisite";

		//dcredit数字字符个数，ucredit大写字符个数，ocredit特殊字符个数，lcredit小写字符个数
		string dcredit = "cat /etc/pam.d/system-auth | grep password | grep requisite | grep -v ^# |awk -F 'dcredit=' '{print $2}' | awk -F ' ' '{print $1}' | tr -d '\n'";
		string ucredit = "cat /etc/pam.d/system-auth | grep password | grep requisite | grep -v ^# |awk -F 'ucredit=' '{print $2}' | awk -F ' ' '{print $1}' | tr -d '\n'";
		string ocredit = "cat /etc/pam.d/system-auth | grep password | grep requisite | grep -v ^# |awk -F 'ocredit=' '{print $2}' | awk -F ' ' '{print $1}' | tr -d '\n'";
		string lcredit = "cat /etc/pam.d/system-auth | grep password | grep requisite | grep -v ^# |awk -F 'lcredit=' '{print $2}' | awk -F ' ' '{print $1}' | tr -d '\n'";

		dcredit = execute_commands(session, dcredit);
		ucredit = execute_commands(session, ucredit);
		ocredit = execute_commands(session, ocredit);
		lcredit = execute_commands(session, lcredit);
		//password_complex.result = execute_commands(session, password_complex.command);
		if (dcredit.compare("") && ucredit.compare("") && ocredit.compare("") && lcredit.compare(""))
		{
			int num1 = atoi(dcredit.c_str());
			int num2 = atoi(ucredit.c_str());
			int num3 = atoi(ocredit.c_str());
			int num4 = atoi(lcredit.c_str());
			if (num1 <= -1 && num2 <= -1 && num3 <= -1 && num4 <= -1)
			{
				password_complex.IsComply = "true";
			}
			else
			{
				password_complex.recommend = "密码复杂度提高，至少包含1个大写字母、1个小写字母、1个数字、1个特殊字符";
			}
		}
		else
		{
			password_complex.result = "未全部开启";
			password_complex.recommend = "开启检查密码复杂度要求，至少包含1个大写字母、1个小写字母、1个数字、1个特殊字符";
		}
	}

	//检查/etc/security/pwquality.conf
	//minlen为密码字符串长度，minclass为字符类别
	if (!findFile)
	{
		fileIsExist = "cat /etc/security/pwquality.conf 2>&1 | grep cat: ";
		fileIsExist = execute_commands(session, fileIsExist);

		if (fileIsExist.compare("") == 0)
		{
			findFile = true;

			password_complex.command = "cat /etc/security/pwquality.conf | grep minclass | grep -v ^# | awk -F ' = ' '{print $2}' | tr -d '\n'";
			password_complex.result = execute_commands(session, password_complex.command);

			if (password_complex.result.compare(""))
			{
				num = atoi(password_complex.result.c_str());
				if (num >= 4)
				{
					password_complex.IsComply = "true";
				}
			}
			else
			{
				password_complex.result = "未开启";
				password_complex.recommend = "开启检查密码复杂度要求，至少包含1个大写字母、1个小写字母、1个数字、1个特殊字符";
			}
		}

	}

	if (!findFile)
	{
		//password_complex.result = "未找到配置文件 'system-auth' 或者 'pwquality.conf'";
		password_complex.result = "未找到配置文件";
	}

	Event.push_back(password_complex);



	//2.5检查是否存在空口令账号
	event password_empty;
	password_empty.importantLevel = "3";
	password_empty.description = "检查是否存在空口令账号";
	password_empty.basis = "不存在空口令账号";
	//" "内要加"时需要转义：\"
	password_empty.command = "cat /etc/shadow | awk -F: '($2 == \"\" ) '";
	//password_empty.command = "cat /etc/shadow";
	password_empty.result = execute_commands(session, password_empty.command);
	password_empty.recommend = "空口令会让攻击者不需要口令进入系统，存在较大风险。应删除空口令账号或者为其添加口令";

	if (password_empty.result.compare("") == 0)
	{
		password_empty.IsComply = "true";
	}
	//cout << password_empty.IsComply << endl;

	Event.push_back(password_empty);

	//2.6检查是否设置除root之外UID为0的用户
	event uid0_except_root;
	uid0_except_root.description = "检查是否设置除root之外UID为0的用户";
	uid0_except_root.basis = "普通用户的UID全为非0";
	uid0_except_root.command = "cat /etc/passwd | awk -F: '($3 == 0 ){ print $1 }'| grep -v '^root'";

	uid0_except_root.result = execute_commands(session, uid0_except_root.command);
	uid0_except_root.recommend = "不可设置除了root之外，第二个具有root权限的账号。root之外的用户其UID应为0。";
	uid0_except_root.importantLevel = "2";
	if (uid0_except_root.result.compare("") == 0)
	{
		uid0_except_root.IsComply = "true";
	}

	//cout << uid0_except_root.IsComply << endl;

	Event.push_back(uid0_except_root);

	//3认证授权

	//3.1 检查用户umask设置、分别从/etc/csh.cshrc、/etc/bashrc、/etc/profile检查
	//3.1.1检查/etc/csh.cshrc文件中umask设置(未测试！)
	event umask_cshrc;
	umask_cshrc.description = "检查/etc/csh.cshrc中的用户umask设置";
	umask_cshrc.basis = "=027 或 =077";
	umask_cshrc.recommend = "用户权限要求不严格可设置为027，严格可设置为077";
	umask_cshrc.importantLevel = "2";
	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "cat /etc/csh.cshrc 2>&1 | grep cat: ";
	fileIsExist = execute_commands(session, fileIsExist);
	findFile = false;

	if (fileIsExist.compare("") == 0)
	{
		findFile = true;

		//旧版：多个输出的情况不适用
		//umask_cshrc.command = "cat /etc/csh.cshrc | grep umask | /bin/awk -F 'umask' '{print $2}' | tr -d ' ' | tr -d '\n'";
		//umask_cshrc.result = execute_commands(session, umask_cshrc.command);

		umask_cshrc.command = R"(/bin/awk '!/^\s*#/ && /^\s*umask/ {print $2}' /etc/csh.cshrc)";
		std::string result_raw = execute_commands(session, umask_cshrc.command);
		umask_cshrc.result = result_raw;

		if (!result_raw.empty())
		{
			std::istringstream iss(result_raw);
			std::string line;
			bool all_good = true;
			std::vector<std::string> umask_values;

			while (std::getline(iss, line))
			{
				// 清除空格
				line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());

				if (!line.empty())
				{
					umask_values.push_back(line);

					if (line != "027" && line != "077")
					{
						all_good = false;
					}
				}
			}

			// 格式化为 “027或077” 形式
			if (!umask_values.empty())
			{
				umask_cshrc.result = umask_values[0];
				for (size_t i = 1; i < umask_values.size(); ++i)
				{
					umask_cshrc.result += "或" + umask_values[i];
				}
			}
			else
			{
				umask_cshrc.result = "未设置";
				all_good = false;
			}

			umask_cshrc.IsComply = all_good ? "true" : "false";
		}
		else
		{
			umask_cshrc.result = "未开启";
			umask_cshrc.recommend = "开启 /etc/csh.cshrc 中的用户 umask 设置，且 umask 应为027或者077";
			umask_cshrc.IsComply = "false";
		}
	}
	else
	{
		umask_cshrc.result = "未找到配置文件";
	}

	Event.push_back(umask_cshrc);

	//3.1.2检查/etc/bashrc文件中umask设置（未测试！）
	event umask_bashrc;
	umask_bashrc.description = "检查/etc/bashrc中的用户umask设置";
	umask_bashrc.basis = "=027 或 =077";
	umask_bashrc.recommend = "用户权限要求不严格可设置为027，严格可设置为077";
	umask_bashrc.importantLevel = "2";
	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "cat /etc/bashrc 2>&1 | grep cat: ";
	fileIsExist = execute_commands(session, fileIsExist);
	findFile = false;

	if (fileIsExist.compare("") == 0)
	{
		findFile = true;

		//旧版:有的情况不适用
		// umask_bashrc.command = "/bin/cat /etc/bashrc | grep umask | /bin/awk -F 'umask' '{print $2}' | tr -d ' ' | tr -d '\n'";
		umask_bashrc.command = R"(/bin/awk '!/^\s*#/ && /^\s*umask/ {print $2}' /etc/bashrc)";
		std::string result_raw = execute_commands(session, umask_bashrc.command);
		umask_bashrc.result = result_raw;

		//旧版:有的情况不适用
		//if (umask_bashrc.result.compare(""))
		//{
		//	if (umask_bashrc.result.compare("077") || umask_bashrc.result.compare("027"))
		//	{
		//		umask_bashrc.IsComply = "true";
		//	}
		//}
		if (!result_raw.empty())
		{
			std::istringstream iss(result_raw);
			std::string line;
			bool all_good = true;
			std::vector<std::string> umask_values;

			while (std::getline(iss, line))
			{
				// 清理空格、换行等
				line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());

				if (!line.empty())
				{
					umask_values.push_back(line);

					if (line != "027" && line != "077")
					{
						all_good = false;
					}
				}
			}

			// 拼接结果为 "027或077" 的形式
			if (!umask_values.empty())
			{
				umask_bashrc.result = umask_values[0];
				for (size_t i = 1; i < umask_values.size(); ++i)
				{
					umask_bashrc.result += "或" + umask_values[i];
				}
			}
			else
			{
				umask_bashrc.result = "未设置";
				all_good = false;
			}

			umask_bashrc.IsComply = all_good ? "true" : "false";
		}
		else
		{
			umask_bashrc.result = "未开启";
			umask_bashrc.recommend = "开启/etc/bashrc中的用户umask设置，且umask应为027或者077";
		}
	}

	if (!findFile)
	{
		umask_bashrc.result = "未找到配置文件";
	}

	Event.push_back(umask_bashrc);

	//3.1.3检查/etc/profile文件中umask设置
	event umask_profile;
	umask_profile.description = "检查/etc/profile中的用户umask设置";
	umask_profile.basis = "=027 或 =077";
	umask_profile.recommend = "用户权限要求不严格可设置为027，严格可设置为077";
	umask_profile.importantLevel = "2";
	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "cat /etc/profile 2>&1 | grep cat: ";
	fileIsExist = execute_commands(session, fileIsExist);
	findFile = false;

	if (fileIsExist.compare("") == 0)
	{
		findFile = true;

		//旧版：多种情况不适用
		//umask_profile.command = "/bin/cat /etc/profile| grep umask | /bin/awk -F 'umask' '{print $2}' | tr -d ' ' | tr -d '\n'";
		//umask_profile.result = execute_commands(session, umask_profile.command);

		//if (umask_profile.result.compare(""))
		//{
		//	if (umask_profile.result.compare("077") || umask_profile.result.compare("027"))
		//	{
		//		umask_profile.IsComply = "true";
		//	}
		//}
		//else
		//{
		//	umask_profile.result = "未开启";
		//	umask_profile.recommend = "开启/etc/profile中的用户umask设置，且umask应为027或者077";
		//}

		umask_profile.command = R"(/bin/awk '!/^\s*#/ && /^\s*umask/ {print $2}' /etc/profile)";
		std::string result_raw = execute_commands(session, umask_profile.command);
		umask_profile.result = result_raw;

		if (!result_raw.empty())
		{
			std::istringstream iss(result_raw);
			std::string line;
			bool all_good = true;
			std::vector<std::string> umask_values;

			while (std::getline(iss, line))
			{
				// 去掉空格
				line.erase(std::remove_if(line.begin(), line.end(), ::isspace), line.end());

				if (!line.empty())
				{
					umask_values.push_back(line);

					if (line != "027" && line != "077")
					{
						all_good = false;
					}
				}
			}

			// 拼接结果为 "027或077"
			if (!umask_values.empty())
			{
				umask_profile.result = umask_values[0];
				for (size_t i = 1; i < umask_values.size(); ++i)
				{
					umask_profile.result += "或" + umask_values[i];
				}
			}
			else
			{
				umask_profile.result = "未设置";
				all_good = false;
			}

			umask_profile.IsComply = all_good ? "true" : "false";
		}
		else
		{
			umask_profile.result = "未开启";
			umask_profile.recommend = "开启 /etc/profile 中的用户 umask 设置，且 umask 应为027或者077";
			umask_profile.IsComply = "false";
		}
	}

	if (!findFile)
	{
		umask_profile.result = "未找到配置文件";
	}

	Event.push_back(umask_profile);

	//3.2检查重要目录或文件权限设置
	//3.2.1检查/etc/xinetd.conf文件权限
	event mod_xinetd; 
	mod_xinetd.description = "检查/etc/xinetd.conf文件权限";
	mod_xinetd.basis = "<=600";
	mod_xinetd.recommend = "/etc/xinted.conf的权限应该小于等于600";
	mod_xinetd.importantLevel = "2";
	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "stat -c %a /etc/xineted.conf 2>&1 | grep stat: ";
	fileIsExist = execute_commands(session, fileIsExist);

	if (fileIsExist.compare("") == 0)
	{

		mod_xinetd.command = "stat -c %a /etc/xineted.conf | tr -d ' ' | tr -d '\n'";
		mod_xinetd.result = execute_commands(session, mod_xinetd.command);

		num = atoi(mod_xinetd.result.c_str());

		if (num <= 600)
		{

			mod_xinetd.IsComply = "true";

		}
	}
	else
	{
		mod_xinetd.result = "未找到配置文件";
	}

	Event.push_back(mod_xinetd);

	//3.2.2检查/etc/group文件权限
	event mod_group;
	mod_group.description = "检查/etc/group文件权限";
	mod_group.basis = "<=644";
	mod_group.recommend = "/etc/group的权限应该小于等于644";
	mod_group.importantLevel = "2";
	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "stat -c %a /etc/group 2>&1 | grep stat: ";
	fileIsExist = execute_commands(session, fileIsExist);

	if (fileIsExist.compare("") == 0)
	{

		mod_group.command = "stat -c %a /etc/group | tr -d ' ' | tr -d '\n'";
		mod_group.result = execute_commands(session, mod_group.command);

		num = atoi(mod_group.result.c_str());

		if (num <= 644)
		{

			mod_group.IsComply = "true";

		}
	}
	else
	{
		mod_group.result = "未找到配置文件";
	}

	Event.push_back(mod_group);

	//3.2.3检查/etc/shadow文件权限
	event mod_shadow;
	mod_shadow.description = "检查/etc/shadow文件权限";
	mod_shadow.basis = "<=400";
	mod_shadow.recommend = "/etc/shadow的权限应该小于等于400";
	mod_shadow.importantLevel = "2";
	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "stat -c %a /etc/shadow 2>&1 | grep stat: ";
	fileIsExist = execute_commands(session, fileIsExist);

	if (fileIsExist.compare("") == 0)
	{

		mod_shadow.command = "stat -c %a /etc/shadow | tr -d ' ' | tr -d '\n'";
		mod_shadow.result = execute_commands(session, mod_shadow.command);

		num = atoi(mod_shadow.result.c_str());

		if (num <= 400)
		{

			mod_shadow.IsComply = "true";

		}
	}
	else
	{
		mod_shadow.result = "未找到配置文件";
	}

	Event.push_back(mod_shadow);

	//3.2.4检查/etc/services文件权限
	event mod_services;
	mod_services.description = "检查/etc/services文件权限";
	mod_services.basis = "<=644";
	mod_services.recommend = "/etc/services的权限应该小于等于644";
	mod_services.importantLevel = "2";
	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "stat -c %a /etc/services 2>&1 | grep stat: ";
	fileIsExist = execute_commands(session, fileIsExist);

	if (fileIsExist.compare("") == 0)
	{

		mod_services.command = "stat -c %a /etc/services | tr -d ' ' | tr -d '\n'";
		mod_services.result = execute_commands(session, mod_services.command);

		num = atoi(mod_services.result.c_str());

		if (num <= 644)
		{

			mod_services.IsComply = "true";

		}
	}
	else
	{
		mod_services.result = "未找到配置文件";
	}

	Event.push_back(mod_services);

	//3.2.5检查/etc/security目录权限
	event mod_security;
	mod_security.description = "检查/etc/security目录权限";
	mod_security.basis = "<=600";
	mod_security.recommend = "/etc/security的权限应该小于等于600";
	mod_security.importantLevel = "2";
	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "stat -c %a /etc/security 2>&1 | grep stat: ";
	fileIsExist = execute_commands(session, fileIsExist);

	if (fileIsExist.compare("") == 0)
	{

		mod_security.command = "stat -c %a /etc/security | tr -d ' ' | tr -d '\n'";
		mod_security.result = execute_commands(session, mod_security.command);

		num = atoi(mod_security.result.c_str());

		if (num <= 600)
		{

			mod_security.IsComply = "true";

		}
	}
	else
	{
		mod_security.result = "未找到配置文件";
	}

	Event.push_back(mod_security);

	//3.2.6检查/etc/passwd文件权限
	event mod_passwd;
	mod_passwd.description = "检查/etc/passwd文件权限";
	mod_passwd.basis = "<=644";
	mod_passwd.recommend = "/etc/passwd的权限应该小于等于644";
	mod_passwd.importantLevel = "2";
	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "stat -c %a /etc/passwd 2>&1 | grep stat: ";
	fileIsExist = execute_commands(session, fileIsExist);

	if (fileIsExist.compare("") == 0)
	{

		mod_passwd.command = "stat -c %a /etc/passwd | tr -d ' ' | tr -d '\n'";
		mod_passwd.result = execute_commands(session, mod_passwd.command);

		num = atoi(mod_passwd.result.c_str());

		if (num <= 644)
		{

			mod_passwd.IsComply = "true";

		}
	}
	else
	{
		mod_passwd.result = "未找到配置文件";
	}

	Event.push_back(mod_passwd);

	//3.2.7检查/etc/rc6.d目录权限
	event mod_rc6;
	mod_rc6.description = "检查/etc/rc6.d目录权限";
	mod_rc6.basis = "<=750";
	mod_rc6.recommend = "/etc/rc6.d的权限应该小于等于750";
	mod_rc6.importantLevel = "2";
	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "stat -c %a /etc/rc6.d 2>&1 | grep stat: ";
	fileIsExist = execute_commands(session, fileIsExist);

	if (fileIsExist.compare("") == 0)
	{

		mod_rc6.command = "stat -c %a /etc/rc6.d | tr -d ' ' | tr -d '\n'";
		mod_rc6.result = execute_commands(session, mod_rc6.command);

		num = atoi(mod_rc6.result.c_str());

		if (num <= 750)
		{

			mod_rc6.IsComply = "true";

		}
	}
	else
	{
		mod_rc6.result = "未找到配置文件";
	}

	Event.push_back(mod_rc6);

	//3.2.8检查/etc/rc0.d目录权限
	event mod_rc0;
	mod_rc0.importantLevel = "2";
	mod_rc0.description = "检查/etc/rc0.d目录权限";
	mod_rc0.basis = "<=750";
	mod_rc0.recommend = "/etc/rc0.d的权限应该小于等于750";

	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "stat -c %a /etc/rc0.d 2>&1 | grep stat: ";
	fileIsExist = execute_commands(session, fileIsExist);

	if (fileIsExist.compare("") == 0)
	{

		mod_rc0.command = "stat -c %a /etc/rc0.d | tr -d ' ' | tr -d '\n'";
		mod_rc0.result = execute_commands(session, mod_rc0.command);

		num = atoi(mod_rc0.result.c_str());

		if (num <= 750)
		{

			mod_rc0.IsComply = "true";

		}
	}
	else
	{
		mod_rc0.result = "未找到配置文件";
	}

	Event.push_back(mod_rc0);

	//3.2.9检查/etc/rc1.d目录权限
	event mod_rc1;
	mod_rc1.importantLevel = "2";
	mod_rc1.description = "检查/etc/rc1.d目录权限";
	mod_rc1.basis = "<=750";
	mod_rc1.recommend = "/etc/rc1.d的权限应该小于等于750";

	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "stat -c %a /etc/rc1.d 2>&1 | grep stat: ";
	fileIsExist = execute_commands(session, fileIsExist);

	if (fileIsExist.compare("") == 0)
	{

		mod_rc1.command = "stat -c %a /etc/rc1.d | tr -d ' ' | tr -d '\n'";
		mod_rc1.result = execute_commands(session, mod_rc1.command);

		num = atoi(mod_rc1.result.c_str());

		if (num <= 750)
		{

			mod_rc1.IsComply = "true";

		}
	}
	else
	{
		mod_rc1.result = "未找到配置文件";
	}

	Event.push_back(mod_rc1);

	//3.2.10检查/etc/rc2.d目录权限
	event mod_rc2;
	mod_rc2.importantLevel = "2";
	mod_rc2.description = "检查/etc/xinetd.conf文件权限";
	mod_rc2.basis = "<=750";
	mod_rc2.recommend = "/etc/rc2.d的权限应该小于等于750";

	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "stat -c %a /etc/rc2.d 2>&1 | grep stat: ";
	fileIsExist = execute_commands(session, fileIsExist);

	if (fileIsExist.compare("") == 0)
	{

		mod_rc2.command = "stat -c %a /etc/rc2.d | tr -d ' ' | tr -d '\n'";
		mod_rc2.result = execute_commands(session, mod_rc2.command);

		num = atoi(mod_rc2.result.c_str());

		if (num <= 750)
		{

			mod_rc2.IsComply = "true";

		}
	}
	else
	{
		mod_rc2.result = "未找到配置文件";
	}

	Event.push_back(mod_rc2);

	//3.2.11检查/etc目录权限
	event mod_etc;
	mod_etc.importantLevel = "2";
	mod_etc.description = "检查/etc目录权限";
	mod_etc.basis = "<=750";
	mod_etc.recommend = "/etc/的权限应该小于等于750";

	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "stat -c %a /etc 2>&1 | grep stat: ";
	fileIsExist = execute_commands(session, fileIsExist);

	if (fileIsExist.compare("") == 0)
	{

		mod_etc.command = "stat -c %a /etc | tr -d ' ' | tr -d '\n'";
		mod_etc.result = execute_commands(session, mod_etc.command);

		num = atoi(mod_etc.result.c_str());

		if (num <= 750)
		{

			mod_etc.IsComply = "true";

		}
	}
	else
	{
		mod_etc.result = "未找到配置文件";
	}

	Event.push_back(mod_etc);

	//3.2.12检查/etc/rc4.d目录权限
	event mod_rc4;
	mod_rc4.importantLevel = "2";
	mod_rc4.description = "检查/etc/rc4.d目录权限";
	mod_rc4.basis = "<=750";
	mod_rc4.recommend = "/etc/rc4.d的权限应该小于等于750";

	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "stat -c %a /etc/rc4.d 2>&1 | grep stat: ";
	fileIsExist = execute_commands(session, fileIsExist);

	if (fileIsExist.compare("") == 0)
	{

		mod_rc4.command = "stat -c %a /etc/rc4.d | tr -d ' ' | tr -d '\n'";
		mod_rc4.result = execute_commands(session, mod_rc4.command);

		num = atoi(mod_rc4.result.c_str());

		if (num <= 750)
		{

			mod_rc4.IsComply = "true";

		}
	}
	else
	{
		mod_rc4.result = "未找到配置文件";
	}

	Event.push_back(mod_rc4);

	//3.2.13检查/etc/rc5.d目录权限
	event mod_rc5;
	mod_rc5.importantLevel = "2";
	mod_rc5.description = "检查/etc/rc5.d目录权限";
	mod_rc5.basis = "<=750";
	mod_rc5.recommend = "/etc/rc5.d的权限应该小于等于750";

	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "stat -c %a /etc/rc5.d 2>&1 | grep stat: ";
	fileIsExist = execute_commands(session, fileIsExist);

	if (fileIsExist.compare("") == 0)
	{

		mod_rc5.command = "stat -c %a /etc/rc5.d | tr -d ' ' | tr -d '\n'";
		mod_rc5.result = execute_commands(session, mod_rc5.command);

		num = atoi(mod_rc5.result.c_str());

		if (num <= 750)
		{

			mod_rc5.IsComply = "true";

		}
	}
	else
	{
		mod_rc5.result = "未找到配置文件";
	}

	Event.push_back(mod_rc5);

	//3.2.14检查/etc/rc3.d目录权限
	event mod_rc3;
	mod_rc3.importantLevel = "2";
	mod_rc3.description = "检查/etc/rc3.d目录权限";
	mod_rc3.basis = "<=750";
	mod_rc3.recommend = "/etc/rc3.d的权限应该小于等于750";

	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "stat -c %a /etc/rc3.d 2>&1 | grep stat: ";
	fileIsExist = execute_commands(session, fileIsExist);

	if (fileIsExist.compare("") == 0)
	{

		mod_rc3.command = "stat -c %a /etc/rc3.d | tr -d ' ' | tr -d '\n'";
		mod_rc3.result = execute_commands(session, mod_rc3.command);

		num = atoi(mod_rc3.result.c_str());

		if (num <= 750)
		{

			mod_rc3.IsComply = "true";

		}
	}
	else
	{
		mod_rc3.result = "未找到配置文件";
	}

	Event.push_back(mod_rc3);

	//3.2.15检查/etc/rc.d/init.d目录权限
	event mod_init;
	mod_init.importantLevel = "2";
	mod_init.description = "检查/etc/rc.d/init.d目录权限";
	mod_init.basis = "<=750";
	mod_init.recommend = "/etc/rc.d/init.d的权限应该小于等于750";

	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "stat -c %a /etc/rc.d/init.d 2>&1 | grep stat: ";
	fileIsExist = execute_commands(session, fileIsExist);

	if (fileIsExist.compare("") == 0)
	{

		mod_init.command = "stat -c %a /etc/rc.d/init.d | tr -d ' ' | tr -d '\n'";
		mod_init.result = execute_commands(session, mod_init.command);

		num = atoi(mod_init.result.c_str());

		if (num <= 750)
		{

			mod_init.IsComply = "true";

		}
	}
	else
	{
		mod_init.result = "未找到配置文件";
	}

	Event.push_back(mod_init);

	//3.2.16检查/tmp目录权限
	event mod_tmp;
	mod_tmp.importantLevel = "2";
	mod_tmp.description = "检查/tmp目录权限";
	mod_tmp.basis = "<=750";
	mod_tmp.recommend = "/tmp的权限应该小于等于750";

	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "stat -c %a /tmp 2>&1 | grep stat: ";
	fileIsExist = execute_commands(session, fileIsExist);

	if (fileIsExist.compare("") == 0)
	{

		mod_tmp.command = "stat -c %a /tmp | tr -d ' ' | tr -d '\n'";
		mod_tmp.result = execute_commands(session, mod_tmp.command);

		num = atoi(mod_tmp.result.c_str());

		if (num <= 750)
		{

			mod_tmp.IsComply = "true";

		}
	}
	else
	{
		mod_tmp.result = "未找到配置文件";
	}

	Event.push_back(mod_tmp);

	//3.2.17检查/etc/grub.conf文件权限
	event mod_grub;
	mod_grub.importantLevel = "2";
	mod_grub.description = "检查/etc/grub.conf文件权限";
	mod_grub.basis = "<=600";
	mod_grub.recommend = "/etc/grub.conf的权限应该小于等于600";

	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "stat -c %a /etc/grub.conf 2>&1 | grep stat: ";
	fileIsExist = execute_commands(session, fileIsExist);

	if (fileIsExist.compare("") == 0)
	{

		mod_grub.command = "stat -c %a /etc/grub.conf | tr -d ' ' | tr -d '\n'";
		mod_grub.result = execute_commands(session, mod_grub.command);

		num = atoi(mod_grub.result.c_str());

		if (num <= 600)
		{

			mod_grub.IsComply = "true";

		}
	}
	else
	{
		mod_grub.result = "未找到配置文件";
	}

	Event.push_back(mod_grub);

	//3.2.18检查/etc/grub/grub.conf文件权限
	event mod_grub_grub;
	mod_grub_grub.importantLevel = "2";
	mod_grub_grub.description = "检查/etc/grub/grub.conf文件权限";
	mod_grub_grub.basis = "<=600";
	mod_grub_grub.recommend = "/etc/grub/grub.conf的权限应该小于等于600";

	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "stat -c %a /etc/grub/grub.conf 2>&1 | grep stat: ";
	fileIsExist = execute_commands(session, fileIsExist);

	if (fileIsExist.compare("") == 0)
	{

		mod_grub_grub.command = "stat -c %a /etc/grub/grub.conf | tr -d ' ' | tr -d '\n'";
		mod_grub_grub.result = execute_commands(session, mod_grub_grub.command);

		num = atoi(mod_grub_grub.result.c_str());

		if (num <= 600)
		{

			mod_grub_grub.IsComply = "true";

		}
	}
	else
	{
		mod_grub_grub.result = "未找到配置文件";
	}

	Event.push_back(mod_grub_grub);

	//3.2.19检查/etc/lilo.conf文件权限

	event mod_lilo;
	mod_lilo.importantLevel = "2";
	mod_lilo.description = "检查/etc/lilo.conf文件权限";
	mod_lilo.basis = "<=600";
	mod_lilo.recommend = "/etc/lilo.conf的权限应该小于等于600";

	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "stat -c %a /etc/lilo.conf 2>&1 | grep stat: ";
	fileIsExist = execute_commands(session, fileIsExist);

	if (fileIsExist.compare("") == 0)
	{

		mod_lilo.command = "stat -c %a /etc/lilo.conf | tr -d ' ' | tr -d '\n'";
		mod_lilo.result = execute_commands(session, mod_lilo.command);

		num = atoi(mod_lilo.result.c_str());

		if (num <= 600)
		{

			mod_lilo.IsComply = "true";

		}
	}
	else
	{
		mod_lilo.result = "未找到配置文件";
	}

	Event.push_back(mod_lilo);

	//3.3检查重要文件属性设置
	//3.3.1检查/etc/passwd的文件属性
	event attribute_passwd;
	attribute_passwd.importantLevel = "2";
	attribute_passwd.description = "检查/etc/passwd的文件属性";
	attribute_passwd.basis = "是否设置了i属性";
	attribute_passwd.recommend = "应设置重要文件为i属性（如：chattr +i /etc/passwd），设定文件不能删除、改名、设定链接关系等";

	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "lsattr /etc/passwd 2>&1 | grep stat: ";
	fileIsExist = execute_commands(session, fileIsExist);

	if (fileIsExist.compare("") == 0)
	{

		attribute_passwd.command = "lsattr /etc/passwd | awk '{ print $1 }' | awk -F- '{print $5}' | tr -d '\n'";
		attribute_passwd.result = execute_commands(session, attribute_passwd.command);

		if (attribute_passwd.result.compare("i") == 0)
		{

			attribute_passwd.IsComply = "true";

		}
	}
	else
	{
		attribute_passwd.result = "未找到配置文件";
	}

	Event.push_back(attribute_passwd);


	//3.3.2检查/etc/shadow的文件属性
	event attribute_shadow;
	attribute_shadow.importantLevel = "2";
	attribute_shadow.description = "检查/etc/shadow的文件属性";
	attribute_shadow.basis = "是否设置了i属性";
	attribute_shadow.recommend = "应设置重要文件为i属性（如：chattr +i /etc/shadow），设定文件不能删除、改名、设定链接关系等";

	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "lsattr /etc/shadow 2>&1 | grep stat: ";
	fileIsExist = execute_commands(session, fileIsExist);

	if (fileIsExist.compare("") == 0)
	{

		attribute_shadow.command = "lsattr /etc/shadow | awk '{ print $1 }' | awk -F- '{print $5}' | tr -d '\n'";
		attribute_shadow.result = execute_commands(session, attribute_shadow.command);

		if (attribute_shadow.result.compare("i") == 0)
		{

			attribute_shadow.IsComply = "true";

		}
	}
	else
	{
		attribute_shadow.result = "未找到配置文件";
	}

	Event.push_back(attribute_shadow);

	//3.3.3检查/etc/group的文件属性
	event attribute_group;
	attribute_group.importantLevel = "2";
	attribute_group.description = "检查/etc/group的文件属性";
	attribute_group.basis = "是否设置了i属性";
	attribute_group.recommend = "应设置重要文件为i属性（如：chattr +i /etc/group），设定文件不能删除、改名、设定链接关系等";

	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "lsattr /etc/group 2>&1 | grep stat: ";
	fileIsExist = execute_commands(session, fileIsExist);

	if (fileIsExist.compare("") == 0)
	{

		attribute_group.command = "lsattr /etc/group | awk '{ print $1 }' | awk -F- '{print $5}' | tr -d '\n'";
		attribute_group.result = execute_commands(session, attribute_group.command);

		if (attribute_group.result.compare("i") == 0)
		{

			attribute_group.IsComply = "true";

		}
	}
	else
	{
		attribute_group.result = "未找到配置文件";
	}

	Event.push_back(attribute_group);

	//3.3.4检查/etc/gshadow的文件属性
	event attribute_gshadow;
	attribute_gshadow.importantLevel = "2";
	attribute_gshadow.description = "检查/etc/gshadow的文件属性";
	attribute_gshadow.basis = "是否设置了i属性";
	attribute_gshadow.recommend = "应设置重要文件为i属性（如：chattr +i /etc/gshadow），设定文件不能删除、改名、设定链接关系等";

	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "lsattr /etc/gshadow 2>&1 | grep stat: ";
	fileIsExist = execute_commands(session, fileIsExist);

	if (fileIsExist.compare("") == 0)
	{

		attribute_gshadow.command = "lsattr /etc/gshadow | awk '{ print $1 }' | awk -F- '{print $5}' | tr -d '\n'";
		attribute_gshadow.result = execute_commands(session, attribute_gshadow.command);

		if (attribute_gshadow.result.compare("i") == 0)
		{

			attribute_gshadow.IsComply = "true";

		}
	}
	else
	{
		attribute_gshadow.result = "未找到配置文件";
	}

	Event.push_back(attribute_gshadow);







	//3.4检查用户目录缺省访问权限设置
	event umask_login;
	umask_login.importantLevel = "3";
	umask_login.description = "检查用户目录缺省访问权限设置";
	umask_login.basis = "=027";
	umask_login.recommend = "文件目录缺省访问权限修改为 027";

	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "cat /etc/login.defs 2>&1 | grep cat: ";
	fileIsExist = execute_commands(session, fileIsExist);
	findFile = false;

	if (fileIsExist.compare("") == 0)
	{
		findFile = true;

		umask_login.command = "cat /etc/login.defs | grep umask | grep -v ^#";
		umask_login.result = execute_commands(session, umask_login.command);

		if (umask_login.result.compare(""))
		{
			umask_login.command = "cat /etc/login.defs | grep umask | grep -v ^# | grep 027";
			command_result2 = "cat /etc/login.defs | grep UMASK | grep -v ^# | grep 027";

			umask_login.result = execute_commands(session, umask_login.command);
			command_result2 = execute_commands(session, command_result2);

			if (umask_login.result.compare("") || command_result2.compare(""))
			{
				umask_login.IsComply = "true";
			}
		}
		else
		{
			umask_login.result = "未开启";
			umask_login.recommend = "开启/etc/login.defs中的umask设置，且文件目录缺省访问权限修改为 027";
		}
	}

	if (!findFile)
	{
		umask_login.result = "未找到配置文件";
	}

	Event.push_back(umask_login);

	//3.5检查是否设置ssh登录前警告Banner
	event ssh_Banner;
	ssh_Banner.importantLevel = "1";
	ssh_Banner.description = "检查是否设置ssh登录前警告Banner";
	ssh_Banner.basis = "/etc/ssh/sshd_config 是否开启 Banner";
	ssh_Banner.recommend = "检查SSH配置文件:/etc/ssh/sshd_config，启用banner或合理设置banner的内容";

	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "cat /etc/ssh/sshd_config 2>&1 | grep cat: ";
	fileIsExist = execute_commands(session, fileIsExist);
	findFile = false;

	if (fileIsExist.compare("") == 0)
	{
		findFile = true;

		ssh_Banner.command = "cat /etc/ssh/sshd_config | grep Banner | awk '{print $2}' | grep -v '^#' | grep -v 'none'";
		ssh_Banner.result = execute_commands(session, ssh_Banner.command);

		if (ssh_Banner.result.compare(""))
		{
			ssh_Banner.IsComply = "true";
		}
		else
		{
			ssh_Banner.result = "未开启";
			ssh_Banner.recommend = "开启/etc/ssh/sshd_config中的Banner设置,合理设置Banner的内容";
		}
	}

	if (!findFile)
	{
		ssh_Banner.result = "未找到配置文件";
	}

	Event.push_back(ssh_Banner);

	//4.1检查是否配置远程日志功能
	//4.1.1 syslog-ng是否配置远程日志功能
	event syslog_ng;
	syslog_ng.description = "检查syslog-ng是否配置远程日志功能";
	syslog_ng.basis = "查找配置文件是否有相应行";
	syslog_ng.command = "grep  '^destination logserver' /etc/syslog-ng/syslog-ng.conf";
	syslog_ng.result = execute_commands(session, syslog_ng.command);
	if (syslog_ng.result == "") {
		syslog_ng.result = "未配置syslog-ng远程日志功能";
		syslog_ng.IsComply = "false";
	}
	else {
		syslog_ng.result = "已配置syslog-ng远程日志功能";
		syslog_ng.IsComply = "true";
	}
	syslog_ng.importantLevel = "1";
	syslog_ng.recommend = "/etc/syslog-ng/syslog-ng.conf中配置远程日志功能";
	Event.push_back(syslog_ng);

	//4.1.2 rsyslog是否配置远程日志功能
	event rsyslog;
	rsyslog.importantLevel = "1";
	rsyslog.description = "rsyslog是否配置远程日志功能";
	rsyslog.basis = "查找配置文件是否有相应行";
	rsyslog.command = "grep '^*.* @' /etc/rsyslog.conf";
	rsyslog.result = execute_commands(session, rsyslog.command);
	if (rsyslog.result == "") {
		rsyslog.result = "未配置ryslog远程日志功能";
		rsyslog.IsComply = "false";
	}
	else {
		rsyslog.result = "已配置ryslog远程日志功能";
		rsyslog.IsComply = "true";
	}
	rsyslog.recommend = "/etc/rsyslog.conf中配置远程日志功能";
	Event.push_back(rsyslog);


	//4.1.3 syslog是否配置远程日志功能
	event syslog;
	syslog.importantLevel = "1";
	syslog.description = "syslog是否配置远程日志功能";
	syslog.basis = "查找配置文件是否有相应行";
	syslog.command = "grep '^*.* @' /etc/syslog.conf";
	syslog.result = execute_commands(session, syslog.command);
	if (syslog.result == "") {
		syslog.result = "未配置syslog远程日志功能";
		syslog.IsComply = "false";
	}
	else {
		syslog.result = "已配置syslog远程日志功能";
		syslog.IsComply = "true";
	}
	syslog.recommend = "syslog配置远程日志功能，/etc/syslog.conf末行添加相关配置";
	Event.push_back(syslog);

	//4.2检查是否配置安全事件日志
	//4.2.1 syslog_ng是否配置安全事件日志
	event  syslog_ng_safe;
	syslog_ng_safe.importantLevel = "1";
	syslog_ng_safe.description = "syslog_ng是否配置安全事件日志";
	syslog_ng_safe.basis = "查找配置文件是否有相应行";
	syslog_ng_safe.command = "grep  \"filter f_msgs\" /etc/syslog-ng/syslog-ng.conf";
	syslog_ng_safe.result = execute_commands(session, syslog_ng_safe.command);
	if (syslog_ng_safe.result == "") {
		syslog_ng_safe.result = "未配置syslog_ng安全事件日志功能";
		syslog_ng_safe.IsComply = "false";
	}
	else {
		syslog_ng_safe.result = "已配置syslog_ng安全事件日志功能";
		syslog_ng_safe.IsComply = "true";
	}
	syslog_ng_safe.recommend = "应配置安全事件日志功能,/etc/syslog-ng/syslog-ng.conf文件中修改";
	Event.push_back(syslog_ng_safe);

	//4.2.2 rsyslog是否配置安全事件日志
	event  rsyslog_safe;
	rsyslog_safe.importantLevel = "1";
	rsyslog_safe.description = "rsyslog_safe是否配置安全事件日志";
	rsyslog_safe.basis = "查找配置文件是否有相应行";
	rsyslog_safe.command = "grep '^\\*\\.err;kern\\.debug;daemon\\.notice /var/adm/messages' /etc/rsyslog.conf";
	rsyslog_safe.result = execute_commands(session, rsyslog_safe.command);
	if (rsyslog_safe.result == "") {
		rsyslog_safe.result = "未配置rsyslog安全事件日志功能";
		rsyslog_safe.IsComply = "false";
	}
	else {
		rsyslog_safe.result = "已配置rsyslog安全事件日志功能";
		rsyslog_safe.IsComply = "true";
	}
	rsyslog_safe.recommend = "应该配置安全事件日志功能,/etc/rsyslog.conf中修改 ";
	Event.push_back(rsyslog_safe);

	//4.2.3 检查syslog是否配置安全事件日志 
	event syslog_safe;
	syslog_safe.importantLevel = "1";
	syslog_safe.description = "rsyslog_safe是否配置安全事件日志";
	syslog_safe.basis = "查找配置文件是否有相应行";
	syslog_safe.command = "grep -E 'auth\\.|authpriv\\.|daemon\\.|kern\\.' /etc/syslog.conf";
	syslog_safe.result = execute_commands(session, rsyslog_safe.command);
	if (syslog_safe.result == "") {
		syslog_safe.result = "未配置rsyslog安全事件日志功能";
		syslog_safe.IsComply = "false";
	}
	else {
		syslog_safe.result = "已配置rsyslog安全事件日志功能";
		syslog_safe.IsComply = "true";
	}
	syslog_safe.recommend = "配置rsyslog安全事件日志功能,/etc/syslog.conf中修改";
	Event.push_back(syslog_safe);

	//4.3检查日志文件是否other用户不可写
	//4.3.1检查/var/log/cron日志文件是否other用户不可写
	event cron;
	cron.importantLevel = "1";
	cron.description = "检查/var/log/cron日志文件是否other用户不可写";
	cron.basis = "ls -l检查";
	cron.command = "ls -l /var/log/cron";
	cron.result = execute_commands(session, cron.command);
	if (cron.result == "") {
		cron.result = "没有这个文件";
	}
	command_Iscomply = "ls -l /var/log/cron | grep -q \".\\{7\\}[^ w]\" && echo -n true || echo -n false";
	cron.IsComply = execute_commands(session, command_Iscomply);

	cron.recommend = "/var/log/cron日志文件other用户不可写";
	Event.push_back(cron);

	//4.3.2检查/var/log/secure日志文件是否other用户不可写";
	event secure;
	secure.importantLevel = "1";
	secure.description = "检查/var/log/secure日志文件是否other用户不可写";
	secure.basis = "ls -l检查";
	secure.command = "ls -l /var/log/secure";
	secure.result = execute_commands(session, secure.command);
	if (secure.result == "") {
		secure.result = "没有这个文件";
	}
	command_Iscomply = "ls -l /var/log/secure | grep -q \".\\{7\\}[^ w]\" && echo -n true || echo -n false";
	secure.IsComply = execute_commands(session, command_Iscomply);
	secure.recommend = "/var/log/secure日志文件other用户不可写";
	Event.push_back(secure);

	//4.3.3 检查/var/log/messages日志文件是否other用户不可写
	event message;
	message.importantLevel = "1";
	message.description = "检查/var/log/messages日志文件是否other用户不可写";
	message.basis = "ls -l检查";
	message.command = "ls -l /var/log/messages";
	message.result = execute_commands(session, message.command);
	if (message.result == "") {
		message.result = "没有这个文件";
	}
	command_Iscomply = "ls -l /var/log/messages | grep -q \".\\{7\\}[^ w]\" && echo -n true || echo -n false";
	message.IsComply = execute_commands(session, command_Iscomply);

	message.recommend = "/var/log/messages日志文件other用户不可写";
	Event.push_back(message);

	//4.3.4 检查/var/log/boot.log日志文件是否other用户不可写

	event boot_log;
	boot_log.importantLevel = "1";
	boot_log.description = "检查/var/log/boot.log日志文件是否other用户不可写";
	boot_log.basis = "ls -l检查";
	boot_log.command = "ls -l /var/log/boot.log";
	boot_log.result = execute_commands(session, boot_log.command);
	if (boot_log.result == "") {
		boot_log.result = "没有这个文件";
	}
	command_Iscomply = "ls -l /var/log/boot.log | grep -q \".\\{7\\}[^ w]\" && echo -n true || echo -n false";
	boot_log.IsComply = execute_commands(session, command_Iscomply);
	boot_log.recommend = "/var/log/boot.log日志文件other用户不可写";
	Event.push_back(boot_log);

	//4.3.5检查/var/log/mail日志文件是否other用户不可写
	event mail;
	mail.importantLevel = "1";
	mail.description = "检查/var/log/mail日志文件是否other用户不可写";
	mail.basis = "ls -l检查";
	mail.command = "ls -l /var/log/mail";
	mail.result = execute_commands(session, boot_log.command);
	if (mail.result == "") {
		mail.result = "没有这个文件";
	}
	command_Iscomply = "ls -l /var/log/mail | grep -q \".\\{7\\}[^ w]\" && echo -n true || echo -n false";
	mail.IsComply = execute_commands(session, command_Iscomply);
	mail.recommend = "/var/log/mail日志文件other用户不可写";
	Event.push_back(mail);

	//4.3.6 检查/var/log/spooler日志文件是否other用户不可写
	event spooler;
	spooler.importantLevel = "1";
	spooler.description = "检查/var/log/spooler日志文件是否other用户不可写";
	spooler.basis = "ls -l检查";
	spooler.command = "ls -l /var/log/spooler";
	spooler.result = execute_commands(session, spooler.command);
	if (spooler.result == "") {
		spooler.result = "没有这个文件";
	}
	command_Iscomply = "ls -l /var/log/spooler | grep -q \".\\{7\\}[^ w]\" && echo -n true || echo -n false";
	spooler.IsComply = execute_commands(session, command_Iscomply);
	spooler.recommend = "/var/log/spooler日志文件other用户不可写";
	Event.push_back(spooler);

	//4.3.7 检查/var/log/localmessages日志文件是否other用户不可写
	event localmessages;
	localmessages.importantLevel = "1";
	localmessages.description = "检查/var/log/localmessages日志文件是否other用户不可写";
	localmessages.basis = "ls -l检查";
	localmessages.command = "ls -l /var/log/localmessages";
	localmessages.result = execute_commands(session, localmessages.command);
	if (localmessages.result == "") {
		localmessages.result = "没有这个文件";
	}
	command_Iscomply = "ls -l /var/log/localmessages | grep -q \".\\{7\\}[^ w]\" && echo -n true || echo -n false";
	localmessages.IsComply = execute_commands(session, command_Iscomply);
	localmessages.recommend = "/var/log/spooler日志文件other用户不可写";
	Event.push_back(localmessages);


	//4.3.8 检查/var/log/maillog日志文件是否other用户不可写
	event maillog;
	maillog.importantLevel = "1";
	maillog.description = "检查/var/log/maillog日志文件是否other用户不可写";
	maillog.basis = "ls -l检查";
	maillog.command = "ls -l /var/log/maillog";
	maillog.result = execute_commands(session, maillog.command);
	if (maillog.result == "") {
		maillog.result = "没有这个文件";
	}
	command_Iscomply = "ls -l /var/log/maillog | grep -q \".\\{7\\}[^ w]\" && echo -n true || echo -n false";
	maillog.IsComply = execute_commands(session, command_Iscomply);
	maillog.recommend = "应/var/log/maillog日志文件other用户不可写";
	Event.push_back(maillog);

	//4.4是否对登录进行日志记录
	event last;
	last.importantLevel = "3";
	last.description = "是否对登录进行日志记录";
	last.basis = "last检查";
	last.command = "last";
	last.result = execute_commands(session, last.command);
	if (last.result == "") {
		last.result = "未对登录进行日志记录";
		last.IsComply = "false";
	}
	else {
		last.result = "已对登录进行日志记录,结果太长，已忽略";
		last.IsComply = "true";
	}
	last.recommend = "要对登录进行日志记录";
	Event.push_back(last);

	//检查是否配置su命令使用情况记录
	event su_log;
	su_log.importantLevel = "1";
	su_log.description = "是否对su命令进行日志记录";
	su_log.basis = "基于Debian或者RPM访问不同的文件";
	if (type_os == "Debian") {
		su_log.command = "grep 'su' /var/log/auth.log";
		su_log.result = execute_commands(session, su_log.command);
	}
	else {
		su_log.command = "grep 'su' /var/log/secure";
		su_log.result = execute_commands(session, su_log.command);
	}
	if (su_log.result == "") {
		su_log.result = "未对登录进行日志记录";
		su_log.IsComply = "false";
	}
	else {
		su_log.result = "已对登录进行日志记录,结果太长，已忽略";
		su_log.IsComply = "true";
	}
	su_log.recommend = "要对登录进行日志记录";
	Event.push_back(su_log);

	//5.1检查系统openssh安全配置

	event openssh_config;
	openssh_config.importantLevel = "2";
	openssh_config.description = "检查系统openssh安全配置";
	openssh_config.basis = "/etc/ssh/sshd_config中的Protocol配置值为2";
	openssh_config.command = "grep - i Protocol / etc / ssh / sshd_config | egrep - v '^\s*#' | awk '{print $2}'";

	openssh_config.result = execute_commands(session, openssh_config.command);
	if (openssh_config.result == "") {
		openssh_config.result = "没有Protocol这一行";
	}
	if (openssh_config.result == "2") {
		openssh_config.IsComply = "true";
	}
	else {
		openssh_config.IsComply = "false";
	}
	openssh_config.recommend = "建议把/etc/ssh/sshd_config中的Protocol配置值为2";
	Event.push_back(openssh_config);

	//5.2检查是否已修改snmp默认团体字
	//5.2.1 检查SNMP服务是否运行


	event running_snmp;
	running_snmp.importantLevel = "2";
	running_snmp.description = "检查SNMP服务是否在运行";
	running_snmp.basis = "查看是否存在SNMP进程";
	running_snmp.command = "ps -ef|grep \"snmpd\"|grep -v \"grep\"";
	running_snmp.result = execute_commands(session, running_snmp.command);
	if (running_snmp.result == "") {
		running_snmp.result = "snmp进程没有运行";
		running_snmp.IsComply = "true";
	}
	else {
		running_snmp.result = "snmp进程正在运行,需要进一步检测";
		running_snmp.IsComply = "false";
	}
	running_snmp.recommend = "无";
	Event.push_back(running_snmp);
	//5.2.2检查是否已修改snmp默认团体字，进程未开启就不用

	event snmp_config;
	snmp_config.importantLevel = "2";
	snmp_config.description = "检查是否已修改snmp默认团体字";
	snmp_config.basis = "检查是否已修改snmp默认团体字";
	snmp_config.command = "cat /etc/snmp/snmpd.conf | grep com2sec  | grep public | grep -v ^#";

	if (running_snmp.IsComply == "true") {
		snmp_config.result = "snmp进程未运行，不用检测修改";
		snmp_config.IsComply = "true";
	}
	else {
		snmp_config.result = execute_commands(session, snmp_config.command);
		if (snmp_config.result == "") {
			snmp_config.result = "已修改snmp默认团体字";
			snmp_config.IsComply = "true";
		}
		else {
			snmp_config.IsComply = "false";
		}

	}
	snmp_config.recommend = "/etc/snmp/snmpd.conf 文件中修改默认团体字";
	Event.push_back(snmp_config);
	//5.3检查使用ip协议远程维护的设备是否配置ssh协议，禁用telnet协议
	//5.3.1是否配置ssh协议
	event ssh_config;

	ssh_config.importantLevel = "3";
	ssh_config.description = "是否配置ssh协议";
	ssh_config.basis = "根据22号端口是否开放检测是否配置ssh协议";
	ssh_config.command = "ss -tuln | grep \":22\"";
	ssh_config.result = execute_commands(session, ssh_config.command);
	if (ssh_config.result == "") {
		ssh_config.result = "未配置ssh协议";
		ssh_config.IsComply = "false";
	}
	else {
		ssh_config.result = "已配置ssh协议";
		ssh_config.IsComply = "true";
	}
	ssh_config.recommend = "需要配置ssh协议即要开启ssh服务";
	Event.push_back(ssh_config);//复制一个临时对象，然后存进去的，所以后面再次修改ssh_config也不会改变Event里面的值
	//5.3.2是否配置telnet协议
	event telnet_config;
	telnet_config.importantLevel = "3";
	telnet_config.description = "由于telnet明文传输，所以应该禁止telnet协议";
	telnet_config.basis = "根据23号端口是否开放检测是否配置telnet协议";
	telnet_config.command = "ss -tuln | grep \":23\"";
	telnet_config.result = execute_commands(session, telnet_config.command);
	if (telnet_config.result == "") {
		telnet_config.result = "未配置telnet协议";
		telnet_config.IsComply = "true";
	}
	else {
		telnet_config.result = "已配置telnet协议";
		telnet_config.IsComply = "false";
	}
	telnet_config.recommend = "应该禁止配置telnet协议";
	Event.push_back(telnet_config);
	//5.4检查是否禁止root用户登录ftp
	//5.4.1检查是否在运行ftp服务
	event running_ftp;
	running_ftp.importantLevel = "2";
	running_ftp.description = "检查是否在运行ftp";
	running_ftp.basis = "判断相应的服务是否后台运行";
	running_ftp.command = "ps -ef | grep ftp | grep -v grep";
	running_ftp.result = execute_commands(session, running_ftp.command);
	if (running_ftp.result == "") {
		running_ftp.result = "ftp服务没有在运行，检测通过";
		running_ftp.IsComply = "true";
	}
	else {
		running_ftp.result = "ftp服务在运行，还要进一步检测配置文件";
		running_ftp.IsComply = "false";
	}
	Event.push_back(running_ftp);

	event ftp_config;
	ftp_config.importantLevel = "2";
	ftp_config.description = "检查是否禁止root用户登录ftp";
	ftp_config.basis = "/etc/vsftpd/ftpusers文件中是否包含root用户";
	ftp_config.command = "grep '^[^#]*root' /etc/vsftpd/ftpusers";
	if (running_ftp.IsComply == "true") {
		ftp_config.result = "ftp未运行，不用判断";
		ftp_config.IsComply = "true";
	}
	else {
		ftp_config.result = execute_commands(session, ftp_config.command);
		if (ftp_config.result == "") {
			ftp_config.IsComply = "false";
		}
		else {
			ftp_config.IsComply = "true";
		}
	}
	ftp_config.recommend = "应该禁止root用户登录ftp";
	Event.push_back(ftp_config);

	//5.5检查是否禁止匿名用户登录FTP
	event anonymous_ftp;
	anonymous_ftp.importantLevel = "3";
	anonymous_ftp.description = "检查是否禁止匿名用户登录FTP";
	anonymous_ftp.basis = "/etc/vsftpd/vsftpd.conf文件中是否存在anonymous_enable=NO配置";
	anonymous_ftp.command = "cat /etc/vsftpd/vsftpd.conf | grep \"anonymous_enable=NO\" | grep -v ^#";
	anonymous_ftp.result = execute_commands(session, anonymous_ftp.command);
	if (anonymous_ftp.result == "") {
		anonymous_ftp.result = "未禁止匿名登录";
		anonymous_ftp.IsComply = "false";
	}
	else {
		anonymous_ftp.IsComply = "true";
	}
	anonymous_ftp.recommend = "禁止匿名用户登录FTP  /etc/vsftpd/vsftpd.conf中检查相关配置";
	Event.push_back(anonymous_ftp);

	//6其他配置操作

	//6.1检查是否设置命令行界面超时退出
	event cmd_timeout;
	cmd_timeout.importantLevel = "3";
	cmd_timeout.description = "检查是否设置命令行界面超时退出";
	cmd_timeout.basis = "<=600";
	cmd_timeout.recommend = "建议命令行界面超时自动登出时间TMOUT应不大于600s，检查项建议系统管理员根据系统情况自行判断";

	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "cat /etc/profile 2>&1 | grep cat: ";
	fileIsExist = execute_commands(session, fileIsExist);
	findFile = false;

	if (fileIsExist.compare("") == 0)
	{
		findFile = true;

		cmd_timeout.command = "cat /etc/profile |grep -i TMOUT | grep -v ^#";
		cmd_timeout.result = execute_commands(session, cmd_timeout.command);

		if (cmd_timeout.result.compare(""))
		{
			cmd_timeout.command = "cat /etc/profile |grep -i TMOUT | grep -v ^# | awk -F '=' '{print $2}' | tr -d ' ' | tr -d '\n'";
			cmd_timeout.result = execute_commands(session, cmd_timeout.command);
			num = atoi(cmd_timeout.result.c_str());
			if (num <= 600 && num >= 0)
			{
				cmd_timeout.IsComply = "true";
			}
		}
		else
		{
			cmd_timeout.result = "未开启";
			cmd_timeout.recommend = "开启/etc/profile中的TMOUT设置，且TMOUT值应不大于600";
		}
	}

	if (!findFile)
	{
		cmd_timeout.result = "未找到配置文件";
	}

	Event.push_back(cmd_timeout);


	//6.2检查是否设置系统引导管理器密码
	event password_bootloader;
	password_bootloader.importantLevel = "1";
	password_bootloader.description = "检查是否设置系统引导管理器密码";
	password_bootloader.basis = "系统引导管理器grub2或grub或lilo是否设置了密码";
	password_bootloader.recommend = "根据引导器不同类型（grub2或grub或lilo），为其设置引导管理器密码。";

	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "cat /boot/grub/menu.lst 2>&1 | grep cat: ";
	command_result2 = "cat /etc/grub.conf 2>&1 | grep cat:";
	command_result3 = "cat /boot/grub/grub.cfg 2>&1 | grep cat:";

	fileIsExist = execute_commands(session, fileIsExist);
	command_result2 = execute_commands(session, command_result2);
	command_result3 = execute_commands(session, command_result3);

	findFile = false;

	if (fileIsExist.compare("") == 0 || command_result2.compare("") == 0 || command_result3.compare("") == 0)
	{
		findFile = true;

		//cout << "系统引导器为grub！" << endl;

		password_bootloader.command = "echo $grub | grep password | tr -d '\n'";
		password_bootloader.result = execute_commands(session, password_bootloader.command);

		if (password_bootloader.result.compare(""))
		{
			password_bootloader.IsComply = "true";
		}

	}

	if (!findFile)
	{
		fileIsExist = "cat /boot/grub2/menu.lst 2>&1 | grep cat: ";
		command_result2 = "cat /etc/grub2.conf 2>&1 | grep cat:";
		command_result3 = "cat /boot/grub2/grub2.cfg 2>&1 | grep cat:";

		fileIsExist = execute_commands(session, fileIsExist);
		command_result2 = execute_commands(session, command_result2);
		command_result3 = execute_commands(session, command_result3);

		if (fileIsExist.compare("") == 0 || command_result2.compare("") == 0 || command_result3.compare("") == 0)
		{
			findFile = true;

			//cout << "系统引导器为grub2！" << endl;

			password_bootloader.command = "echo $grub2 | grep password | tr -d '\n'";
			password_bootloader.result = execute_commands(session, password_bootloader.command);

			if (password_bootloader.result.compare(""))
			{
				password_bootloader.IsComply = "true";
			}

		}

	}

	if (!findFile)
	{
		fileIsExist = "cat /etc/lilo.conf 2>&1 | grep cat: ";
		fileIsExist = execute_commands(session, fileIsExist);

		if (fileIsExist.compare("") == 0)
		{
			findFile = true;

			//cout << "系统引导器为lilo！" << endl;

			password_bootloader.command = "echo $lilo | grep password | tr -d '\n'";
			password_bootloader.result = execute_commands(session, password_bootloader.command);

			if (password_bootloader.result.compare(""))
			{
				password_bootloader.IsComply = "true";
			}

		}

	}

	if (!findFile)
	{
		password_bootloader.result = "未找到配置文件";
	}

	Event.push_back(password_bootloader);






	//6.3检查系统coredump设置
	event core_dump;
	core_dump.importantLevel = "2";
	core_dump.description = "检查系统coredump设置";
	core_dump.basis = "检查/etc/security/limits.conf是否设置* hard core 0 和 * soft core 0";
	core_dump.recommend = "检查系统cire dump设置，防止内存状态信息暴露，设置* soft  core、* hard core为0，且注释掉ulimit -S -c 0 > /dev/null 2>&1";

	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "cat /etc/security/limits.conf 2>&1 | grep cat: ";
	fileIsExist = execute_commands(session, fileIsExist);
	findFile = false;

	if (fileIsExist.compare("") == 0)
	{
		findFile = true;

		core_dump.command = "cat /etc/security/limits.conf | grep soft | grep core | grep 0 | grep ^*";
		command_result2 = "cat /etc/security/limits.conf | grep hard | grep core | grep 0 | grep ^*";

		core_dump.result = execute_commands(session, core_dump.command);
		command_result2 = execute_commands(session, command_result2);

		if (core_dump.result.compare("") && command_result2.compare(""))
		{
			core_dump.IsComply = "true";
		}
		else
		{
			core_dump.result = "未开启";
		}
	}

	if (!findFile)
	{
		core_dump.result = "未找到配置文件";
	}

	Event.push_back(core_dump);

	//6.4检查历史命令设置
	event hist_size;
	hist_size.importantLevel = "1";
	hist_size.description = "检查历史命令设置";
	hist_size.basis = "HISTFILESIZE和HISTSIZE的值应<=5";
	hist_size.recommend = "历史命令文件HISTFILESIZE和HISTSIZE的值应小于等于5";

	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "cat /etc/profile 2>&1 | grep cat: ";
	fileIsExist = execute_commands(session, fileIsExist);
	findFile = false;

	if (fileIsExist.compare("") == 0)
	{
		findFile = true;

		hist_size.command = "cat /etc/profile | grep ^HISTSIZE | egrep -v ^\# | awk -F  '=' '{print $2}' | tr -d ' ' | tr -d '\n'";
		command_result2 = "cat /etc/profile | grep ^HISTFILESIZE | egrep -v ^\# | awk -F '=' '{print $2}' | tr -d ' ' | tr -d '\n'";

		hist_size.result = execute_commands(session, hist_size.command);
		command_result2 = execute_commands(session, command_result2);


		if (hist_size.result.compare("") && command_result2.compare(""))
		{
			num1 = atoi(hist_size.result.c_str());
			num2 = atoi(command_result2.c_str());
			if (num1 <= 5 && num2 <= 5)
			{
				hist_size.IsComply = "true";
			}
		}
		else
		{
			hist_size.result = "未开启";
		}
	}

	if (!findFile)
	{
		hist_size.result = "未找到配置文件";
	}

	Event.push_back(hist_size);

	//6.5检查是否使用PAM认证模块禁止wheel组之外的用户su为root
	event group_wheel;
	group_wheel.importantLevel = "3";
	group_wheel.description = "检查是否使用PAM认证模块禁止wheel组之外的用户su为root";
	group_wheel.basis = "检查/etc/pam.d/su文件中，是否存在如下配置: auth  sufficient pam_rootok.so 和 auth  required pam_wheel.so group=wheel";
	group_wheel.recommend = "禁止wheel组外用户使用su命令，提高操作系统的完整性";

	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "cat /etc/pam.d/su 2>&1 | grep cat: ";
	fileIsExist = execute_commands(session, fileIsExist);
	findFile = false;

	if (fileIsExist.compare("") == 0)
	{
		findFile = true;

		group_wheel.command = "cat /etc/pam.d/su | grep auth | grep sufficient | grep pam_rootok.so | grep -v ^#";
		command_result2 = "cat /etc/pam.d/su | grep auth | grep pam_wheel.so | grep group=wheel | grep -v ^#";

		group_wheel.result = execute_commands(session, group_wheel.command);
		command_result2 = execute_commands(session, command_result2);


		if (group_wheel.result.compare("") && command_result2.compare(""))
		{
			group_wheel.IsComply = "true";
		}
		else
		{
			group_wheel.result = "未开启";
		}
	}

	if (!findFile)
	{
		group_wheel.result = "未找到配置文件";
	}

	Event.push_back(group_wheel);

	//6.6检查是否对系统账户进行登录限制
	event inter_login;
	inter_login.importantLevel = "1";
	inter_login.description = "检查是否对系统账户进行登录限制";
	inter_login.basis = "请手动检查文件文件/etc/passwd，/etc/shadow，并使用命令：usermod -s /sbin/nologin username";
	inter_login.recommend = "对系统账户登录进行限制，禁止账户交互式登录。";
	inter_login.result = "手动检查";

	Event.push_back(inter_login);

	//6.7检查密码重复使用次数限制
	event password_repeatlimit;
	password_repeatlimit.importantLevel = "2";
	password_repeatlimit.description = "检查密码重复使用次数限制";
	password_repeatlimit.basis = ">=5";
	password_repeatlimit.recommend = "检查密码重复使用次数，使用户不能重复使用最近5次（含5次）内已使用的口令，预防密码重复使用被爆破的风险。";

	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "cat /etc/pam.d/system-auth 2>&1 | grep cat: ";
	fileIsExist = execute_commands(session, fileIsExist);
	findFile = false;

	if (fileIsExist.compare("") == 0)
	{
		findFile = true;

		password_repeatlimit.command = "cat /etc/pam.d/system-auth | grep password | grep sufficient | grep pam_unix.so | grep remember | grep -v ^#";
		password_repeatlimit.result = execute_commands(session, password_repeatlimit.command);


		if (password_repeatlimit.result.compare(""))
		{
			password_repeatlimit.command = "cat /etc/pam.d/system-auth | grep password | grep sufficient | grep pam_unix.so | grep remember | grep -v ^# | awk -F 'remember=' '{print $2}' | tr -d '\n'";
			password_repeatlimit.result = execute_commands(session, password_repeatlimit.command);

			num = atoi(password_repeatlimit.result.c_str());
			if (num >= 5)
			{
				password_repeatlimit.IsComply = "true";
			}
		}
		else
		{
			password_repeatlimit.result = "未开启";
		}
	}

	if (!findFile)
	{
		password_repeatlimit.result = "未找到配置文件";
	}

	Event.push_back(password_repeatlimit);

	//6.8检查账户认证失败次数限制
	event auth_failtimes;
	auth_failtimes.importantLevel = "1";
	auth_failtimes.description = "检查账户认证失败次数限制";
	auth_failtimes.basis = "登录失败限制可以使用pam_tally或pam.d，请手工检测/etc/pam.d/system-auth、/etc/pam.d/passwd、/etc/pam.d/common-auth文件。";
	auth_failtimes.recommend = "应配置密码失败次数限制，预防密码被爆破的风险。";
	auth_failtimes.result = "手动检查";

	Event.push_back(auth_failtimes);

	//6.9检查是否关闭绑定多ip功能
	event multi_ip;
	multi_ip.importantLevel = "1";
	multi_ip.description = "检查是否关闭绑定多ip功能";
	multi_ip.basis = "/etc/host.conf中multi的开启状态";
	multi_ip.recommend = "应关闭绑定多ip功能，使系统操作责任到人。";

	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "cat /etc/host.conf 2>&1 | grep cat: ";
	fileIsExist = execute_commands(session, fileIsExist);
	findFile = false;

	if (fileIsExist.compare("") == 0)
	{
		findFile = true;

		multi_ip.command = "cat /etc/host.conf | grep -v ^# | grep multi | grep off";
		multi_ip.result = execute_commands(session, multi_ip.command);


		if (multi_ip.result.compare(""))
		{
			multi_ip.IsComply = "true";
		}
	}

	if (!findFile)
	{
		multi_ip.result = "未找到配置文件";
	}

	Event.push_back(multi_ip);

	//6.10检查是否限制远程登录IP范围
	event login_remote_ip;

	login_remote_ip.importantLevel = "1";
	login_remote_ip.description = "检查是否限制远程登录IP范围";
	login_remote_ip.basis = "请手工查看/etc/hosts.allow和/etc/hosts.deny两个文件";
	login_remote_ip.recommend = "应配置相关设置防止未知ip远程登录，此检查项建议系统管理员根据系统情况自行判断。";
	login_remote_ip.result = "手动检查";

	Event.push_back(login_remote_ip);

	//6.11检查别名文件

	event aliases_unnecessary;
	aliases_unnecessary.importantLevel = "1";
	aliases_unnecessary.description = "检查别名文件";
	aliases_unnecessary.basis = "请手工查看/etc/aliases和/etc/mail/aliases两个文件";
	aliases_unnecessary.recommend = "检查是否禁用不必要的别名，此检查项建议系统管理员根据系统情况自行判断。";
	aliases_unnecessary.result = "手动检查";

	Event.push_back(aliases_unnecessary);


	//6.12检查重要文件是否存在suid和sgid权限
	event Perm_suid_sgid;
	Perm_suid_sgid.importantLevel = "1";
	Perm_suid_sgid.description = "检查重要文件是否存在suid和sgid权限";
	Perm_suid_sgid.basis = "重要文件是否存在suid和sgid权限：/usr/bin/chage /usr/bin/gpasswd /usr/bin/wall /usr/bin/chfn /usr/bin/chsh /usr/bin/newgrp /usr/bin/write /usr/sbin/usernetctl /usr/sbin/traceroute /bin/mount /bin/umount /bin/ping /sbin/netreport";
	Perm_suid_sgid.recommend = "suid管理上有漏洞，易被黑客利用suid来踢拳，来放后门控制linux主机。sgid同样权力过大。对于重要文件建议关闭suid和sgid";


	Perm_suid_sgid.command = "find /usr/bin/chage /usr/bin/gpasswd /usr/bin/wall /usr/bin/chfn /usr/bin/chsh /usr/bin/newgrp /usr/bin/write /usr/sbin/usernetctl /usr/sbin/traceroute /bin/mount /bin/umount /bin/ping /sbin/netreport -type f -perm /6000";
	Perm_suid_sgid.result = execute_commands(session, Perm_suid_sgid.command);


	if (Perm_suid_sgid.result.compare("") == 0)
	{
		Perm_suid_sgid.IsComply = "true";
	}

	Event.push_back(Perm_suid_sgid);

	//6.13检查是否配置定时自动屏幕锁定（适用于图形化界面）
	event screen_autolock;
	screen_autolock.importantLevel = "1";
	screen_autolock.description = "检查是否配置定时自动屏幕锁定（适用于图形化界面）";
	screen_autolock.basis = "在屏幕上面的面板中，打开“系统”-->“首选项”-->“屏幕保护程序”";
	screen_autolock.recommend = "对具有图形化界面的设备应配置定时自动屏幕锁定";
	screen_autolock.result = "手动检查";

	Event.push_back(screen_autolock);

	//6.14检查系统内核参数配置（可能不全）
	event tcp_syncookies;
	tcp_syncookies.importantLevel = "2";
	tcp_syncookies.description = "检查系统内核参数配置";
	tcp_syncookies.basis = "=1";
	tcp_syncookies.recommend = "该项配置主要为了缓解拒绝服务攻击。调整内核安全参数，增强系统安全性，tcp_syncookies的值应设为1";

	//fileIsExist是判断配置文件是否存在，如果存在，则找到了配置文件，标记findFile为true;
	//将stderr（文件描述符2）重定向为stdout（文件描述符1）来根据返回信息判断文件是否存在。
	fileIsExist = "cat /proc/sys/net/ipv4/tcp_syncookies 2>&1 | grep cat: ";
	fileIsExist = execute_commands(session, fileIsExist);
	findFile = false;

	if (fileIsExist.compare("") == 0)
	{
		findFile = true;

		tcp_syncookies.command = "cat /proc/sys/net/ipv4/tcp_syncookies | tr -d '\n' | tr -d ' '";
		tcp_syncookies.result = execute_commands(session, tcp_syncookies.command);


		if (tcp_syncookies.result.compare("1") == 0)
		{
			tcp_syncookies.IsComply = "true";
		}
	}

	if (!findFile)
	{
		tcp_syncookies.result = "未找到配置文件";
	}

	Event.push_back(tcp_syncookies);

	//6.15检查是否按组进行账号管理
	event group_manage;
	group_manage.importantLevel = "1";
	group_manage.description = "检查是否按组进行账号管理";
	group_manage.basis = "请手工查看/etc/group等文件";
	group_manage.recommend = "此配置项主要偏向于对系统用户的管理，如账户已分组管理，该检查项可以跳过。此检查项建议系统管理员根据系统情况自行判断";
	group_manage.result = "手动检查";

	Event.push_back(group_manage);



	//6.17 检查root用户的path环境变量
	event root_path_check;
	root_path_check.importantLevel = "2";
	root_path_check.description = "检查root用户的path环境变量内容";
	root_path_check.basis = "不包含（.和..）的路径";
	root_path_check.command = "sudo sh -c 'echo $PATH' | grep -o -e '\\.\\.' -e '\\.' | wc -l";
	root_path_check.result = execute_commands(session, root_path_check.command);
	root_path_check.recommend = "修改文件/etc/profile或/root/.bash_profile 在环境变量$PATH中删除包含（.和..）的路径";


	//转为Int来比较
	int numm = atoi(root_path_check.result.c_str());

	if (numm == 0)
	{
		root_path_check.IsComply = "true";
		root_path_check.result = "不包含（.和..）的路径,符合基线";
	}

	/*cout << root_path_check.recommend << endl;
	cout << root_path_check.result << endl;
	cout << root_path_check.IsComply << endl;*/

	Event.push_back(root_path_check);

	//6.18 检查系统是否禁用ctrl+alt+del组合键
	event ctrl_alt_del_disabled;
	ctrl_alt_del_disabled.importantLevel = "2";
	ctrl_alt_del_disabled.description = "检查系统是否禁用ctrl+alt+del组合键";
	ctrl_alt_del_disabled.basis = "禁用Ctrl+Alt+Delete组合键重启系统";

	if (type_os == "RPM") { //centos7
		ctrl_alt_del_disabled.command = "cat /usr/lib/systemd/system/ctrl-alt-del.target | grep \"Alias=ctrl-alt-del.target\" | grep -v ^#";
		ctrl_alt_del_disabled.recommend = "系统应该禁用ctrl+alt+del组合键，具体操作：vi /usr/lib/systemd/system/ctrl-alt-del.target。找到下面行并注释掉：Alias = ctrl - alt - del.target。";
	}
	else if (type_os == "Debian") { //ubuntu
		ctrl_alt_del_disabled.command = "cat /lib/systemd/system/ctrl-alt-del.target | grep \"Alias=ctrl-alt-del.target\" | grep -v ^#";
		ctrl_alt_del_disabled.recommend = "系统应该禁用ctrl+alt+del组合键，具体操作：vi /lib/systemd/system/ctrl-alt-del.target。找到下面行并注释掉：Alias = ctrl - alt - del.target。";
	}

	ctrl_alt_del_disabled.result = execute_commands(session, ctrl_alt_del_disabled.command);
	if (ctrl_alt_del_disabled.result == "") {
		ctrl_alt_del_disabled.result = "已经禁用这个快捷键,符合基线";
		ctrl_alt_del_disabled.IsComply = "true";
	}
	else {
		ctrl_alt_del_disabled.IsComply = "false";
	}

	Event.push_back(ctrl_alt_del_disabled);

	//6.19 检查是否关闭系统信任机制
	event sys_trust_mechanism;
	sys_trust_mechanism.description = "检查是否关闭系统信任机制";
	sys_trust_mechanism.basis = "关闭系统信任机制";
	sys_trust_mechanism.importantLevel = "3";
	sys_trust_mechanism.command = "find / -maxdepth 3 -type f -name .rhosts 2>/dev/null; find / -maxdepth 2 -name hosts.equiv 2>/dev/null";
	sys_trust_mechanism.recommend = "1.执行命令find / -maxdepth 2 -name hosts.equiv 进入到. hosts.equiv文件存在的目录，执行命令：mv hosts.equiv hosts.equiv.bak。2.执行命令find / -maxdepth 3 -type f -name .rhosts 2>/dev/null 进入到.rhosts文件存在的目录，执行命令：mv .rhosts .rhosts.bak。";

	sys_trust_mechanism.result = execute_commands(session, sys_trust_mechanism.command);
	if (sys_trust_mechanism.result == "") {
		sys_trust_mechanism.result = "已经关闭系统信任机制,符合基线";
		sys_trust_mechanism.IsComply = "true";
	}
	else {
		sys_trust_mechanism.IsComply = "false";
	}

	Event.push_back(sys_trust_mechanism);

	//6.20 检查系统磁盘分区使用率
	event disk_partition_usage_rate;
	disk_partition_usage_rate.importantLevel = "1";
	disk_partition_usage_rate.description = "检查系统磁盘分区使用率";
	disk_partition_usage_rate.basis = "<=80";

	disk_partition_usage_rate.command = "df -h | awk 'NR>1 {sub(/%/,\"\",$5); if ($5+0 > 80) print $5 \" % \" \" \" $6}'";
	disk_partition_usage_rate.recommend = "磁盘动态分区空间不足，建议管理员扩充磁盘容量。命令：df - h";

	disk_partition_usage_rate.result = execute_commands(session, disk_partition_usage_rate.command);
	if (disk_partition_usage_rate.result == "") {
		disk_partition_usage_rate.result = "系统磁盘分区使用率都<=80,符合基线";
		disk_partition_usage_rate.IsComply = "true";
	}
	else {
		disk_partition_usage_rate.IsComply = "false";
	}

	Event.push_back(disk_partition_usage_rate);


	//6.21 检查是否删除了潜在危险文件
	event potential_risk_files;
	potential_risk_files.importantLevel = "3";
	potential_risk_files.description = "检查是否删除了潜在危险文件";
	potential_risk_files.basis = "删除潜在危险文件，包括hosts.equiv文件 .rhosts文件和 .netrc 文件";

	potential_risk_files.command = "find / -type f \\( -name \".rhosts\" -o -name \".netrc\" -o -name \"hosts.equiv\" \\) 2>/dev/null";
	potential_risk_files.recommend = "应该删除潜在危险文件 hosts.equiv文件 .rhosts文件和 .netrc 文件";

	potential_risk_files.result = execute_commands(session, potential_risk_files.command);
	if (potential_risk_files.result == "") {
		potential_risk_files.result = "已删除潜在危险文件，符合基线";
		potential_risk_files.IsComply = "true";
	}
	else {
		potential_risk_files.IsComply = "false";
	}

	Event.push_back(potential_risk_files);

	//6.22 检查是否删除与设备运行，维护等工作无关的账号 手动检查

	//6.23 检查是否配置用户所需最小权限
	event user_min_permission;
	user_min_permission.importantLevel = "2";
	user_min_permission.description = "检查是否配置用户所需最小权限";
	user_min_permission.basis = "配置用户所需最小权限,/etc/passwd为644；/etc/group为644；/etc/shadow为600";

	user_min_permission.command = "[ $(stat -c \" % a\" /etc/passwd) -le 644 ] || stat -c \" % a % n\" /etc/passwd; [ $(stat -c \" % a\" /etc/shadow) -le 600 ] || stat -c \" % a % n\" /etc/shadow; [ $(stat -c \" % a\" /etc/group) -le 644 ] || stat -c \" % a % n\" /etc/group";
	user_min_permission.recommend = "应配置用户所需最小权限,chmod 644 /etc/passwd；chmod 644 /etc/group；chmod 600 /etc/shadow";

	user_min_permission.result = execute_commands(session, user_min_permission.command);
	if (user_min_permission.result == "") {
		user_min_permission.result = "已配置用户最小权限，符合基线";
		user_min_permission.IsComply = "true";
	}
	else {
		user_min_permission.IsComply = "false";
	}

	Event.push_back(user_min_permission);

	//6.24 检查是否关闭数据包转发功能（适用于不做路由功能的系统）-对于集群系统或者需要数据包转发的系统不做该配置
	event packet_forward_func;
	packet_forward_func.importantLevel = "1";
	packet_forward_func.description = "对检查是否关闭数据包转发功能";
	packet_forward_func.basis = "对于不做路由功能的系统，应该关闭数据包转发功能";

	packet_forward_func.command = "cat /proc/sys/net/ipv4/ip_forward";
	packet_forward_func.recommend = "应该关闭数据包转发功能；命令： #sysctl -w net.ipv4.ip_forward=0";

	packet_forward_func.result = execute_commands(session, packet_forward_func.command);

	int num11 = atoi(packet_forward_func.result.c_str());
	if (packet_forward_func.result.compare(""))
	{
		if (num11 == 0)
		{
			packet_forward_func.result = "已关闭数据包转发功能，符合基线";
			packet_forward_func.IsComply = "true";
		}
		else {
			packet_forward_func.result = "未关闭数据包转发功能";
			packet_forward_func.IsComply = "false";
		}
	}
	else
	{
		packet_forward_func.IsComply = "false";
	}

	Event.push_back(packet_forward_func);

	//6.25检查是否禁用不必要的系统服务 手动检查


	//6.26 检查是否使用NTP（网络时间协议）保持时间同步
	event ntp_sync_status;
	ntp_sync_status.importantLevel = "1";
	ntp_sync_status.description = "检查是否使用NTP（网络时间协议）保持时间同步";
	ntp_sync_status.basis = "检查ntp服务是否开启，若开启则需配置NTP服务器地址";
	//没有使用ntp，则输出no ntp；使用ntp但没配置地址，则输出no server；使用ntp且配置了地址，则输出配置。
	ntp_sync_status.command = "ps -ef | egrep \"ntp | ntpd\" | grep -v grep | grep \" / usr / sbin / ntpd\" >/dev/null && (grep \" ^ server\" /etc/ntp.conf || echo \"no server\") || echo \"no ntp\"";

	ntp_sync_status.result = execute_commands(session, ntp_sync_status.command);

	if (ntp_sync_status.result.find("no ntp") != std::string::npos) {
		ntp_sync_status.result = "未开启NTP服务，不符合基线";
		ntp_sync_status.recommend = "开启ntp服务： redhat为：/etc/init.d/ntpd start ；suse9为：/etc/init.d/xntpd start ；suse10,11为：/etc/init.d/ntp start。";
		ntp_sync_status.IsComply = "false";
	}
	else if (ntp_sync_status.result.find("no server") != std::string::npos) {
		ntp_sync_status.result = "未配置NTP服务器地址，不符合基线";
		ntp_sync_status.recommend = "编辑ntp的配置文件： #vi / etc / ntp.conf,配置：server IP地址（提供ntp服务的机器）,如：server 192.168.1.1 ";
		ntp_sync_status.IsComply = "false";
	}
	else {
		ntp_sync_status.result = "已配置NTP服务器地址，符合基线";
		ntp_sync_status.IsComply = "true";
	}

	Event.push_back(ntp_sync_status);

	//6.27 检查NFS（网络文件系统）服务设置
	event nfs_server;
	nfs_server.importantLevel = "1";
	nfs_server.description = "检查NFS（网络文件系统）服务设置";
	nfs_server.basis = "如果需要NFS服务，需要限制能够访问NFS服务的IP范围；如果没有必要，需要停止NFS服务";
	//1."no nfs": 没有NFS服务在运行。2. 输出非注释非空行: 显示了/etc/hosts.allow和/etc/hosts.deny中配置的IP访问限制规则。3."no ip limitation": NFS服务在运行，但没有配置任何IP访问限制规则。
	nfs_server.command = "netstat -lntp | grep -q nfs && { cat /etc/hosts.allow /etc/hosts.deny | grep -v ^# | sed '/^$/d' || echo \"no ip limitation\"; } || echo \"no nfs\"";

	nfs_server.result = execute_commands(session, nfs_server.command);
	nfs_server.recommend = "停止NFS服务或限制能够访问NFS服务的IP范围";

	if (nfs_server.result.find("no nfs") != std::string::npos) {
		nfs_server.result = "没有NFS服务在运行，符合基线";
		nfs_server.recommend = "停止NFS服务或限制能够访问NFS服务的IP范围";
		nfs_server.IsComply = "true";
	}
	else if (nfs_server.result.find("no ip limitation") != std::string::npos) {
		nfs_server.result = "NFS服务在运行，但没有配置任何IP访问限制规则，不符合基线";
		nfs_server.recommend = "限制能够访问NFS服务的IP范围： 编辑文件：vi /etc/hosts.allow 增加一行:portmap: 允许访问的IP。或停止nfs服务： Suse系统：/etc/init.d/nfsserver stop ；Redhat系统：/etc/init.d/nfs stop";
		nfs_server.IsComply = "false";
	}
	else {
		nfs_server.result = "已开启NFS服务并限制能够访问NFS服务的IP范围，符合基线";
		nfs_server.IsComply = "true";
	}

	Event.push_back(nfs_server);

	//6.28 检查是否安装OS补丁 手动

	//6.29 检查是否设置ssh成功登陆后Banner
	event ssh_banner;
	ssh_banner.importantLevel = "1";
	ssh_banner.description = "检查是否设置ssh成功登陆后Banner";
	ssh_banner.basis = "设置ssh成功登陆后Banner";

	ssh_banner.command = "systemctl status sshd | grep -q running && [ -s /etc/motd ] && cat /etc/motd || true";
	ssh_banner.recommend = "为了保证信息安全的抗抵赖性，需要设置ssh成功登录后Banner";

	ssh_banner.result = execute_commands(session, ssh_banner.command);
	if (ssh_banner.result == "") {
		ssh_banner.result = "未设置ssh成功登陆后Banner，不符合基线";
		ssh_banner.recommend = "为了保证信息安全的抗抵赖性，需要设置ssh成功登录后Banner：修改文件/etc/motd的内容，如没有该文件，则创建它。 #echo \"Login success.All activity will be monitored and reported \" > /etc/motd根据实际需要修改该文件的内容";
		ssh_banner.IsComply = "false";
	}
	else {
		ssh_banner.IsComply = "false";
	}

	Event.push_back(ssh_banner);

	string is_install;
	string rpm_command = "rpm -qa | grep -E 'vsftpd|pure-ftpd' &> /dev/null && (rpm -qa | grep -q 'vsftpd' && echo \"vsftpd\") || (rpm -qa | grep -q 'pure-ftpd' && echo \"pure-ftpd\") || echo \"Neither\"";
	string Debian_command = "dpkg -l | grep -E 'vsftpd|pure-ftpd' &> /dev/null && (dpkg -l | grep -q 'vsftpd' && echo \"vsftpd\") || (dpkg -l | grep -q 'pure-ftpd' && echo \"pure-ftpd\") || echo \"Neither\"";
	string soft_ware;

	
	//6.30 检查FTP用户上传的文件所具有的权限

	event upload_ftp;
	upload_ftp.importantLevel = "1";
	upload_ftp.description = "检查FTP用户上传的文件所具有的权限";
	upload_ftp.basis = "检查是否允许上传和上传权限设置正确";
	if (type_os == "RPM") {
		soft_ware = execute_commands(session, rpm_command);
	}
	else {
		soft_ware = execute_commands(session, Debian_command);
	}
	// 查找最后一个不是换行符(\n)的字符
	pos = soft_ware.find_last_not_of('\n');
	if (pos != std::string::npos) {
		// 从开头到最后一个非换行符的字符复制字符串
		soft_ware = soft_ware.substr(0, pos + 1);
	}
	else {
		// 如果没有找到，说明没有换行符，直接复制原始字符串
		soft_ware = soft_ware;
	}
	if (soft_ware == "vsftpd") {
		upload_ftp.command = "grep -E \"^(write_enable=YES|ls_recurse_enable=YES|local_umask=022|anon_umask=022)\" /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf";
		upload_ftp.result = execute_commands(session, upload_ftp.command);
		if (upload_ftp.result == "") {
			upload_ftp.result = "未对FTP用户上传的文件所具有的权限检查";
			upload_ftp.IsComply = "false";
		}
		else {
			upload_ftp.IsComply = "true";
			upload_ftp.recommend = "对FTP用户上传的文件所具有的权限检查";
		}
	}
	else if (soft_ware == "pure-ftpd") {
		upload_ftp.command = "grep -E \"^Umask 177:077\" /etc/pure-ftpd/pure-ftpd.conf";
		upload_ftp.result = execute_commands(session, upload_ftp.command);
		if (upload_ftp.result == "") {
			upload_ftp.result = "未对FTP用户上传的文件所具有的权限检查";
			upload_ftp.IsComply = "false";
		}
		else {
			upload_ftp.IsComply = "true";
		}
	}
	else {
		upload_ftp.command = "None";
		upload_ftp.result = "未安装vsftpd或者pure-ftpd";
		upload_ftp.IsComply = "false";
		upload_ftp.recommend = "要安装vsftpd或者pure-ftpd";

	}

	Event.push_back(upload_ftp);

	//6.31检查是否更改默认的ftp登陆警告Banner

	event ftp_baner;
	ftp_baner.importantLevel = "1";
	ftp_baner.description = "是否更改默认的ftp登陆警告Banner";
	ftp_baner.basis = "需要自己检查自定义的banner";

	if (soft_ware == "vsftpd") {
		ftp_baner.command = "grep -E \"^[^#]*ftpd_banner\" /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf";
		ftp_baner.result = execute_commands(session, ftp_baner.command);
		if (ftp_baner.result == "") {
			ftp_baner.result = "未更改默认的ftp登陆警告Banner";
			ftp_baner.IsComply = "false";
		}
		else {
			ftp_baner.IsComply = "false";
		}
	}
	else if (soft_ware == "pure-ftpd") {
		ftp_baner.command = "grep -v '^#' /etc/pure-ftpd/pure-ftpd.conf | grep 'FortunesFile'";
		ftp_baner.result = execute_commands(session, ftp_baner.command);
		if (ftp_baner.result == "") {
			ftp_baner.result = "未更改默认的ftp登陆警告Banner";
			ftp_baner.IsComply = "false";
			ftp_baner.recommend = "更改默认的ftp登陆警告Banner";
		}
		else {
			ftp_baner.IsComply = "false";
		}
	}
	else {
		ftp_baner.command = "None";
		ftp_baner.result = "未安装vsftpd或者pure-ftpd";
		ftp_baner.IsComply = "false";
		ftp_baner.recommend = "安装vsftpd或者pure-ftpd";
	}
	Event.push_back(ftp_baner);


	//6.32检查/usr/bin/目录下可执行文件的拥有者属性
	event bin_owner;
	bin_owner.importantLevel = "1";
	bin_owner.description = "为了保证信息安全的可靠性，需要减产可执行文件的拥有者属性";
	bin_owner.basis = "所有含有“s”属性的文件，把不必要的“s”属性去掉，或者把不用的直接删除。";
	bin_owner.command = "find /usr/bin -type f \( -perm -04000 -o -perm -02000 \) -exec ls -lg {} \; ";
	bin_owner.result = "自行判断";
	bin_owner.IsComply = "false";
	bin_owner.recommend = "减产可执行文件的拥有者属性";
	Event.push_back(bin_owner);


	//6.33 检查telnet Banner设置
	event telnet_banner;
	telnet_banner.importantLevel = "1";
	telnet_banner.description = "检查是否更改默认的telnet登录警告Banner";
	telnet_banner.basis = "请手动检查修改文件/etc/issue 和/etc/issue.net中的内容";
	telnet_banner.recommend = "请手动检查修改文件/etc/issue 和/etc/issue.net中的内容";
	telnet_banner.IsComply = "false";
	telnet_banner.result = "自行判断";
	Event.push_back(telnet_banner);

	//6.34 检查是否限制FTP用户登录后能访问的目录
	event ftp_directory;
	ftp_directory.importantLevel = "1";
	ftp_directory.description = "检查是否限制FTP用户登录后能访问的目录";
	ftp_directory.basis = "应该限制FTP用户登录后能访问的目录";

	ftp_directory.command = "ps -ef | grep ftp | grep -v grep";
	ftp_directory.recommend = "为了保证信息安全的可靠性，需要限制FTP用户登录后能访问的目录";

	ftp_directory.result = execute_commands(session, ftp_directory.command);
	if (ftp_directory.result == "") {
		ftp_directory.result = "没有FTP服务在运行，符合基线";
		ftp_directory.IsComply = "true";
	}
	else {
		string command1 = "[ -f /etc/vsftpd/vsftpd.conf ] && grep '^chroot_local_user=NO' /etc/vsftpd/vsftpd.conf && grep '^chroot_list_enable=YES' /etc/vsftpd/vsftpd.conf && grep '^chroot_list_file=/etc/vsftpd/chroot_list' /etc/vsftpd/vsftpd.conf && echo \"All configurations are as expected\"";
		string result1 = execute_commands(session, command1);
		if (result1 == "") {
			ftp_directory.result = "未限制FTP用户登录后能访问的目录，不符合基线";
			ftp_directory.IsComply = "false";
		}
		else {
			ftp_directory.IsComply = "true";
		}
	}

	Event.push_back(ftp_directory);

	//6.36 检查内核版本是否处于CVE-2021-43267漏洞影响版本
	event kernel_cve_2021_43267;
	kernel_cve_2021_43267.importantLevel = "3";
	kernel_cve_2021_43267.description = "检查内核版本是否处于CVE-2021-43267漏洞影响版本";
	kernel_cve_2021_43267.basis = "内核版本不在5.10和5.14.16之间";
	//内核版本在5.10和5.14.16之间则输出版本号，不在则输出"不受CVE - 2021 - 43267影响"
	kernel_cve_2021_43267.command = "kernel=$(uname -r | awk -F- '{print $1}'); kernel_major=$(echo $kernel | cut -d. -f1); kernel_minor=$(echo $kernel | cut -d. -f2); kernel_patch=$(echo $kernel | cut -d. -f3); if [[ \"$kernel_major\" -eq 5 && (\"$kernel_minor\" -gt 10 || (\"$kernel_minor\" -eq 10 && \"$kernel_patch\" -ge 0)) && (\"$kernel_minor\" -lt 14 || (\"$kernel_minor\" -eq 14 && \"$kernel_patch\" -lt 16)) ]]; then echo $kernel; else echo \"不受CVE - 2021 - 43267影响\"; fi";
	kernel_cve_2021_43267.recommend = "内核版本不能在5.10和5.14.16之间";

	kernel_cve_2021_43267.result = execute_commands(session, kernel_cve_2021_43267.command);
	if (kernel_cve_2021_43267.result.find("不受CVE - 2021 - 43267影响") != std::string::npos) {
		kernel_cve_2021_43267.result = "内核版本不受CVE-2021-43267漏洞影响，符合基线";
		kernel_cve_2021_43267.IsComply = "true";
	}
	else {
		kernel_cve_2021_43267.IsComply = "false";
		kernel_cve_2021_43267.recommend = "该内核范围存在漏洞，请升级内核或打上补丁";
	}

	Event.push_back(kernel_cve_2021_43267);



}


void ServerInfo_Padding(ServerInfo& info, ssh_session session) {
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
	string free = "free - g | grep Mem | awk '{print $2}'| tr -d \"\\n\"";
	info.free = execute_commands(session, free);
	string ping = "(ping -c 1 8.8.8.8 > /dev/null 2>&1 && echo true || echo false) | tr -d \"\\n\"";
	info.isInternet = execute_commands(session, ping);

}
