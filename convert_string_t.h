#pragma once
#include<cstring>
#include <libssh/libssh.h>
#include <fstream>
#include <vector>
#include <sstream>
#include <string>
#include <iostream>
#include"Login.h"
#include"Command_Excute.h"
#include"Padding.h"
#include"Event_h.h"
std::vector<event_t> ConvertEvents(const std::vector<event>& oldEvents);

ServerInfo_t convert(ServerInfo& info);
string ws2s(const wstring& ws);
wstring s2ws(const string& s);