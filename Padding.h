#pragma once
#include"Event.h"
#include<unordered_map>
#include<libssh/libssh.h>
#include <algorithm>   // std::remove_if
#include <cctype>      // ::isspace
void ServerInfo_Padding(ServerInfo& info, ssh_session session);
void fun(vector<event>& Event, ssh_session session);
