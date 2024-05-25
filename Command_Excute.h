#pragma once
#include <libssh/libssh.h>
#include <fstream>
#include <vector>
#include <sstream>
#include <string>
#include <iostream>
using namespace std;
string execute_commands(ssh_session session,  string commands);