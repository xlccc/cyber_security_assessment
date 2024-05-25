#pragma once
#include <libssh/libssh.h>
#include <fstream>
#include <vector>
#include <sstream>
#include <string>
#include <iostream>

ssh_session initialize_ssh_session(const char* hostname, const char* username, const char* password);
