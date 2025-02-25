#include <iostream>
#include <fstream>
#include <sstream>
#include <cstdlib>
#include <string>
#include <array>
#include <memory>
#include <stdexcept>
#include"log/log.h"

std::string executeCommand(const std::string& command);

std::string performPortScan(const std::string& targetHost, bool allPorts);

//µ÷ÓÃC¿âº¯Êý
extern "C" const char* executePortScan(const char* targetHost);