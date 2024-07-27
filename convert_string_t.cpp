#define _CRT_SECURE_NO_WARNINGS
#include "convert_string_t.h"
#include <cpprest/json.h>
#include <locale>
#include <codecvt>
#include <string>

using namespace std;

wstring s2ws(const string& s)
{
    setlocale(LC_ALL, "chs");

    const char* _Source = s.c_str();
    size_t _Dsize = s.size() + 1;
    wchar_t* _Dest = new wchar_t[_Dsize];
    wmemset(_Dest, 0, _Dsize);
    mbstowcs(_Dest, _Source, _Dsize);
    wstring result = _Dest;
    delete[] _Dest;

    setlocale(LC_ALL, "C");

    return result;
}

string ws2s(const wstring& ws)
{
    string curLocale = setlocale(LC_ALL, NULL); // curLocale = "C";

    setlocale(LC_ALL, "chs");

    const wchar_t* _Source = ws.c_str();
    size_t _Dsize = 2 * ws.size() + 1;
    char* _Dest = new char[_Dsize];
    memset(_Dest, 0, _Dsize);
    wcstombs(_Dest, _Source, _Dsize);
    string result = _Dest;
    delete[] _Dest;

    setlocale(LC_ALL, curLocale.c_str());

    return result;
}

utility::string_t to_utility_string_t(const std::wstring& wstr)
{
#ifdef _WIN32
    return wstr;
#else
    return ws2s(wstr);
#endif
}

std::vector<event_t> ConvertEvents(const std::vector<event>& oldEvents) {
    std::vector<event_t> newEvents;
    for (const auto& oldEvent : oldEvents) {
        event_t newEvent;

        newEvent.description = to_utility_string_t(s2ws(oldEvent.description));
        newEvent.basis = to_utility_string_t(s2ws(oldEvent.basis));
        newEvent.command = to_utility_string_t(s2ws(oldEvent.command));
        newEvent.result = to_utility_string_t(s2ws(oldEvent.result));
        newEvent.IsComply = to_utility_string_t(s2ws(oldEvent.IsComply));
        newEvent.recommend = to_utility_string_t(s2ws(oldEvent.recommend));

        newEvents.push_back(newEvent);
    }
    return newEvents;
}

ServerInfo_t convert(ServerInfo& info) {
    ServerInfo_t info_new;
    info_new.arch = to_utility_string_t(s2ws(info.arch));
    info_new.cpu = to_utility_string_t(s2ws(info.cpu));
    info_new.cpuCore = to_utility_string_t(s2ws(info.cpuCore));
    info_new.cpuPhysical = to_utility_string_t(s2ws(info.cpuPhysical));
    info_new.free = to_utility_string_t(s2ws(info.free));
    info_new.hostname = to_utility_string_t(s2ws(info.hostname));
    info_new.isInternet = to_utility_string_t(s2ws(info.isInternet));
    info_new.ProductName = to_utility_string_t(s2ws(info.ProductName));
    info_new.version = to_utility_string_t(s2ws(info.version));
    return info_new;
}
