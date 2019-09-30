#pragma once
#include <string>
#include <map>
#include <vector>

using namespace std;

typedef map<string, string> Objmap;

// 获取环境变量
string getenv(const char* name, const string& defaultValue);

// 获取公网IP
string getip();

// 向阿里云更新DNS
void sendip(const string& ip, const string& domainName);

// 签名
string getSignature(const string& keySecret, const string& str);

// url参数编码
string url_encode(const string& value);

string toSignString(const string& HTTPMethod, const string& cq);

string getTimestamp();

string canonicalizedQueryString(const Objmap& params);

map<string, string> oneTimeParams();

map<string, string> getDefaultParams();

string doAction(const Objmap& params, const string& method = "GET");

void sendip(const string& ip, const string& domainName);