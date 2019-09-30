#pragma once
#include <string>
#include <map>
#include <vector>

using namespace std;

typedef map<string, string> Objmap;

// ��ȡ��������
string getenv(const char* name, const string& defaultValue);

// ��ȡ����IP
string getip();

// �����Ƹ���DNS
void sendip(const string& ip, const string& domainName);

// ǩ��
string getSignature(const string& keySecret, const string& str);

// url��������
string url_encode(const string& value);

string toSignString(const string& HTTPMethod, const string& cq);

string getTimestamp();

string canonicalizedQueryString(const Objmap& params);

map<string, string> oneTimeParams();

map<string, string> getDefaultParams();

string doAction(const Objmap& params, const string& method = "GET");

void sendip(const string& ip, const string& domainName);