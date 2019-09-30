#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <map>
#include <vector>
#include <random>
#include <ctime>
#include "httplib.h"
#include "../crypto/hmac.h"
#include "../crypto/base64.h"
#include "json.hpp"
#include "updns.h"

using namespace std;
using json = nlohmann::json;

random_device rd;

string getip() {
	httplib::Client client("api.ipify.org");
	auto res = client.Get("/");
	auto body = res->body;
	return body;
}

string getTimestamp() {
	time_t now;
	time(&now);
	char buf[sizeof "2011-10-08T07:07:09Z"];
	strftime(buf, sizeof buf, "%FT%TZ", gmtime(&now));
	return buf;
}

string getenv(const char* name, const string& defaultValue) {
	auto v = getenv(name);
	return v == 0 ? defaultValue : v;
}

string getSignature(const string& keySecret, const string& str) {
	const auto key = keySecret + "&";
	uint8_t de[20];
	size_t deSize;
	hmac_sha1((uint8_t*)& key[0], key.size(), (uint8_t*)str.c_str(), str.size(), de, &deSize);
	return base64_encode(de, 20);
}

string url_encode(const string& value) {
	ostringstream escaped;
	escaped.fill('0');
	escaped << hex;

	for (string::const_iterator i = value.begin(), n = value.end(); i != n; ++i) {
		string::value_type c = (*i);

		// Keep alphanumeric and other accepted characters intact
		if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
			escaped << c;
			continue;
		}

		// Any other characters are percent-encoded
		escaped << uppercase;
		escaped << '%' << setw(2) << int((unsigned char)c);
		escaped << nouppercase;
	}

	return escaped.str();
}

string toSignString(const string& HTTPMethod, const string& cq) {
	return HTTPMethod + '&' + url_encode("/") + '&' + url_encode(cq);
}

string canonicalizedQueryString(const Objmap& params) {
	ostringstream ostr;
	auto psize = params.size();
	size_t i = 1;
	for (const auto& p : params) {
		ostr << url_encode(p.first) + "=" << url_encode(p.second);
		if (i != psize) {
			ostr << '&';
		}
		i++;
	}
	return ostr.str();
}

Objmap oneTimeParams() {
	Objmap r;
	uniform_int_distribution ud(0, 999999999);
	r["Timestamp"] = getTimestamp();
	r["SignatureNonce"] = to_string(ud(rd));
	return r;
}

Objmap getDefaultParams() {
	Objmap r;
	r["Format"] = "JSON";
	r["Version"] = "2015-01-09";
	r["SignatureMethod"] = "HMAC-SHA1";
	r["SignatureVersion"] = "1.0";
	r["AccessKeyId"] = getenv("ALIYUN_ACCESSKEYID", ""); 
	return r;
}

string doAction(const Objmap& params, const string& method) {
	Objmap reqParams;
	const auto timeParams = oneTimeParams();
	const auto defaultParams = getDefaultParams();
	
	reqParams.insert(params.cbegin(), params.cend());
	reqParams.insert(timeParams.cbegin(), timeParams.cend());
	reqParams.insert(defaultParams.cbegin(), defaultParams.cend());

	auto Signature = getSignature(getenv("ALIYUN_KEYSECRET", ""), toSignString(method, canonicalizedQueryString(reqParams)));
	
	reqParams["Signature"] = Signature;
	auto qs = canonicalizedQueryString(reqParams);
	auto path = "/?" + qs;

	httplib::Client client("alidns.aliyuncs.com");
	if (method == "GET") {
		auto res = client.Get(path.c_str());
		return res->body;
	}

	return "";
}

void sendip(const string& ip, const string& domainName) {
	Objmap obj;
	obj["Action"] = "DescribeDomainRecords";
	obj["DomainName"] = domainName;
	auto res = doAction(obj);
	json j = json::parse(res);
	
	auto DomainRecords = j["DomainRecords"]["Record"];
	for (const auto& record : DomainRecords) {
		if (record["Type"].get<string>() == "A") {
			Objmap updateParams;
			updateParams["Action"] = "UpdateDomainRecord";
			updateParams["RecordId"] = record["RecordId"];
			updateParams["RR"] = record["RR"];
			updateParams["Type"] = record["Type"];
			updateParams["Value"] = ip;

			doAction(updateParams);
		}
	}
	return;
}

int main()
{
	auto ip = getip();
	sendip(ip, getenv("ALIYUN_DOMAIN", ""));

    cout << ip << endl;
}
