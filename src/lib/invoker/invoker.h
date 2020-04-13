// Copyright (c) 2019 Ivan Šincek

#ifndef INVOKER
#define INVOKER

#include <windows.h>
#include <string>

void print(std::string msg);

std::string trim(std::string str);

std::string input(std::string msg);

bool isPositiveNumber(std::string str);

void psExec(std::string encoded);

bool createFile(std::string file, std::string data = "");

std::string readFile(std::string file);

bool downloadFile(std::string url, std::string out);

bool addRegistryKey(HKEY hKey, std::string path, std::string name, std::string value);

bool reverseTCP(std::string ip, int port);

int chooseProcess();

bool terminateProcess(int pid);

bool runProcess(std::string file, std::string args = "", PHANDLE hToken = NULL);

std::string getWebContent(std::string url, int port);

std::string extractPayload(std::string data, std::string element, std::string placeholder);

bool injectBytecode(int pid, std::string bytecode);

bool injectDll(int pid, std::string file);

void enableAccessTokenPrivs();

HANDLE duplicateAccessToken(int pid);

#endif

