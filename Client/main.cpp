#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <array>

PVOID sharedMem;
HANDLE pipe;
float colors[20][3] = {
	{ 242.f, 19.f, 19.f },
	{ 242.f, 153.f, 19.f },
	{ 149.f, 242.f, 19.f },
	{ 19.f, 242.f, 64.f },
	{ 19.f, 242.f, 223.f },
	{ 19.f, 60.f, 242.f },
	{ 175.f, 19.f, 242.f },
	{ 242.f, 19.f, 186.f },
	{ 156.f, 60.f, 12.f },
	{ 156.f, 142.f, 12.f },
	{ 108.f, 156.f, 12.f },
	{ 12.f, 156.f, 103.f },
	{ 12.f, 120.f, 156.f },
	{ 110.f, 12.f, 156.f },
	{ 156.f, 12.f, 106.f },
	{ 120.f, 191.f, 141.f },
	{ 120.f, 166.f, 191.f },
	{ 152.f, 120.f, 191.f },
	{ 120.f, 140.f, 191.f },
};

typedef struct Color_ {
	float r;
	float g;
	float b;
} Color;

void triggerRoutine() {
	char x;
	ReadFile(pipe, &x, 1, NULL, NULL);
}

template <typename T>
T rpm(UINT32 pid, UINT64 virtAddr) {
	*(UINT32*)((CHAR*)sharedMem + 1) = pid;
	*(UINT64*)((CHAR*)sharedMem + 5) = virtAddr;
	*(UINT32*)((CHAR*)sharedMem + 13) = sizeof(T);
	*(CHAR*)sharedMem = 'r';

	triggerRoutine();
	while (*(CHAR*)sharedMem != 'x') Sleep(1);

	T buffer;
	memcpy(&buffer, (CHAR*)sharedMem + 17, sizeof(T));

	return buffer;
}

template <typename T>
void wpm(UINT32 pid, UINT64 virtAddr, T buffer) {
	*(UINT32*)((CHAR*)sharedMem + 1) = pid;
	*(UINT64*)((CHAR*)sharedMem + 5) = virtAddr;
	*(UINT32*)((CHAR*)sharedMem + 13) = sizeof(buffer);
	*(T*)((CHAR*)sharedMem + 17) = buffer;

	* (CHAR*)sharedMem = 'w';

	triggerRoutine();
	while (*(CHAR*)sharedMem != 'x') Sleep(1);
}

void wpm(UINT32 pid, UINT64 virtAddr, void* buffer, size_t bufferSize) {
	*(UINT32*)((CHAR*)sharedMem + 1) = pid;
	*(UINT64*)((CHAR*)sharedMem + 5) = virtAddr;
	*(UINT32*)((CHAR*)sharedMem + 13) = (UINT32)bufferSize;
	memcpy((CHAR*)sharedMem + 17, buffer, sizeof(buffer));

	*(CHAR*)sharedMem = 'w';

	triggerRoutine();
	while (*(CHAR*)sharedMem != 'x') Sleep(1);
}

PVOID modBase(UINT32 pid, std::string moduleName) {
	if (moduleName.length() >= 0x40 - 13) return 0;

	*(UINT32*)((CHAR*)sharedMem + 1) = pid;
	strcpy_s((CHAR*)sharedMem + 5, 0x40 - 13, moduleName.c_str());
	*(CHAR*)sharedMem = 'm';

	triggerRoutine();
	while (*(CHAR*)sharedMem != 'x') Sleep(1);

	return *(PVOID*)((UCHAR*)sharedMem + 0x38);
}

UINT32 getPid(std::string moduleName) {
	if (moduleName.length() >= 0x40 - 5) return 0;

	strcpy_s((CHAR*)sharedMem + 5, 0x40 - 13, moduleName.c_str());
	*(CHAR*)sharedMem = 'p';

	triggerRoutine();
	while (*(CHAR*)sharedMem != 'x') Sleep(1);

	return *(UINT32*)((UCHAR*)sharedMem + 1);
}

int main() {
	pipe = CreateNamedPipeA("\\\\.\\pipe\\test", PIPE_ACCESS_DUPLEX, PIPE_NOWAIT, 1, 256, 256, 0, NULL);
	sharedMem = (PVOID)0x42000000;
	std::cout << VirtualAlloc(sharedMem, 0x100, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE) << std::endl;

	std::string processName;
	std::cout << "Name: ";
	std::cin >> processName;
	UINT32 pid = getPid(processName);
	UINT64 base = (UINT64)modBase(pid, processName);
	UINT64 entityList = base + 0x18ad3a8;

	UINT64 local_player = rpm<UINT64>(pid, base + 0x1C5BCC8);

	UINT32 local_team_num = rpm<UINT32>(pid, local_player + 0x430);
	printf("Team num: %u\n", local_team_num);

	UINT8 local_life_state;

	while (!rpm<UINT8>(pid, local_player + 0x770)) { // While alive
		for (int i = 1; i < 100; i++) {
			UINT64 ent = rpm<UINT64>(pid, entityList + 0x20 * i);

			if (!ent || ent == local_player) {
				//printf("Invalid entity pointer\n");
				continue;
			}

			//UINT64 entSigName = rpm<UINT64>(pid, ent + 0x558);
			//if (entSigName != 0x1b488f277a0) {//0x726579616c70) {
			//	printf("Sig name did not match: %llx\n", entSigName);
			//	continue;
			//}
			

			UINT8 life_state = rpm<UINT8>(pid, ent + 0x770);
			if (life_state) {
				printf("entity is dead\n");
				continue;
			}

			UINT32 bleedout_state = rpm<UINT32>(pid, ent + 0x2610);
			if (bleedout_state) {
				printf("entity is downed\n");
				continue;
			}

			UINT32 health = rpm<UINT32>(pid, ent + 0x420);
			if (health < 1 || health > 100) {
				printf("entity has no/invalid health\n");
				continue;
			}

			UINT32 team_num = rpm<UINT32>(pid, ent + 0x430);
			if (team_num == local_team_num || team_num < 1 || team_num > 50) {
				printf("entity is not in enemy team\n");
				continue;
			}

			wpm<UINT32>(pid, ent + 0x3e0, 1);
			wpm<UINT32>(pid, ent + 0x350, 1);

			Color c;
			c.r = 0.04f * colors[team_num % 20][0];
			c.g = 0.04f * colors[team_num % 20][1];
			c.b = 0.04f * colors[team_num % 20][2];
			wpm(pid, ent + 0x1b8 + 24, &c, sizeof(c));
			std::array<float, 7> inf = { INFINITY, INFINITY, INFINITY, INFINITY, INFINITY, INFINITY, INFINITY };
			wpm(pid, ent + 0x310, inf.data(), sizeof(inf));
			wpm<float>(pid, ent + 0x33C, 2000.f);
		}

		Sleep(3000);
	}

	/*while (true) {
		std::string action;
		std::cin >> action;

		if (!action.compare("r4")) {
			UINT32 pid;
			std::cout << "PID: ";
			std::cin >> std::dec >> pid;
			UINT64 virtAddr;
			std::cout << "Virtual Address: ";
			std::cin >> std::hex >> virtAddr;
			UINT32 buffer;

			std::cout << "PID: " << std::dec << pid << " Virtual Address: " << std::hex << virtAddr << std::endl;
			buffer = rpm<UINT32>(pid, virtAddr);

			std::cout << std::hex << buffer << std::endl;
		}
		else if (!action.compare("r8")) {
			UINT32 pid;
			std::cout << "PID: ";
			std::cin >> std::dec >> pid;
			UINT64 virtAddr;
			std::cout << "Virtual Address: ";
			std::cin >> std::hex >> virtAddr;
			UINT64 buffer;

			std::cout << "PID: " << std::dec << pid << " Virtual Address: " << std::hex << virtAddr << std::endl;
			buffer = rpm<UINT64>(pid, virtAddr);

			std::cout << std::hex << buffer << std::endl;
		}
		else if (!action.compare("w")) {
			UINT32 pid;
			std::cout << "PID: ";
			std::cin >> std::dec >> pid;
			UINT64 virtAddr;
			std::cout << "Virtual Address: ";
			std::cin >> std::hex >> virtAddr;
			UINT32 buffer;
			std::cout << "Data: ";
			std::cin >> std::dec >> buffer;

			std::cout << "PID: " << std::dec << pid << " Virtual Address: 0x" << std::hex << virtAddr << " Data: 0x" << std::dec << buffer << std::endl;
			wpm<UINT32>(pid, virtAddr, buffer);
		}
		else if (!action.compare("modbase")) {
			UINT32 pid;
			std::string moduleName;

			std::cout << "PID: ";
			std::cin >> std::dec >> pid;
			std::cout << "module name: ";
			std::cin >> moduleName;

			std::cout << "Base: " << std::hex << modBase(pid, moduleName) << std::endl;
		}
		else if (!action.compare("getpid")) {
			std::string processName;

			std::cout << "process name: ";
			std::cin >> processName;

			std::cout << "PID: " << std::dec << getPid(processName) << std::endl;
		}
		else if (!action.compare("exit")) {
			break;
		}

	}*/

	return CloseHandle(pipe);
}