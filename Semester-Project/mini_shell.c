// mini_shell.cpp
// Mini Linux Shell for beginners with colorful kpcb output and detailed PCB info
// Compile: g++ -std=c++17 -o mini_shell mini_shell.cpp

#include <bits/stdc++.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <dirent.h>
#include <fcntl.h>

using namespace std;

// ANSI Colors
#define GREEN  "\033[1;32m"
#define YELLOW "\033[1;33m"
#define BLUE   "\033[1;34m"
#define RED    "\033[1;31m"
#define RESET  "\033[0m"

static const char* PROMPT_SYMBOL = "mini-shell> ";

// ---------------- Helper Functions ----------------
vector<string> tokenize(const string &line) {
    vector<string> tokens;
    string token;
    istringstream iss(line);
    while (iss >> token) tokens.push_back(token);
    return tokens;
}

char** make_exec_args(const vector<string>& tokens) {
    char** argv = new char*[tokens.size() + 1];
    for (size_t i = 0; i < tokens.size(); ++i)
        argv[i] = strdup(tokens[i].c_str());
    argv[tokens.size()] = nullptr;
    return argv;
}

void free_exec_args(char** argv, size_t n) {
    for (size_t i = 0; i < n; ++i) free(argv[i]);
    delete[] argv;
}

bool read_proc_statm(pid_t pid, long &vm_kb, long &rss_kb) {
    string path = "/proc/" + to_string(pid) + "/statm";
    ifstream f(path);
    if (!f.is_open()) return false;
    long size_pages = 0, rss_pages = 0;
    f >> size_pages >> rss_pages;
    long page_size_kb = sysconf(_SC_PAGESIZE) / 1024;
    vm_kb = size_pages * page_size_kb;
    rss_kb = rss_pages * page_size_kb;
    return true;
}

vector<pair<int,string>> list_open_fds(pid_t pid) {
    vector<pair<int,string>> fds;
    string path = "/proc/" + to_string(pid) + "/fd";
    DIR *d = opendir(path.c_str());
    if (!d) return fds;
    struct dirent *entry;
    while ((entry = readdir(d)) != nullptr) {
        if (entry->d_name[0] == '.') continue;
        int fd = atoi(entry->d_name);
        string linkpath = path + "/" + entry->d_name;
        char buf[4096];
        ssize_t len = readlink(linkpath.c_str(), buf, sizeof(buf)-1);
        if (len != -1) {
            buf[len] = '\0';
            fds.emplace_back(fd, string(buf));
        } else fds.emplace_back(fd, "unknown");
    }
    closedir(d);
    sort(fds.begin(), fds.end(), [](auto &a, auto &b){ return a.first < b.first; });
    return fds;
}

// ---------------- Resource Usage ----------------
struct ResourceSnapshot {
    double utime_sec;
    double stime_sec;
    long max_rss_kb;
};
ResourceSnapshot get_resource_snapshot_of_children() {
    struct rusage usage;
    ResourceSnapshot snap{0,0,0};
    if (getrusage(RUSAGE_CHILDREN, &usage) == 0) {
        snap.utime_sec = usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1e6;
        snap.stime_sec = usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1e6;
        snap.max_rss_kb = usage.ru_maxrss;
    }
    return snap;
}

// ---------------- Simulated PCB ----------------
struct SimulatedPCB {
    pid_t pid;
    pid_t ppid;
    string state;
    void* stack_ptr;
    void* ret_addr;
    time_t timestamp;
    SimulatedPCB(): pid(0), ppid(0), state("unknown"), stack_ptr(nullptr), ret_addr(nullptr), timestamp(0) {}
};

SimulatedPCB capture_simulated_pcb() {
    SimulatedPCB pcb;
    pcb.pid = getpid();
    pcb.ppid = getppid();
    pcb.state = "Running (user-space snapshot)";
    int local_var = 42;
    pcb.stack_ptr = (void*) &local_var;
    pcb.ret_addr = __builtin_return_address(0);
    pcb.timestamp = time(nullptr);
    return pcb;
}

void print_simulated_pcb(const SimulatedPCB &pcb) {
    cout << "---- Simulated PCB Snapshot ----\n";
    cout << "PID: " << pcb.pid << "  PPID: " << pcb.ppid << "\n";
    cout << "State: " << pcb.state << "\n";
    cout << "Timestamp: " << ctime(&pcb.timestamp);
    cout << "Stack pointer (proxy): " << pcb.stack_ptr << "\n";
    cout << "Return address (proxy for PC): " << pcb.ret_addr << "\n";
    cout << "--------------------------------\n";
}

void print_resource_usage_for_pid(pid_t pid) {
    long vm_kb = 0, rss_kb = 0;
    if (read_proc_statm(pid, vm_kb, rss_kb)) {
        cout << "Memory (proc/statm): VM = " << vm_kb << " KB, RSS = " << rss_kb << " KB\n";
    } else {
        cout << "Memory info: /proc/" << pid << "/statm not available\n";
    }

    auto fds = list_open_fds(pid);
    cout << "Open file descriptors (" << fds.size() << "):\n";
    for (auto &p : fds) {
        cout << "  fd " << p.first << " -> " << p.second << "\n";
    }
}

// ------------------- KPCB Helpers -------------------
struct PCBInfo {
    int pid;
    long long user_cpu;
    long long system_cpu;
    long long vm_size;
    long long rss;
    bool is_kernel_thread;
    int ppid;
    string state; // Running, Sleeping, etc.
    long long total_cpu() const { return user_cpu + system_cpu; }
};

    string get_process_state(int pid) {
    string path = "/proc/" + to_string(pid) + "/status";
    ifstream f(path);
    if (!f.is_open()) return "Unknown";
    string line;
    while (getline(f, line)) {
        if (line.rfind("State:", 0) == 0) {
            char s = line[7];
            switch (s) {
                case 'R': return GREEN "Running" RESET;
                case 'S': return YELLOW "Sleeping" RESET;
                case 'D': return "Disk sleep";
                case 'Z': return RED "Zombie" RESET;
                case 'T': return "Stopped";
                case 't': return "Tracing stop";
                case 'X': return "Dead";
                case 'K': return "Wakekill";
                case 'W': return "Waking";
                default: return "Unknown";
            }
        }
    }
    return "Unknown";
}

vector<PCBInfo> read_pcb() {
    vector<PCBInfo> list;
    ifstream file("/proc/realpcb");
    if (!file.is_open()) { cout << RED << "Error: Cannot open /proc/realpcb\n" << RESET; return list; }

    string line;
    PCBInfo pcb;
    while (getline(file, line)) {
        if (line == "1") continue;
        if (line.rfind("PID:",0)==0) { 
            pcb = PCBInfo(); 
            pcb.pid = stoi(line.substr(5)); 
            pcb.ppid = 0; 
            pcb.state = get_process_state(pcb.pid);
        }
        else if (line.rfind("PPID:",0)==0) pcb.ppid = stoi(line.substr(6));
        else if (line.rfind("CPU user:",0)==0) {
            stringstream ss(line.substr(10));
            ss >> pcb.user_cpu; ss.ignore(10); ss >> pcb.system_cpu;
        }
        else if (line.find("Kernel thread") != string::npos) { 
            pcb.is_kernel_thread = true; pcb.vm_size = pcb.rss = 0; list.push_back(pcb); 
        }
        else if (line.rfind("VM size:",0)==0) { 
            pcb.is_kernel_thread = false; 
            stringstream ss(line.substr(9)); 
            ss >> pcb.vm_size; ss.ignore(10); ss >> pcb.rss; 
            list.push_back(pcb); 
        }
    }
    return list;
}

void display_pcb(const vector<PCBInfo> &list, bool only_user, bool only_kernel, bool memory_mode=false) {
    long long total_vm=0, total_rss=0, total_user_cpu=0, total_sys_cpu=0;
    for (auto &p : list) {
        if (only_user && p.is_kernel_thread) continue;
        if (only_kernel && !p.is_kernel_thread) continue;

        total_user_cpu += p.user_cpu; total_sys_cpu += p.system_cpu;
        if (!p.is_kernel_thread) { total_vm += p.vm_size; total_rss += p.rss; }

        if (memory_mode) continue; // skip details for -m

        if (p.is_kernel_thread) cout << YELLOW; else cout << GREEN;

        cout << "------------------------------\n";
        cout << "PID: " << p.pid << "  PPID: " << p.ppid << "\n";
        cout << "Type: " << (p.is_kernel_thread ? "Kernel Thread" : "User Thread") << "\n";
        cout << "State: " << p.state << "\n";
        cout << "CPU: " << p.user_cpu << " ns (user) + " << p.system_cpu << " ns (system)\n";
        if (!p.is_kernel_thread) cout << "VM: " << p.vm_size << " KB  RSS: " << p.rss << " KB\n";
        cout << "------------------------------" << RESET << "\n";
    }

    // Always show summary
    cout << "\n===== CPU SUMMARY =====\n";
    cout << "Total User CPU: " << total_user_cpu << " ns\n";
    cout << "Total System CPU: " << total_sys_cpu << " ns\n";

    cout << "\n===== MEMORY SUMMARY =====\n";
    cout << "Total VM: " << total_vm << " KB\n";
    cout << "Total RSS: " << total_rss << " KB\n";
}

void handle_kpcb_command(const vector<string>& tokens) {
    bool only_user=false, only_kernel=false, memory_mode=false;
    for (auto &tok : tokens) {
        if (tok=="-u") only_user=true;
        else if (tok=="-k") only_kernel=true;
        else if (tok=="-m") memory_mode=true;
    }
    auto list = read_pcb();
    display_pcb(list, only_user, only_kernel, memory_mode);
}

// ------------------- Builtin -------------------
bool handle_builtin(const vector<string>& tokens) {
    if (tokens.empty()) return true;
    if (tokens[0]=="exit") { cout << "Exiting mini shell.\n"; exit(0); }
    else if (tokens[0]=="cd") {
        string dir = (tokens.size()>=2) ? tokens[1] : (getenv("HOME")?getenv("HOME"):"/");
        if (chdir(dir.c_str())!=0) perror("cd");
        return true;
    }
    else if (tokens[0]=="pcb") { print_simulated_pcb(capture_simulated_pcb()); return true; }
    else if (tokens[0]=="resources") { print_resource_usage_for_pid(getpid()); return true; }
    else if (tokens[0]=="kpcb") { handle_kpcb_command(tokens); return true; }
    else if (tokens[0]=="help") {
        cout << BLUE << "Available commands:\n"
             << "cd [dir]      - change directory\n"
             << "exit          - exit shell\n"
             << "pwd           - print working directory\n"
             << "ls            - list directory contents\n"
             << "pcb           - show simulated PCB snapshot\n"
             << "resources     - show memory + open fds\n"
             << "kpcb [-u|-k|-m]- show kernel/user threads + summary\n"
             << "help          - show this message\n" << RESET;
        return true;
    }
    return false;
}

// ------------------- Execute External -------------------
void execute_external(vector<string> tokens) {
    if (tokens.empty()) return;
    pid_t pid=fork();
    if (pid<0) { perror("fork"); return; }
    else if (pid==0) {
        char** argv=make_exec_args(tokens);
        if (execvp(argv[0],argv)==-1) { perror("execvp"); free_exec_args(argv,tokens.size()); exit(EXIT_FAILURE); }
    }
    else { int status; waitpid(pid,&status,0); }
}

// ------------------- MAIN -------------------
int main() {
    cout << GREEN
         << "\n===========================================================\n"
         << "                      WELCOME TO MINISHELL               \n"
         << "-----------------------------------------------------------\n"
         << "     Created by Sharaiz Ahmed [57288] & Abdul Moiz [54482]   \n"
         << "     BSCS 5-1, Riphah International University             \n"
         << "     Semester Project for OS under Sir Zeeshan Ali          \n"
         << "===========================================================\n\n" << RESET;

    while (true) {
        char cwd[4096];
        if (getcwd(cwd,sizeof(cwd))) cout << cwd << " " << PROMPT_SYMBOL;
        else cout << PROMPT_SYMBOL;

        string line;
        if (!getline(cin,line)) { cout << "\n"; break; }
        if (line.empty()) continue;

        auto tokens=tokenize(line);
        if (tokens.empty()) continue;

        if (handle_builtin(tokens)) continue;
        execute_external(tokens);
    }
    return 0;
}
