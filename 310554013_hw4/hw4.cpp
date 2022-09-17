#include<iostream>
#include<sstream>
#include <fstream>
#include"hw4.h"
#include"hw4_elf.h"
#include<string>
#include<vector>
#include<cstring>
#include<sys/ptrace.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <capstone/capstone.h>
#include <iomanip>
#include <algorithm>
#include <sys/user.h>
using namespace std;
elfhandle_t* e = (elfhandle_t*)calloc(1, sizeof(elfhandle_t));
state_t state = OTHERS;
string program;
vector<string>cmd;
Elf64_Shdr text;
int child;
vector<breakpoint_t>bps;
char* code = NULL;
int code_size;
unsigned long long rip_now = 0;
ifstream fin;
int file_flag = 0;
void error_quit(string msg)
{
    cout << msg << endl;
    close_elf(e);
    exit(-1);
}

void load(const char* file){
    if(state == LOADED){
        cout << "** program has already been loaded." << endl;
        return;
    }
    int ret;
    ret = open_elf(e, file);
    if(ret==0){
        load_elf(e);
        state = LOADED;
        cout << "** program '" << file << "' loaded. entry point 0x" << hex << e->entry << dec << endl;
        program = file;
    }
    else{
        error_quit("** unable to load '" + string(file) + "'.");
    }
    //find string name section table 
    strtab_t* tab;
    for(tab = e->strtab; tab != NULL; tab = tab->next)
        if(tab->id == e->sh_stridx)
            break;
    //find text section
    for(int i = 0; i < e->sh_cnt; i++)
        if(!strcmp(&tab->data[e->shdr[i].sh_name], ".text")) 
        {
            text = e->shdr[i];
            break;
        }
}

void parse_args(const int argc, const char *argv[]){
    if(argc>=2){
        if(string(argv[1]) == "-s")
        {
            // source = SCRIPT;
            fin.open(argv[2]);
            file_flag = 1;
            if(argc > 3)
            {
                load(argv[3]);
            }
        }
        else{
            load(argv[1]);
        }
    }
    return;
}

void init_regs_map(){
    return;
}

vector<string> parse_cmd(string line){
    vector<string> vec_str;
    string temp;
    stringstream ss;
    ss<<line;
    while (ss>>temp)
        vec_str.push_back(temp);
    return vec_str;
}

void start(){
    if (state == OTHERS){
        cout<<"** not yet loaded"<<endl;
        return;
    }
    else if (state == RUNNING){
        kill(child, SIGTERM); // SIGKILL, SIGINT
        child = 0;
    }
    bps.clear();
    child = fork();
    if (child < 0){
        error_quit("** fork error");
    }
    else if (child==0){
        if(ptrace(PTRACE_TRACEME, 0, 0, 0)<0){
            error_quit("** PTRACE_TRACEME error");
        }
        char* argv[] = {NULL};
        if(program.c_str()[0]!='.' && program.c_str()[1]!='/'){
            string s = "./"+program;
            program = s;
        }
        execvp(program.c_str(), argv);
    }
    else{
        int stat;
        if (waitpid(child, &stat, 0)<0){
            error_quit("** waitpid error");
        }
        ptrace(PTRACE_SETOPTIONS, 0, child, PTRACE_O_EXITKILL);
        cout<< "** pid "<<child<<endl;
        state = RUNNING;
    }


}

void getcode(){
    ifstream f(program.c_str(), ios::in | ios::binary | ios::ate);
    streampos size = f.tellg();
    code = new char [size+1L];
    f.seekg(0, ios::beg);
    f.read(code, size);
    f.close();
    code[size]=0;
    // return size;
}

string disasmembly(char* pos, long long* addr){
    csh handle;
	cs_insn *insn;
	size_t count;
    string instruction="";
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
        error_quit("** cs_open error");
    count = cs_disasm(handle, (uint8_t*)pos, 256, *addr, 0, &insn);
    // cout<<count<<endl;
	if (count > 0) {
        string toprint, tmp;
        stringstream ss;
        // cout<<insn[0].size<<endl;
		for (int j = 0; j < insn[0].size; j++) {
            stringstream sss;
            int val = int(insn[0].bytes[j]);
            sss << hex << setw(2) << setfill('0') << val;
            sss >> tmp;
            toprint += tmp + " ";
            // cout<<toprint<<endl;
		}
        ss << "\t" << hex << insn[0].address << dec << ": " << hex << toprint
             << dec << "\t\t" << insn[0].mnemonic << "\t" << insn[0].op_str << endl;
        *addr += insn[0].size;
        // cout<<*addr<<endl;
        instruction = ss.str();
        cs_free(insn, count);
	} 
    else
		error_quit("** cs_disasm error.");

	cs_close(&handle);
    return instruction;
}

void disasm(string assm_addr, int length){
    if (code == NULL){
        getcode();
    }
    long long addr= strtoll(assm_addr.c_str(), NULL, 16);
    for (int i=0;i<length;i++){
        if (addr >= (text.sh_addr + text.sh_size)){
            break;
        }
        long long offset = (addr - text.sh_addr) + text.sh_offset;
        char* pos  = code+offset;
        cout<<disasmembly(pos, &addr);
    }
    // cout<<"** the address is out of the range of the text segment"<<endl;
}

void help()
{
    cout << "- break {instruction-address}: add a break point" << endl;
    cout << "- cont: continue execution" << endl;
    cout << "- delete {break-point-id}: remove a break point" << endl;
    cout << "- disasm addr: disassemble instructions in a file or a memory region" << endl;
    cout << "- dump addr [length]: dump memory content" << endl;
    cout << "- exit: terminate the debugger" << endl;
    cout << "- get reg: get a single value from a register" << endl;
    cout << "- getregs: show registers" << endl;
    cout << "- help: show this message" << endl;
    cout << "- list: list break points" << endl;
    cout << "- load {path/to/a/program}: load a program" << endl;
    cout << "- run: run the program" << endl;
    cout << "- vmmap: show memory layout" << endl;
    cout << "- set reg val: get a single value to a register" << endl;
    cout << "- si: step into instruction" << endl;
    cout << "- start: start the program and stop at the first instruction" << endl;
}


void vmmap(){
    ifstream f("/proc/"+to_string(child)+"/maps");
    string line;
    while(getline(f,line)){
        stringstream ss(line);
        string s;
        ss>>s;
        replace(s.begin(), s.end(), '-', ' ');
        stringstream sss;
        string address1, address2, perms, offset, dev, inode, pathname;
        sss<<s;
        sss>>address1;
        sss>>address2;
        ss>>perms;
        // cout<<perms<<endl;
        perms.erase(perms.find("p"),1);
        ss>>offset;
        ss>>dev;
        ss>>inode;
        ss>>pathname;
        cout << setw(16) << setfill('0') << address1 << "-" << setw(16) << setfill('0') << address2 << "\t"<<perms<<"\t"<<inode<<"\t"<<pathname<<endl;
        
    }
}

void get(string reg){
    unsigned long long value;
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, child, 0, &regs)==-1){
        error_quit("** PTRACE_GETREGS error.");
    }
    if(reg=="rax")      value = regs.rax;
    else if(reg=="rbx") value = regs.rbx;
    else if(reg=="rcx") value = regs.rcx;
    else if(reg=="rdx") value = regs.rdx;
    else if(reg=="r8")  value = regs.r8;
    else if(reg=="r9")  value = regs.r9;
    else if(reg=="r10") value = regs.r10;
    else if(reg=="r11") value = regs.r11;
    else if(reg=="r12") value = regs.r12;
    else if(reg=="r13") value = regs.r13;
    else if(reg=="r14") value = regs.r14;
    else if(reg=="r15") value = regs.r15;
    else if(reg=="rdi") value = regs.rdi;
    else if(reg=="rsi") value = regs.rsi;
    else if(reg=="rbp") value = regs.rbp;
    else if(reg=="rsp") value = regs.rsp;
    else if(reg=="rip") value = regs.rip;
    else if(reg=="flags") value = regs.eflags;
    else{
        cout<<"**   [reg] is not found!\n";
        return;
    }
    cout<<reg<<" = "<<dec<<value<<" (0x"<<hex<<value<<")\n";

}

void set(string reg, unsigned long long val){
    // unsigned long long int value;
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, child, 0, &regs)==-1){
        error_quit("** PTRACE_GETREGS error.");
    }
    if(reg=="rax")      regs.rax = val;
    else if(reg=="rbx") regs.rbx = val;
    else if(reg=="rcx") regs.rcx = val;
    else if(reg=="rdx") regs.rdx = val;
    else if(reg=="r8")  regs.r8 = val;
    else if(reg=="r9")  regs.r9 = val;
    else if(reg=="r10") regs.r10 = val;
    else if(reg=="r11") regs.r11 = val;
    else if(reg=="r12") regs.r12 = val;
    else if(reg=="r13") regs.r13 = val;
    else if(reg=="r14") regs.r14 = val;
    else if(reg=="r15") regs.r15 = val;
    else if(reg=="rdi") regs.rdi = val;
    else if(reg=="rsi") regs.rsi = val;
    else if(reg=="rbp") regs.rbp = val;
    else if(reg=="rsp") regs.rsp = val;
    else if(reg=="rip") regs.rip = val;
    else if(reg=="flags") regs.eflags = val;
    else    cout<<"**   [reg] is not found!\n";
    if(ptrace(PTRACE_SETREGS, child, 0, &regs) != 0) error_quit("** PTRACE_SETREGS error");

}



void breakpoint(string s_address){
    unsigned long address = strtoul(s_address.c_str(), NULL, 16);
    unsigned long code = ptrace(PTRACE_PEEKTEXT, child, address, 0);
    if((code & 0xff)==0xcc) //already set bp
        return;
    if(ptrace(PTRACE_POKETEXT, child, address, (code & 0xffffffffffffff00) | 0xcc) != 0)
        error_quit("** PTRACE_POKETEXT error");
    for (int i=0;i<(int)bps.size();i++){
        if (bps[i].addr == address){
            return;
        }
    }
    breakpoint_t bp;
    bp.addr = address;
    // cout<<address<<endl;
    bp.s_addr = s_address;
    bp.id = bps.size();
    bp.ori_code = code;
    bps.push_back(bp);
    cout<<"**   set bp @ ";
    disasm(s_address, 1);
    // cout<<"**   set bp @ "; 

}

void checkbp(){
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, child, 0, &regs)!=0){
         error_quit("** PTRACE_GETREGS error");
    }
    for(int i=0;i<(int)bps.size();i++){
        if(bps[i].addr>regs.rip){
            breakpoint(bps[i].s_addr);
        }
    }
}

void checkstate(){
    int status;
    if (waitpid(child, &status, 0)<0){
        error_quit("** waitpid error");
    }
    if(WIFEXITED(status)){
        if(WIFSIGNALED(status))
            cout<<"** child process "<<dec<<child<<" terminiated by signal (code"<<WTERMSIG(status)<<")"<<endl;
        else
            cout<<"** child process "<<dec<<child<<" terminiated normally (code "<<status<<")"<<endl;
        child = 0;
        state = LOADED;
    }
    if ( WIFSTOPPED(status)){
        if(WSTOPSIG(status)==SIGTRAP){
            struct user_regs_struct regs;
            if(ptrace(PTRACE_GETREGS, child, 0,&regs)!=0){
                // cout<<1<<endl;
                error_quit("** PTRACE_GETREGS error");
            }
            // cout<<"here"<<endl;
            for(int i=0;i<(int)bps.size();i++){
                // cout<<"bps[i].addr : "<<bps[i].addr<<endl;
                // cout<<regs.rip<<endl;
                // cout<<"regs.rip-1 : "<<regs.rip-1<<endl;
                
                if (bps[i].addr == regs.rip-1 ){
                    cout<<"** breakpoint @";
                    disasm(bps[i].s_addr, 1);
                    if(ptrace(PTRACE_POKETEXT, child, bps[i].addr, bps[i].ori_code) != 0){
                        error_quit("** PTRACE_POKETEXT error");
                    }
                    regs.rip--;
                    if(ptrace(PTRACE_SETREGS, child, 0, &regs) != 0) {
                        error_quit("** PTRACE_SETREGS error");
                    }
                }
            }
        }
        else{
            cout<<"** child process "<<child<<" terminiated by signal (code"<<WSTOPSIG(status)<<")"<<endl;
        }
    }
}
void cont(){
    checkbp();
    if(ptrace(PTRACE_CONT, child, 0, 0)<0)    error_quit("** PTRACE_CONT error");
    checkstate();
}

void si(){
    checkbp();
    if(ptrace(PTRACE_SINGLESTEP, child, 0, 0)<0){
        error_quit("** PTRACE_SINGLESTEP error");
    }
    checkstate();
}

void run(){
    if (state == RUNNING){
        // error_quit("** program is running now.");
        cout<<"** program "<<program<<" is running now."<<endl;
        cont();
        return;
    }
    else if (state == LOADED){
        start();
        cont();
    }
    else
    {
        cout << "** not in loaded or running state." << endl;
        return;
    }
}


void getregs(){
    struct user_regs_struct regs;
    if(ptrace(PTRACE_GETREGS, child, 0, &regs)!=0){
        error_quit("** PTRACE_CONT error");
    }
    cout<<hex
        <<left<<setw(7)<<"RAX: "   <<left<<setw(10)<<regs.rax   <<"\t"
        <<left<<setw(7)<<"RBX: "   <<left<<setw(10)<<regs.rbx  <<"\t"
        <<left<<setw(7)<<"RCX: "   <<left<<setw(10)<<regs.rcx  <<"\t"
        <<left<<setw(7)<<"RDX: "   <<left<<setw(10)<<regs.rdx  <<endl
        <<left<<setw(7)<<"R8: "    <<left<<setw(10)<<regs.r8   <<"\t"
        <<left<<setw(7)<<"R9: "    <<left<<setw(10)<<regs.r9   <<"\t"
        <<left<<setw(7)<<"R10: "   <<left<<setw(10)<<regs.r10  <<"\t"
        <<left<<setw(7)<<"R11: "   <<left<<setw(10)<<regs.r11  <<endl
        <<left<<setw(7)<<"R12: "   <<left<<setw(10)<<regs.r12  <<"\t"
        <<left<<setw(7)<<"R13: "   <<left<<setw(10)<<regs.r13  <<"\t"
        <<left<<setw(7)<<"R14: "   <<left<<setw(10)<<regs.r14  <<"\t"
        <<left<<setw(7)<<"R15: "   <<left<<setw(10)<<regs.r15  <<endl
        <<left<<setw(7)<<"RDI: "   <<left<<setw(10)<<regs.rdi  <<"\t"
        <<left<<setw(7)<<"RSI: "   <<left<<setw(10)<<regs.rsi  <<"\t"
        <<left<<setw(7)<<"RBP: "   <<left<<setw(10)<<regs.rbp  <<"\t"
        <<left<<setw(7)<<"RSP: "   <<left<<setw(10)<<regs.rsp  <<endl
        <<left<<setw(7)<<"RIP: "   <<left<<setw(10)<<regs.rip  <<"\t"
        <<left<<setw(7)<<"FLAGS: " <<left<<setw(16)<<setfill('0')<<right<<regs.eflags<<endl;
    cout<<setfill(' ');
}

void exit(){
    if(child != 0)
        kill(child, SIGTERM);
    close_elf(e);
    exit(0);
}

void list_bps(){
    for(int i=0;i<(int)bps.size();i++)
        cout<<"\t"<<bps[i].id<<":\t"<<hex<<bps[i].addr<<endl;
}

void reindex(int id){
    for(int i=id;i<int(bps.size());i++)
        bps[i].id-=1;
}

void del(string s_id){
    if (state != RUNNING){
        error_quit("** program is not running.");
        // return;
    }
    int id = stoi(s_id);
    int idx;
    for(idx=0;idx<(int)bps.size();idx++){
        if (bps[idx].id==id){
            cout<<"**   del bp @ ";
            disasm(bps[idx].s_addr, 1);
            if(ptrace(PTRACE_POKETEXT, child, bps[idx].addr, bps[idx].ori_code) != 0)
                error_quit("** PTRACE_POKETEXT error");
            bps.erase(bps.begin()+id);
            reindex(id);
            return ;
        }
    }
    cout<<"** bp id is not found!\n";
}

void dump(unsigned long addr){
    if (text.sh_addr>addr || text.sh_addr+text.sh_size<addr){
        cout<<"**   Addr out of text region!"<<endl;
        // return;
    }
    unsigned long code0,code8;
    for(int i=0;i<5;i++, addr+=16){
        code0 = ptrace(PTRACE_PEEKTEXT, child, addr, 0);
        code8 = ptrace(PTRACE_PEEKTEXT, child, addr+8, 0);
        cout<<hex<<setw(12)<<setfill(' ')<<right<<addr<<": ";
        for(int idx=0; idx<8; idx++)
            cout<<hex<<setw(2)<<setfill('0')<<(int)((unsigned char *) (&code0))[idx]<<" ";
        cout<<setfill(' ');
        for(int idx=0; idx<8; idx++)
            cout<<hex<<setw(2)<<setfill('0')<<(int)((unsigned char *) (&code8))[idx]<<" ";
        cout<<setfill(' ');
        for(int i=0; i<8; i++){
            if(isprint((int)((char *) (&code0))[i]))
                cout<<((char *) (&code0))[i];
            else
                cout<<".";
        }
        for(int i=0; i<8; i++){
            if(isprint((int)((char *) (&code8))[i]))
                cout<<((char *) (&code8))[i];
            else
                cout<<".";
        }
        cout<<"|"<<endl;

    }

}


void quit_exit()
{
    if(child != 0)
        kill(child, SIGTERM);
    close_elf(e);
}

int main(const int argc, const char *argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);
    init_regs_map();
    //parse args
    bool eof_flag = false;
    parse_args(argc, argv);
    while (true){
        string line;
        if(file_flag==0){
            cout<< "sdc> ";
            if(!getline(cin, line)){
            eof_flag = true;
        }
        }
        else{
            if(!getline(fin,line)){
                eof_flag = true;
            }
        }
        if (eof_flag){
            break;
        }
        cmd = parse_cmd(line);
        if (cmd.empty()){
            continue;
        }
        else if (cmd[0]=="load" && cmd.size()==2){
            /* code */
            load(cmd[1].c_str());
        }
        else if (cmd[0]=="start"){
            start();
        }
        else if (cmd[0]=="disasm" || cmd[0]=="d"){
            if(state != RUNNING){
                cout << "** program is not running." << endl;
            }
            else if (cmd.size()==1){
                cout<<"** no addr is given."<<endl;
            }
            else if (cmd.size()==2){
                disasm(cmd[1], 10);//16
            }
        }
        else if (cmd[0]=="help" || cmd[0]=="h"){
            if(cmd.size()==1){
                help();
            }
            else if (cmd.size()==2){
                help();
            }
        }
        else if (cmd[0]=="vmmap" || cmd[0]=="m"){
            if(state != RUNNING){
                cout << "** program is not running." << endl;
            }
            else
                vmmap();
        }
        else if (cmd[0]=="get" || cmd[0]=="g"){
            if(state != RUNNING){
                cout << "** program is not running." << endl;
            }
            else if(cmd.size()==2)
                get(cmd[1]);
        }
        else if (cmd[0]=="run" || cmd[0]=="r"){
            if(cmd.size()==1)
                run();
        }
        else if (cmd[0]=="break" || cmd[0]=="b"){
            // cout<<strtoull(cmd[1].c_str(), NULL, 16);
            if(state != RUNNING){
                cout << "** program is not running." << endl;
            }
            else if (cmd.size()==2)
                breakpoint(cmd[1]);
        }
        else if (cmd[0]=="cont" || cmd[0]=="c"){
            if(state != RUNNING){
                cout << "** program is not running." << endl;
            }
            else if (cmd.size()==1)
                cont();
        }
        else if (cmd[0]=="getregs"){
            if(state != RUNNING){
                cout << "** program is not running." << endl;
            }
            else if(cmd.size()==1)
                getregs();
        }
        else if (cmd[0]=="si"){
            if(state != RUNNING){
                cout << "** program is not running." << endl;
            }
            else if(cmd.size()==1)
                si();
        }
        else if (cmd[0]=="exit" || cmd[0]=="q"){
            if(cmd.size()==1)
                exit();
        }
        else if (cmd[0]=="list" || cmd[0]=="l"){
            if(cmd.size()==1)
                list_bps();
        }
        else if (cmd[0]=="set" || cmd[0]=="s"){
            if(state != RUNNING){
                cout << "** program is not running." << endl;
            }
            else if(cmd.size()==3)
                set(cmd[1], strtoull(cmd[2].c_str(), NULL, 16));
        }
        else if (cmd[0]=="delete"){
            if(state != RUNNING){
                cout << "** program is not running." << endl;
            }
            else if(cmd.size()==2)
                del(cmd[1]);
        }
        else if (cmd[0]=="dump"){
            if(state != RUNNING){
                cout << "** program is not running." << endl;
            }
            else if (cmd.size()==2){
                dump(strtoul(cmd[1].c_str(), NULL, 16));
            }
        }
        cmd.clear();
    }
    
    quit_exit();
    return 0;
}