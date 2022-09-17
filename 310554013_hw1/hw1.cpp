#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <iostream>
#include <algorithm>
#include <set>
#include <iomanip>
#include <utility>
#include <regex>
#include <map>
#include <errno.h>
using namespace std;


std::map<std::string, std::string> filter;

std::string find_inode_by_socket_symlink (char* symlink) {
  std::string inode;
  std::string s = std::string(symlink);
  unsigned int inode_tmp;
  std::regex reg("socket:\[[0-9]*]"); // ex: socket:[123]
 
  if (std::regex_match(s.begin(), s.end(), reg))
    sscanf(s.substr(8, s.length()-9).c_str(), "%u", &inode_tmp);
  inode = std::to_string(inode_tmp);
  return inode;
}

std::string find_inode_by_pipe_symlink (char* symlink) {
  std::string inode;
  std::string s = std::string(symlink);
  unsigned int inode_tmp;
  std::regex reg("pipe:\[[0-9]*]"); // ex: pipe:[123]
 
  if (std::regex_match(s.begin(), s.end(), reg))
    sscanf(s.substr(6, s.length()-7).c_str(), "%u", &inode_tmp);
  inode = std::to_string(inode_tmp);
  return inode;
}

int get_inode (int fd)
{
    struct stat buf;
    int ret;
 
    ret = fstat(fd, &buf);
    if ( ret <0 ) {
         perror ("fstat");
         return -1;
    }
   
    return buf.st_ino;
}


void lsof()
{
    printf("%-16s%-16s%-16s%-16s%-16s%-16s%-30s\n", "COMMAND", "PID", "USER", "FD", "TYPE", "NODE", "NAME");
    std::set< std::string > map_info;
    // Open the /proc directory
    DIR *dp = opendir("/proc");
    DIR *dp2;


    if (dp != NULL)
    {
        // Enumerate all entries in directory until process found
        struct dirent *dirp, *dirp2;
        struct stat file_stat;
        struct passwd *p;
        int ret, n;
        //
        char *buf1, *buf2, *buf3, *buf4, *buf5, *buf6;
        ssize_t nbytes, bufsiz=128;
        // for mem
        FILE *fp;
        char *username, *tmp1, *tmp2, *tmp3, *tmp4, *inode, *pathname ;
        buf1=(char*)malloc(128);
        buf2=(char*)malloc(128);
        buf3= (char*)malloc(128);
        buf4 = (char*)malloc(128);
        buf5 = (char*)malloc(128);
        username = (char*)malloc(128);
        tmp1 = (char*)malloc(128);
        tmp2 = (char*)malloc(128);
        tmp3 = (char*)malloc(128);
        tmp4 = (char*)malloc(128);
        inode = (char*)malloc(128);
        pathname = (char*)malloc(128);
        char *mode =  (char*)malloc(100);
        char *link_path = (char*)malloc(100);
        char *sym_link = (char*)malloc(100);
        while ((dirp = readdir(dp)))
        {
            // Skip non-numeric entries
            int id = atoi(dirp->d_name);
            
            if (id > 0)
            {
                map_info.clear();
                memset(buf1, 0, 128);
                memset(buf2, 0, 128);
                memset(buf3, 0, 128);
                memset(buf4, 0, 128);

                // get user uid
                string dir_name = string("/proc/") + dirp->d_name;
                stat(dir_name.c_str(), &file_stat);
                gid_t uid = file_stat.st_uid;

                // find username
                dir_name = string("/etc/passwd");
                fp = fopen(dir_name.c_str(), "r");
                if (fp!=NULL){
                    while(fgets(buf1, 128, fp)!=NULL){
                        sscanf(buf1, "%[^':']:%[^':']:%[^':']:%[^':']", username, tmp2, tmp3, tmp4);
                        if (atoi(tmp3) == int(uid)){
                            // username = tmp1;
                            break;
                        }
                    }
                }
                fclose(fp);

                // // Read contents of virtual /proc/{pid}/cmdline file
                string cmdPath = string("/proc/") + dirp->d_name + "/stat";
                ifstream cmdFile(cmdPath.c_str());
                string cmdLine;
                getline(cmdFile, cmdLine);
                // cout<<cmdLine<<endl;
                if (!cmdLine.empty()){
                    size_t beg = cmdLine.find('(');
                    if (beg != string::npos)
                        cmdLine = cmdLine.substr(beg+1);
                    size_t end = cmdLine.find(')');
                    if (end != string::npos)
                        cmdLine = cmdLine.substr(0, end);
                }
                cmdFile.close();

                map<string, string>::iterator iter_cmd = filter.find("-c");
                if(iter_cmd != filter.end()){
                    std::regex reg(filter["-c"]); // -c xxx
                    std::smatch cmd_match;
                    if (!std::regex_search(cmdLine, cmd_match, reg)){
                        // cout<<"no match"<<cmdLine<<endl;
                        continue;
                    }
                }

                map<string, string>::iterator iter_filename = filter.find("-f");

                map<string, string>::iterator iter_type = filter.find("-t");
                if(iter_type == filter.end() || filter["-t"] == "DIR"){

                    //cwd
                    memset(buf1, 0, 128);
                    string cwdPath = string("/proc/") + dirp->d_name + "/cwd";
                    nbytes = readlink(cwdPath.c_str(), buf1, bufsiz);
                    if (nbytes != -1){
                        n = open(buf1,O_RDONLY);
                        if (n!=-1){
                            ret = get_inode(n);
                            if (iter_filename == filter.end() || regex_search(buf1, regex(filter["-f"])))
                                printf("%-16s%-16d%-16s%-16s%-16s%-24d%-30s\n", cmdLine.c_str(), id, username, "cwd", "DIR", ret, buf1);
                            }
                        close(n);
                    }
                    else if (errno==13 &&(iter_type == filter.end() || filter["-t"] == "unknown")){
                        printf("%-16s%-16d%-16s%-16s%-16s%-24s%s\n", cmdLine.c_str(), id, username, "cwd", "unknown",cwdPath.c_str(), strerror(errno));
                    }

                    //rtd
                    string rootPath = string("/proc/") + dirp->d_name + "/root";
                    nbytes = readlink(rootPath.c_str(), buf2, bufsiz);
                    if (nbytes != -1){
                        n = open(buf2,O_RDONLY);
                        if (n!=-1){
                            ret = get_inode(n);
                            if (iter_filename == filter.end() || regex_search(buf2, regex(filter["-f"])))
                                printf("%-16s%-16d%-16s%-16s%-16s%-24d%-30s\n", cmdLine.c_str(), id, username,  "rtd", "DIR", ret, buf2);
                            close(n);
                        }
                    }
                    else if (errno==13 &&(iter_type == filter.end() || filter["-t"] == "unknown") ){
                        printf("%-16s%-16d%-16s%-16s%-16s%-24s%s\n", cmdLine.c_str(), id, username, "rtd", "unknown",rootPath.c_str(), strerror(errno));
                    }
                }
                if(iter_type == filter.end() || filter["-t"] == "REG"){
                    // txt
                    string txtPath = string("/proc/") + dirp->d_name + "/exe";
                    nbytes = readlink(txtPath.c_str(), buf3, bufsiz);
                    if (nbytes != -1){
                        n = open(buf3,O_RDONLY);
                        if (n!=-1){
                            ret = get_inode(n);
                            if (iter_filename == filter.end() || regex_search(buf3, regex(filter["-f"]))){
                                printf("%-16s%-16d%-16s%-16s%-16s%-24d%-30s\n", cmdLine.c_str(), id, username, "txt", "REG", ret, buf3);
                                map_info.insert(std::to_string(ret));
                                }
                            close(n);
                        }
                    }
                    else if (errno==13 && (iter_type == filter.end()|| filter["-t"] == "unknown") ){
                        printf("%-16s%-16d%-16s%-16s%-16s%-24s%s\n", cmdLine.c_str(), id, username, "txt", "unknown",txtPath.c_str(), strerror(errno));
                    }
                    // // mem
                    // string memPath = string("/proc/") + dirp->d_name + "/maps";
                    // fp = fopen(memPath.c_str(), "r");
                    // if (fp==NULL){
                    //     if (errno==13 &&((iter_type == filter.end()&&iter_type == filter.end()) || regex_search(memPath.c_str(), regex(filter["-f"])) || filter["-t"] == "unknown"))
                    //         printf("%-16s%-16d%-16s%-16s%-16s%-24s%s\n", cmdLine.c_str(), id, username, "mem", "unknown",memPath.c_str(), strerror(errno));
                    // }
                    // else{
                    //     while (fgets(buf4, 128, fp)!=NULL) {
                    //         memset(pathname, 0, 25);
                    //         sscanf(buf4, "%s %s %s %s %s %s", tmp1, tmp2, tmp3, tmp4, inode, pathname);
                    //         if( pathname[0]=='/' && map_info.find(string(inode))==map_info.end() ){
                    //             if (iter_filename == filter.end() || regex_search(pathname, regex(filter["-f"]))){
                    //                 printf("%-16s%-16d%-16s%-16s%-16s%-24s%-30s\n", cmdLine.c_str(), id, username, "mem", "REG", inode, pathname);
                    //                 map_info.insert(string(inode));
                    //             }
                    //         }  
                    //     }
                    //     fclose(fp);
                    // }
                }
                string fdPath = string("/proc/") + dirp->d_name + "/fd";
                dp2 = opendir(fdPath.c_str());
                if (dp2 == NULL ){
                    if (errno==13 && (iter_type == filter.end()))
                        printf("%-16s%-16d%-16s%-16s%-16s%-24s%s\n", cmdLine.c_str(), id, username, "NOFD", "",fdPath.c_str(), strerror(errno));
                }
                else{
                    // mem
                    string memPath = string("/proc/") + dirp->d_name + "/maps";
                    fp = fopen(memPath.c_str(), "r");
                    // if (fp==NULL){
                    //     if (errno==13 &&((iter_type == filter.end()&&iter_type == filter.end()) || regex_search(memPath.c_str(), regex(filter["-f"])) || filter["-t"] == "unknown"))
                    //         printf("%-16s%-16d%-16s%-16s%-16s%-24s%s\n", cmdLine.c_str(), id, username, "mem", "unknown",memPath.c_str(), strerror(errno));
                    // }
                    if (fp != NULL){
                        while (fgets(buf4, 128, fp)!=NULL) {
                            memset(pathname, 0, 25);
                            sscanf(buf4, "%s %s %s %s %s %s", tmp1, tmp2, tmp3, tmp4, inode, pathname);
                            if( pathname[0]=='/' && map_info.find(string(inode))==map_info.end() ){
                                if ((iter_filename == filter.end() || regex_search(pathname, regex(filter["-f"])))&&(iter_type == filter.end() || filter["-t"] == "REG") ){
                                    std::size_t str_del = string(pathname).find("(delete)");
                                    if (str_del == string::npos)
                                        printf("%-16s%-16d%-16s%-16s%-16s%-24s%-30s\n", cmdLine.c_str(), id, username, "mem", "REG", inode, pathname);
                                    else
                                        printf("%-16s%-16d%-16s%-16s%-16s%-24s%-30s\n", cmdLine.c_str(), id, username, "DEL", "REG", inode, (string(pathname).substr(0,str_del)).c_str());
                                    map_info.insert(string(inode));
                                }
                            }  
                        }
                        fclose(fp);
                    }


                    // add if statement to know whether open the dir or not
                    while((dirp2 = readdir(dp2))!=NULL){
                        if (dirp2->d_type == DT_LNK){
                            memset(link_path, 0, 100);
                            memset(sym_link, 0, 100);
                            sprintf(link_path, "%s/%s", fdPath.c_str(), dirp2->d_name);
                            int result = readlink(link_path, sym_link, 100);
                            std::string sym_inode;
                            if (result != -1){
                                string fd = string(dirp2->d_name);
                                stat (link_path, &file_stat);
                                string fdinfoPath = string("/proc/") + dirp->d_name + "/fdinfo/" + dirp2->d_name;
                                fp = fopen(fdinfoPath.c_str(), "r");
                                if (fp == NULL){
                                    continue;
                                }
                                else
                                {
                                    while(fgets(mode, 128, fp)!=NULL)
                                    {
                                        string tmp(mode);
                                        int pos = tmp.find(':');
                                        string label = tmp.substr(0,pos);
                                        string value = tmp.substr(pos);
                                        if (label == "flags")
                                            if(value[value.size()-2]=='0')
                                                fd = fd + "r";
                                            else if(value[value.size()-2]=='1')
                                                fd = fd + "w";
                                            else if(value[value.size()-2]=='2')
                                                fd = fd + "u";
                                    }
                                    fclose(fp);
                                }
                                if (iter_filename == filter.end() || regex_search(sym_link, regex(filter["-f"]))){
                                    if(S_ISFIFO(file_stat.st_mode) && (iter_type == filter.end() || filter["-t"] == "FIFO")){
                                        if (sym_link[0]=='/'){
                                            n = open(sym_link,O_RDONLY);
                                            if (n != -1){
                                                ret = get_inode(n);
                                                printf("%-16s%-16d%-16s%-16s%-16s%-16d%-30s\n", cmdLine.c_str(), id, username,  fd.c_str(), "FIFO", ret, sym_link);
                                                close(n);
                                            }
                                            else {
                                                string f = string(sym_link);
                                                int p = f.find(' ');
                                                f = f.substr(0, p);
                                                printf("%-16s%-16d%-16s%-16s%-16s%-16ld%-30s\n", cmdLine.c_str(), id, username,  fd.c_str(), "FIFO", file_stat.st_ino, f.c_str());
                                            }
                                        }
                                        else{
                                            sym_inode = find_inode_by_pipe_symlink(sym_link);
                                            printf("%-16s%-16d%-16s%-16s%-16s%-16s%-30s\n", cmdLine.c_str(), id, username,  fd.c_str(), "FIFO", sym_inode.c_str(), sym_link);
                                        }
                                    }
                                    else if(S_ISCHR(file_stat.st_mode)&& (iter_type == filter.end() || filter["-t"] == "CHR")){
                                        n = open(sym_link,O_RDONLY);
                                        if (n != -1){
                                            ret = get_inode(n);
                                            printf("%-16s%-16d%-16s%-16s%-16s%-16d%-30s\n", cmdLine.c_str(), id, username, fd.c_str(), "CHR", ret, sym_link);
                                            close(n);
                                        }
                                    }
                                    else if(S_ISSOCK(file_stat.st_mode)&& (iter_type == filter.end() || filter["-t"] == "SOCK")){
                                        sym_inode = find_inode_by_socket_symlink(sym_link);
                                        printf("%-16s%-16d%-16s%-16s%-16s%-16s%-30s\n", cmdLine.c_str(), id, username, fd.c_str(), "SOCK", sym_inode.c_str(), sym_link);
                                    }
                                    else if(S_ISREG(file_stat.st_mode)&& (iter_type == filter.end() || filter["-t"] == "REG")){
                                        n = open(sym_link, O_RDONLY);
                                        if (n != -1){
                                            ret = get_inode(n);
                                            printf("%-16s%-16d%-16s%-16s%-16s%-16d%-30s\n", cmdLine.c_str(), id, username, fd.c_str(), "REG", ret, sym_link);
                                            close(n);
                                        }
                                    }
                                    else if (iter_type == filter.end() || filter["-t"] == "unknown"){
                                        n = open(sym_link,O_RDONLY);
                                        if (n != -1){
                                            ret = get_inode(n);
                                            printf("%-16s%-16d%-16s%-16s%-16s%-16d%-30s\n", cmdLine.c_str(), id, username, fd.c_str(), "unknown", ret, sym_link);
                                            close(n);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    closedir(dp2);
                }
            }
        }
        closedir(dp);
    }
}


int main(int argc, char* argv[])
{
    vector<std::string> normal_type = {"REG", "CHR", "DIR", "FIFO", "SOCK", "unknown"}; 
    // Fancy command line processing skipped for brevity
    for (int i=1;i<argc;i+=2){
        filter[argv[i]] = argv[i+1];
    }
    map<string, string>::iterator iter_type = filter.find("-t");
    if(iter_type==filter.end() || (iter_type!=filter.end() && find(normal_type.begin(), normal_type.end(), filter["-t"])!=normal_type.end()))
        lsof();
    else
        cout<<"Invalid TYPE option."<<endl;
    return 0;
}