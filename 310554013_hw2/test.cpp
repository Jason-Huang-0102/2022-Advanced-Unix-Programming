#include <fcntl.h>
#include <unistd.h>

int main(void){
    int fd = open("test.txt", O_CREAT | O_WRONLY);
    if(fd<0){
        return 1;
    }
    close(fd);
    return 0;
}