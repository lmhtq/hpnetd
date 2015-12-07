#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>

#define ERR_EXIT(m)    \
do {                   \
    perror(m);         \
    exit(EXIT_FAILURE);\
} while(0); 




int main() {
    time_t t;
    int fd;
    if (daemon(0, 1) == -1) {
        ERR_EXIT("daemon error");
    }

    while (1) {
        fd = open("/tmp/tmp.log", O_WRONLY|O_CREAT|O_APPEND, 644);
        if (fd == -1) {
            ERR_EXIT("open error");
        }
        t = time(0);
        char *buf = asctime(localtime(&t));
        write(fd, buf, strlen(buf));
        close(fd);
        sleep(5);
    }
    return 0;
}