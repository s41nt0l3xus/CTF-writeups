#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int main()
{
    setuid(0);
    setgid(0);
    int fd = open("flag.txt", O_RDONLY);
    if (fd < 0)
    {
        perror("open flag.txt");
        return 1;
    }
    char flag[200];
    ssize_t bytes_read = read(fd, flag, sizeof(flag) - 1);
    if (bytes_read < 0)
    {
        perror("read");
        close(fd);
        return 1;
    }
    flag[bytes_read] = '\0'; // Null-terminate the string
    printf("Flag: %s\n", flag);
    close(fd);
    return 0;
}