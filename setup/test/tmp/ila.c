#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
    char *argv[] = { "insmod", "/root/ila.ko", NULL };
    char *envp[] = { NULL };

    if (execve("/sbin/insmod", argv, envp) == -1) {
        perror("execve insmod failed");
        exit(EXIT_FAILURE);
    }
    return 0;
}
