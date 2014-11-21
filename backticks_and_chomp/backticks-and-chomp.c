#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static unsigned int
backticks(const char * cmd, char * buf, unsigned int buf_max)
{
    FILE         * fp;
    unsigned int   bytes_read    = 0;
    unsigned int   bytes_written = 0;

    fp = popen(cmd, "r");
    if (fp == NULL) { 
        // printf("backticks: popen failed to exec command '%s'\n", cmd);
        // assert?
        buf[0] = '\0';
        return 0;
    }

    while ((bytes_read = fread(buf + bytes_written, sizeof(char), (buf_max - bytes_written - 1), fp)) != 0) {
        // DEBUG: printf("read %u bytes from the pipe\n", bytes_read);
        bytes_written += bytes_read;
    }

    buf[bytes_written] = '\0';
    pclose(fp);
    return bytes_written;
}

static void
chomp(char * buf)
{
    int len = strlen(buf);
    if (isspace(buf[len - 1])) {
        buf[len - 1] = '\0';
        chomp(buf);
    }
}

int
main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;
    char hostname[1024];
    backticks("hostname", hostname, sizeof(hostname));
    chomp(hostname);
    printf("hostname: %s\n", hostname);
    return 0;
}
