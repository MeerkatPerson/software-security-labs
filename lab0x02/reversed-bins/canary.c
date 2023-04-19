#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win() {
    execl("/bin/sh", "sh", "-c", "/bin/sh", (char *) NULL);
}

void vulnerable() {
    char memory[80];
    int cmd;
    while (1) {
        fflush(stdin);
        printf("Your command: ");
        scanf(" %d", &cmd);
        if (cmd == 0) {
            printf("Tell me which slot you wanna read: ");
            scanf("%d", &cmd);
            write(1, memory + cmd*8, 8); // ssize_t write(int fd, const void *buf, size_t count): 
                                         // writes up to count bytes from the buffer starting at buf to the
                                         // file referred to by the file descriptor fd
                                         // file descriptor is an integer that uniquely identifies an open file of the process
                                         // write to fd 1 = write to stdout
        } 
        else if (cmd == 1) {
            printf("Tell me how much you wanna write: ");
            scanf("%d", &cmd);
            printf("What are the contents (max 8 bytes): ");
            read(0, memory, cmd);       // read from fd 0 = read from stdin
                                        // size_t read (int fd, void* buf, size_t cnt)
                                        // read cnt bytes of input into the memory area indicated by buf
            printf("Good\n");           
        }
        else {
            break;
        }
    }
}


int main() {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    setbuf(stdin, NULL);
    printf("Oof looks like this will be a bit more trouble...\n");
    vulnerable();
}
