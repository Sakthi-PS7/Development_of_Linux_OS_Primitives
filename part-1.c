/*
 * file:        part-1.c
 * description: Part 1, CS5600 Project 1, 2025 SP
 */

/* THE ONLY INCLUDE FILE */
#include "sysdefs.h"

#define MAX_INPUT_SIZE 200

/* write these functions */


int read(int fd, void *ptr, int len) {
    return syscall(__NR_read, fd, ptr, len);
}

int write(int fd,  void *ptr, int len) {
    return syscall(__NR_write, fd, ptr, len);
}

void exit(int err) {
    syscall(__NR_exit, err);
}

/* ---------- */

/* Factor, factor! Don't put all your code in main()! 
*/

/* read one line from stdin (file descriptor 0) into a buffer: */

void readline(char *buffer) {
    int i = 0;
    char c;
    while (i < MAX_INPUT_SIZE - 1) {
        if (read(0, &c, 1) <= 0) {
            break;
        }

        if (c == '\n') {
            break;
        }

        buffer[i++] = c;
    }
    buffer[i] = '\0';
}

/* print a string to stdout (file descriptor 1) */

void print(char *str) {
    int len = 0;
    while (str[len] != '\0') {
        len++;
    }
    write(1, str, len);
    write(1, "\n", 1);
}


/* ---------- */

void main(void) 
{
    char buffer[MAX_INPUT_SIZE];

    print("Hello, type lines of input, or 'quit' to exit:");

    while (1) {
        readline(buffer); 

        // Check for "quit" phrase
        if (buffer[0] == 'q' && buffer[1] == 'u' && buffer[2] == 'i' && buffer[3] == 't' && buffer[4] == '\0') {
            exit(0);
        }

        
        print("You typed: ");
        print(buffer);
    }
}
