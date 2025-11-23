/*
* file:        part-2.c
* description: Part 2, CS5600 Project 1, 2025 SP
*/
 
/* NO OTHER INCLUDE FILES */
#include "elf64.h"
#include "sysdefs.h"
 
extern void *vector[];

#define MAX_LOADED_SECTIONS 10
#define MAX_ARGS 10
#define BUF_SIZE 200
 
//Store arguments for getarg
char *args[MAX_ARGS];
int arg_count = 0;

 
/* ---------- */

/* write these functions 
*/

int read(int fd, void *ptr, int len) {
    return syscall(__NR_read, fd, ptr, len);
}
 
int write(int fd, void *ptr, int len) {
    return syscall(__NR_write, fd, ptr, len);
}
 
void exit(int err) {
    syscall(__NR_exit, err);
}
 
int open(char *path, int flags) {
    return syscall(__NR_open, path, flags);
}
 
int close(int fd) {
    return syscall(__NR_close, fd);
}
 
int lseek(int fd, int offset, int flag) {
    return syscall(__NR_lseek, fd, offset, flag);
}
 
void *mmap(void *addr, int len, int prot, int flags, int fd, int offset) {
    return (void *)syscall(__NR_mmap, addr, len, prot, flags, fd, offset);
}
 
int munmap(void *addr, int len) {
    return syscall(__NR_munmap, addr, len);
}
 
/* ---------- */

/* the three 'system call' functions - readline, print, getarg 
 * hints: 
 *  - read() or write() one byte at a time. It's OK to be slow.
 *  - stdin is file desc. 0, stdout is file descriptor 1
 *  - use global variables for getarg
 */

void do_readline(char *buf, int len) {
    int i = 0;
    while (i < len - 1) {
        if (read(0, &buf[i], 1) != 1) break;
        if (buf[i] == '\n') break; 
        i++;
    }
    buf[i] = '\0';
}
 

void do_print(char *buf) {
    while (*buf) {
        write(1, buf, 1);
        buf++;
    }
}
 

char *do_getarg(int i) {
    return (i < arg_count) ? args[i] : 0;
}


/* ---------- */

/* the guts of part 2
 *   read the ELF header
 *   for each section, if b_type == PT_LOAD:
 *     create mmap region
 *     read from file into region
 *   function call to hdr.e_entry
 *   munmap each mmap'ed region so we don't crash the 2nd time
 */
 
 
void *allocated_mem[MAX_LOADED_SECTIONS];
int allocated_sizes[MAX_LOADED_SECTIONS];
int allocated_count = 0;
 
 
void exec_file(char *file) {
    int fd = open(file, O_RDONLY);
    if (fd < 0) {
        do_print("Error: cannot open file\n");
        return;
    }
 
    struct elf64_ehdr hdr;
    read(fd, &hdr, sizeof(hdr));
 
    /* Validation for the ELF header */
    if (hdr.e_ident[0] != 0x7F || hdr.e_ident[1] != 'E' || hdr.e_ident[2] != 'L' || hdr.e_ident[3] != 'F') {
        do_print("Error: not an ELF file\n");
        close(fd);
        return;
    }
 
    
    struct elf64_phdr phdrs[hdr.e_phnum];
    lseek(fd, hdr.e_phoff, SEEK_SET);
    read(fd, phdrs, sizeof(phdrs)); // Read program headers
 
    void *base_addr = (void *)0x80000000; 
 
    for (int i = 0; i < hdr.e_phnum; i++) {
        if (phdrs[i].p_type == PT_LOAD) {
            int size = ROUND_UP(phdrs[i].p_memsz, 4096);
            void *addr = mmap((void *)((long)base_addr + phdrs[i].p_vaddr), size,
                  PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
 
if (addr == MAP_FAILED) {
    //do_print("Error: mmap failed at fixed address. Trying without fixed address...\n");
 
    // Try again with NULL, letting the kernel decide the address. This is mainly used to test with Valgrind
    addr = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        do_print("Error: mmap completely failed\n");
        close(fd);
        return;
    }
}
 
            lseek(fd, phdrs[i].p_offset, SEEK_SET);
            read(fd, addr, phdrs[i].p_filesz);
 
            // Storing the allocated memory info for the later cleanup
            if (allocated_count < MAX_LOADED_SECTIONS) {
                allocated_mem[allocated_count] = addr;
                allocated_sizes[allocated_count] = size;
                allocated_count++;
            }
        }
    }
 
    close(fd);
 
    
    void (*entry)() = (void (*)(void))(hdr.e_entry + (long)base_addr);
    entry();
 
    // Unmapping memory 
    for (int i = 0; i < allocated_count; i++) {
        munmap(allocated_mem[i], allocated_sizes[i]);
    }
}
 
/* ---------- */

/* simple function to split a line:
 *   char buffer[200];
 *   <read line into 'buffer'>
 *   char *argv[10];
 *   int argc = split(argv, 10, buffer);
 *   ... pointers to words are in argv[0], ... argv[argc-1]
 */
int split(char **argv, int max_argc, char *line)
{
	int i = 0;
	char *p = line;

	while (i < max_argc) {
		while (*p != 0 && (*p == ' ' || *p == '\t' || *p == '\n'))
			*p++ = 0;
		if (*p == 0)
			return i;
		argv[i++] = p;
		while (*p != 0 && *p != ' ' && *p != '\t' && *p != '\n')
			p++;
	}
	return i;
}

/* ---------- */

void main(void) {
    vector[0] = do_readline;
    vector[1] = do_print;
    vector[2] = do_getarg;
 
    char buffer[BUF_SIZE];
 
    while (1) {
        do_print("> ");
        do_readline(buffer, BUF_SIZE);
 
        arg_count = split(args, MAX_ARGS, buffer);
        if (arg_count == 0) continue;
 
        if (args[0][0] == 'q' && args[0][1] == 'u' && args[0][2] == 'i' && args[0][3] == 't') {
            exit(0);
        }
 
        // Resetting the vector table before execution of the next program
        vector[0] = do_readline;
        vector[1] = do_print;
        vector[2] = do_getarg;
 
        exec_file(args[0]); // executing the requested program
    }
}