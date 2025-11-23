/*
 * file:        part-3.c
 * description: Part 3, CS5600 Project 1, 2025 SP
 */

/* NO OTHER INCLUDE FILES */
#include "elf64.h"
#include "sysdefs.h"

extern void *vector[];
extern void switch_to(void **location_for_old_sp, void *new_value);
extern void *setup_stack0(void *_stack, void *func);


/* Stack pointers declared for context switching */
void *stack1, *stack2;
void *sp1, *sp2;
void *main_sp;

/* ---------- */

/* write these 
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

/* copy from Part 2 */

void do_print(char *buf)
{
    while (*buf) {
        write(1, buf, 1);
        buf++;
    }
}
/* ---------- */

/* write these new functions */

void do_yield12(void)
{
    switch_to(&sp1, sp2);  // Switch from process1 to process2
}

void do_yield21(void)
{
    switch_to(&sp2, sp1);  // Switch from process2 to process1
}

void do_uexit(void)
{
    switch_to(&sp1, main_sp);  // Return to main stack and exit
}

/* ---------- */

//loading of ELF Executable file
void *load_program(char *filename, int load_offset)
{
    int fd = open(filename, O_RDONLY);
    if (fd < 0)
    {
        do_print("Failed to open file\n");
        exit(1);
    }

    struct elf64_ehdr hdr;
    read(fd, &hdr, sizeof(hdr));

    int i, num_sections = hdr.e_phnum;
    struct elf64_phdr phdrs[num_sections];

    lseek(fd, hdr.e_phoff, SEEK_SET);
    read(fd, phdrs, sizeof(phdrs));

    /* Convert load_offset to a pointer safely using long */
    void *base_addr = (void *)(long)load_offset;

    for (i = 0; i < num_sections; i++)
    {
        if (phdrs[i].p_type == PT_LOAD)
        {
            int len = ROUND_UP(phdrs[i].p_memsz, 4096);

            void *mem = mmap((void *)(((long)base_addr + (long)phdrs[i].p_vaddr) & ~(long)0xFFF), len,
                                 PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

            if (mem == MAP_FAILED)
            {
                do_print("mmap failed\n");
                exit(1);
            }

            lseek(fd, phdrs[i].p_offset, SEEK_SET);
            read(fd, mem, phdrs[i].p_filesz);
        }
    }

    close(fd);
    return (void *)((long)base_addr + (long)hdr.e_entry);
}

/* Main function */
void main(void)
{
    /* Set up function pointers in system call table */
    vector[1] = do_print;
    vector[3] = do_yield12;
    vector[4] = do_yield21;
    vector[5] = do_uexit;
    
     /* Save the main stack */
    main_sp = __builtin_frame_address(0);


    /* Allocation stacks for process1 and process2 */
    stack1 = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    stack2 = mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (stack1 == MAP_FAILED || stack2 == MAP_FAILED)
    {
        do_print("Stack allocation failed\n");
        exit(1);
    }

    /* Loading the two programs */
    void *entry1 = load_program("process1", 0x1000000);
    void *entry2 = load_program("process2", 0x2000000);

    /* Set up the stacks */
    sp1 = setup_stack0((void *)(((long)stack1 + 4096) & ~0xF), entry1);
    sp2 = setup_stack0((void *)(((long)stack2 + 4096) & ~0xF), entry2);

   
    switch_to(&main_sp, sp1);

    do_print("done\n");
    exit(0);
}
