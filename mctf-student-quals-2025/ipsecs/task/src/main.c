#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>       // For pipe, fork, read, write, close, syscall
#include <string.h>
#include <sys/wait.h>     // For waitpid
#include <sys/mman.h>     // For mmap, munmap
#include <seccomp.h>      // For all libseccomp functions
#include <linux/seccomp.h> // For SCMP_ACT_KILL
#include <sys/syscall.h>  // For SYS_getpid
#include <errno.h>
#include <string.h>
#include "./ipc/ipc.h"

void install_seccomp_filter() {
    scmp_filter_ctx ctx;

    ctx = seccomp_init(SCMP_ACT_KILL);
    if (ctx == NULL) {
        perror("seccomp_init");
        exit(EXIT_FAILURE);
    }


    // Allow read()
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) < 0) {
        perror("seccomp_rule_add read");
        exit(EXIT_FAILURE);
    }

    // Allow write()
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) < 0) {
        perror("seccomp_rule_add write");
        exit(EXIT_FAILURE);
    }

    // Allow mmap()
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0) < 0) {
        perror("seccomp_rule_add mmap");
        exit(EXIT_FAILURE);
    }

    // Allow munmap()
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0) < 0) {
        perror("seccomp_rule_add munmap");
        exit(EXIT_FAILURE);
    }

    // Allow exit_group() (this is what exit() calls)
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) < 0) {
        perror("seccomp_rule_add exit_group");
        exit(EXIT_FAILURE);
    }

    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0) < 0) {
        perror("seccomp_rule_add exit_group");
        exit(EXIT_FAILURE);
    }

    // Allow rt_sigreturn() (often needed implicitly) ???
    if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0) < 0) {
        perror("seccomp_rule_add rt_sigreturn");
        exit(EXIT_FAILURE);
    }
    // --- Load the filter ---
    // From this point on, the filter is active.
    if (seccomp_load(ctx) < 0) {
        perror("seccomp_load");
        exit(EXIT_FAILURE);
    }

    seccomp_release(ctx);
}

Cmd read_cmd(int read_fd) {

}

void send_cmd(int write_fd,char* type,char* data,size_t len) {
  Cmd cmdx;
  memset(&cmdx,0,sizeof(cmdx));
  strcpy(cmdx.type,type);
  memcpy(cmdx.data.data,data,len); // put raw bytes to union
  write(write_fd,&cmdx,sizeof(cmdx));
}

void child_process(int read_fd, int write_fd,char* code_buffer,size_t code_len) {
  sleep(5);
  long pid = syscall(SYS_getpid);
  install_seccomp_filter(); //install seccomp
  if (code_len > 0x2000) {
    send_cmd(write_fd,LOG,"[Child] Error: code len is too  big...",20);
    exit(-1);
  }
  void (*code)(int,int);  
  code = mmap(NULL, 0x4000,PROT_READ | PROT_WRITE | PROT_EXEC,MAP_ANONYMOUS | MAP_PRIVATE,-1,0);
  memcpy(code,code_buffer,code_len);
  code(read_fd,write_fd);
  //exit at the end of the child
  exit(0);
}

void parent_process(int read_fd, int write_fd, pid_t child_pid) {
  char buffer[1024];
  int n;
  int status = 0;
  printf("[Parent] Child process created with PID: %d\n", child_pid);
    
    // Read all responses from the child until its pipe closes
    // (which happens when the child process terminates)
  printf("[Parent] Starting command processing...:\n");
  //command process cycle
  while(1) {
    pid_t result = waitpid(child_pid, &status, WNOHANG);
    if(result == 0) {
      dispatch_cmd(read_fd,write_fd);
    }
    else if(result == -1) {
      printf("Some error happened...\n");
      exit(-1);
    }
    else {
      if (WIFEXITED(status)) {
        printf("[Parent] Child exited normally with status: %d\n", WEXITSTATUS(status));
        exit(0);
      } 
      else if (WIFSIGNALED(status)) {
        // It was terminated by a signal
        int term_sig = WTERMSIG(status);
        printf("[Parent] Child was terminated by signal: %d (%s)\n", term_sig, strsignal(term_sig)); 
        exit(0);
      } 
      else {
        printf("[Parent] Child terminated in an unknown way.\n");
        exit(0);
      }
    }
  }
}

void fflushx() {
  setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

int main() {
    fflushx();
    int to_child_pipe[2];
    int from_child_pipe[2];
    char code_buffer[0x2000];
    char* code_end = NULL;
    pid_t pid;

    // Create the pipes
    if (pipe(to_child_pipe) == -1) {
        perror("pipe (to_child)");
        return 1;
    }
    if (pipe(from_child_pipe) == -1) {
        perror("pipe (from_child)");
        return 1;
    }

    // Fork the process
    puts("[Parent] Enter code to execute...");
    puts(">>");
    memset(code_buffer,0,sizeof(code_buffer));
    fgets(code_buffer,sizeof(code_buffer),stdin);
    pid = fork();

    if (pid == -1) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        // --- Child Process ---

        // Close unused pipe ends
        close(to_child_pipe[1]);   // Close write-end of to_child
        close(from_child_pipe[0]); // Close read-end of from_child

        // Call the child's main logic
        // Pass the read-end of to_child and write-end of from_child
        child_process(to_child_pipe[0], from_child_pipe[1],code_buffer,sizeof(code_buffer));
        
        // Close remaining pipes (child_process exits, so this might not be reached)
        close(to_child_pipe[0]);
        close(from_child_pipe[1]);
        exit(0); // Should be unreachable

    } else {
        // --- Parent Process ---
        close(to_child_pipe[0]);   // Close read-end of to_child
        close(from_child_pipe[1]); // Close write-end of from_child

        parent_process(from_child_pipe[0], to_child_pipe[1], pid);

        close(to_child_pipe[1]);
        close(from_child_pipe[0]);
    }
    return 0;
}
