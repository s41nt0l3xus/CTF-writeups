#include <stdlib.h>
#include <stdio.h>

#ifndef IPSECS
#define IPSESC

#define LOG "LOG"
#define SAVE "SAVE"
#define FS "FILE"

#define STORE "STORE"
#define LOAD "LOAD"
#define DELETE "DELETE"

struct Storage_entry {
  char* name;
  size_t length; 
};

struct Storage_cmd {
  size_t index;
  char action[8];
  size_t len;
  char data[232];
};

struct Fs_cmd {
  char action [8];
  char filename[8];
  char data[240];
};

union Data {
  char data[256]; //data
  struct Fs_cmd fs;
  struct Storage_cmd storage;
};

typedef struct Cmd {
  char type[8]; //LOG OR SAVE OR FS
  union Data data;
} Cmd;

void dispatch_cmd(int read_fd,int write_fd);

void save_file(char* filename,char* data,size_t len);

char* read_file(char* filename,char* data,size_t len);

void save_entry(size_t index,char* data,size_t length);

void read_entry(size_t index, char* data,size_t length);

void delete_entry(size_t index);

#endif
