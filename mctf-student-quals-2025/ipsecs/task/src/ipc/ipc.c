#include "ipc.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <fcntl.h>

struct Storage_entry* entries[10]; 

void dispatch_cmd(int read_fd,int write_fd) {
  Cmd cmdx;
  char buffer[256];
  size_t res;
  res = read(read_fd,&cmdx, sizeof(cmdx)); //read cmd from read_fd
  if(res > 0) {
    if(!strncmp(cmdx.type,LOG,strlen(LOG))) { // Just log to stdin
      cmdx.data.data[255] = '\0';
      puts("[Parent] Got LOG command.");
      printf("[Parent] Data: %s\n",cmdx.data.data);
    }
    else if (!strncmp(cmdx.type,SAVE,strlen(SAVE))) { // Save to storage
      puts("[Parent] Got SAVE command.");
      if(!strncmp(cmdx.data.storage.action,STORE,strlen(STORE))) {
        save_entry(cmdx.data.storage.index,cmdx.data.storage.data,cmdx.data.storage.len);
      }
      else if (!strncmp(cmdx.data.storage.action,LOAD,strlen(LOAD))) {
        read_entry(cmdx.data.storage.index,buffer,cmdx.data.storage.len);
        puts("[Parent] Readed from storage.");
        printf("[Parent] Data  %s \n.",buffer);
        write(write_fd,buffer,sizeof(buffer)); //send to child process
      }
      else if (!strncmp(cmdx.data.storage.action,DELETE,strlen(DELETE))) {
        delete_entry(cmdx.data.storage.index);
      }
    }
    else if (!strncmp(cmdx.type,FS,strlen(FS))) { // Save to filesystem
      puts("[Parent] Got FS command.");
      if(!strncmp(cmdx.data.fs.action,STORE,strlen(STORE))) {
        save_file(cmdx.data.fs.filename,cmdx.data.fs.data,sizeof(cmdx.data.fs.data)); //save file to filesystem
        printf("[Parent] File %s sucessfully saved.\n",cmdx.data.fs.filename);
      }
      else if (!strncmp(cmdx.data.fs.action,LOAD,strlen(LOAD))) {
        read_file(cmdx.data.fs.filename,buffer,sizeof(buffer)); // read from filesystem
        printf("[Parent] File %s sucessfully read.\n",cmdx.data.fs.filename);
        printf("[Parent] File data: %s\n",buffer);
        write(write_fd,buffer,sizeof(buffer)); //send to child process
      }
    }
  }
}

int check(char* data) {
  int valid = 1;
  int i = 0;
  do {
    if(data[i] > 'z' || data[i] < 'a') {
      valid = 0;
      break;
    }    
    i++;
  } while(data[i] != '\0');

  return valid;
}


void save_file(char* filename,char* data,size_t len){
  if(!check(filename)) {
    puts("[Parent] There are forbidden symbols in filename.");
    return;
  }
  int fd = open(filename, O_WRONLY | O_CREAT, 0666);
  write(fd,data,len);
  close(fd);
}

char* read_file(char* filename,char* data,size_t len) {
  int fd = open(filename, O_RDONLY);
  read(fd,data,len);
  close(fd);
}

void save_entry(size_t index,char* data,size_t length) {
  if(index >= 10) {
    puts("[Parent] Error: index to save is too big.");
    return;
  }
  struct Storage_entry* current = entries[index];
  if(current != NULL) {
    puts("[Parent] Entry exists.");
    return;
  }
  if(length > 0x100){
    puts("Length is too big.");
    return;
  }

  entries[index] = malloc(sizeof(struct Storage_entry));
  current = entries[index];
  current->name = malloc(length);
  current->length = strlen(data);
  memcpy(current->name,data,current->length);
}

void read_entry(size_t index,char* data,size_t length) {
  if(index >= 10) {
    puts("[Parent] Error: index to read is too big.");
    return;
  }
  struct Storage_entry* current = entries[index];
  if(current == NULL) {
    puts("[Parent] Entry not exists.");
    return;
  }
  memcpy(data,current->name,current->length); // read_data
}

void delete_entry(size_t index) {
  if(index >= 10) {
    puts("[Parent] Error: index to delete is too big.");
    return;
  }
  struct Storage_entry* current = entries[index];
  if(current == NULL) {
    puts("[Parent] Entry not exists.");
    return;
  }
  free(current->name);
  free(current);
  entries[index] = NULL;
}

