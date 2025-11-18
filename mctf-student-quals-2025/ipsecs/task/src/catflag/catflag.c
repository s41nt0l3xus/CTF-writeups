#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

int main() {
  char buffer[256];
  memset(buffer,0,sizeof(buffer));
  int fs = open("/flag",O_RDONLY);
  read(fs,buffer,sizeof(buffer));
  close(fs);
  write(1,buffer,sizeof(buffer));
}
