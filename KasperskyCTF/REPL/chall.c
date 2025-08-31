#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#define BUFSZ 0x80

void __attribute__((constructor)) init(void)
{
  setvbuf(stdin , NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}

void readline(char* buf, size_t maxsz)
{
  getline(&buf, &maxsz, stdin);
}

int parseop(const char* token, char* op)
{
  if (strspn(token, "+-*/%") != 1 || token[1] != '\x00')
    return -1;
  *op = token[0];
  return 0;
}

int parsenum(const char* token, int64_t* num)
{
  char *endptr = NULL;
  int64_t tmp  = strtol(token, &endptr, 10);
  if (!endptr || *endptr)
    return -1;
  *num = tmp;
  return 0;
}

int64_t compute(int64_t left, int64_t right, char op)
{
  switch (op)
  {
    case '+': 
      return left + right;
    case '-':
      return left - right;
    case '*':
      return left * right;
    case '/':
      return left / right;
    case '%':
      return left % right;
    default:
      return 0;
  }
}

int64_t eval(char* linebuf, char** badtoken)
{
  int64_t result = 0;
  char    op     = '+';
  enum {
    NEED_OP,
    NEED_NUM
  } state = NEED_NUM;

  const char* delims = " \t\n";
  char* token = NULL;
  for (token = strtok(linebuf, delims); token; token = strtok(NULL, delims))
  {
    switch (state)
    {
      case NEED_OP:  
        if (parseop(token, &op) != 0)
          goto end;
        state = NEED_NUM;
        break;
      case NEED_NUM:
        int64_t tmp = 0;
        if (parsenum(token, &tmp) != 0)
          goto end;
        result = compute(result, tmp, op);
        state = NEED_OP; 
        break;
      default:
        break;
    }
  }

end:
  *badtoken = token;
  return result;
}

int main(void)
{
  char linebuf[BUFSZ] = "";
  int64_t result      = 0;
  char* badtoken      = NULL;

  for (;;)
  {
    printf("[>] ");
    readline(linebuf, sizeof(linebuf));
    result = eval(linebuf, &badtoken);
    if (badtoken != NULL)
      printf("[-] Bad token \"%s\"\n", badtoken);
    else
      printf("[+] %ld\n", result);
  }

  return 0;
}
