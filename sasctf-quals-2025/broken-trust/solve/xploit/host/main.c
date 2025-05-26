#include <err.h>
#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>

#include <xploit_ta.h>

char flag[0x100];

int main(void)
{
  TEEC_Result res;
  TEEC_Context ctx;
  TEEC_Session sess;
  TEEC_Operation op;
  TEEC_UUID uuid = TA_XPLOIT_UUID;
  uint32_t err_origin;

  res = TEEC_InitializeContext(NULL, &ctx);
  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

  res = TEEC_OpenSession(&ctx, &sess, &uuid,
             TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
      res, err_origin);

  memset(&op, 0, sizeof(op));

  op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
  op.params[0].tmpref.buffer = flag;
  op.params[0].tmpref.size = sizeof(flag);

  res = TEEC_InvokeCommand(&sess, 0, &op, &err_origin);
  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x", 
      res, err_origin);

  printf("%s\n", flag);

  TEEC_CloseSession(&sess);

  TEEC_FinalizeContext(&ctx);

  return 0;
}
