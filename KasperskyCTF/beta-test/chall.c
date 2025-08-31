// gcc -o chall -Wall -Wextra -Werror -fPIE -fstack-protector chall.c -Wl,-z,relro,-z,now

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <errno.h>

#include <unistd.h>

#define MAXID 0xFF

struct storage
{
  uint64_t nitems;
  char     desc[];
};

struct item
{
  uint8_t sz; 
  uint8_t storage_id;
  char    desc[];
};

struct feedback
{
#define FEEDBACKSZ 0x80
  char*  content;
  time_t time;
};

struct feedback*  feedback;
struct item*      items_arr[MAXID+1];
struct storage*   storages_arr[MAXID+1];

void error(const char* msg)
{
  fprintf(stderr, "Error: ");
  if (errno)
  {
    perror(msg);
  }
  else
  {
    fprintf(stderr, "%s\n", msg);
  }
  exit(EXIT_FAILURE);
}

char readchar(void)
{
  char result = EOF;
  int ret = scanf("%c%*c", &result);
  if (ret != 1)
    error("failed to read char");
  return result;
}

uint64_t readnum(void)
{
  uint64_t result = 0;
  int ret = scanf("%lu%*c", &result);
  if (ret != 1)
    error("failed to read num");
  return result;
}

char* readstr(void)
{
  char* result = NULL;
  int ret = scanf("%m[^\n]%*c", &result);
  if (ret != 1)
    error("failed to read string");
  return result;
}

void readstr2(char* str, size_t bufsz)
{
  int rd = read(STDIN_FILENO, str, bufsz);
  if (rd < 0)
    error("failed to read string 2");
  // FIXME: Out Of Bound Write: 
  //        bufsz == 0x00 
  //        -> rd == 0x00 
  //        -> str[-1] = 0x00
  str[rd-1] = '\x00';
}

void update_item(void)
{
  printf("Enter item #ID: ");
  uint8_t      item_id = readnum();
  struct item* item    = items_arr[item_id];
  if (!item)
  {
    printf("No such item\n");
    return;
  }

  printf("Enter new item description: ");
  readstr2(item->desc, item->sz);

  printf("Item was updated\n");
}

void delete_item(void)
{
  printf("Enter item #ID: ");
  uint8_t      item_id = readnum();
  struct item* item    = items_arr[item_id];
  if (!item)
  {
    printf("No such item\n");
    return;
  }

  uint8_t         storage_id = item->storage_id;
  struct storage* storage    = storages_arr[storage_id];

  free(item);
  items_arr[item_id] = NULL;
  printf("Item #%03hhu was deleted\n", item_id);

  // FIXME: Use After Free: 
  //        storage pointer is not erased
  //        -> free'ed storage still can be used
  //        -> --storage->nitems
  if (!--storage->nitems)
  {
    printf("Storage #%03hhu became empty and was deleted\n",
      storage_id
    );
    free(storage);
  }

}

void add_storage(void)
{
  struct storage** storage_slot = NULL;
  for (size_t i = 0; i <= MAXID; i++)
  {
    if (!storages_arr[i])
    {
      storage_slot = &storages_arr[i];
      break;
    }    
  }
  if (!storage_slot)
    error("no free storage slots");

  printf("Enter storage description: ");
  char* desc = readstr();

  struct storage* storage = calloc(1, sizeof(*storage) + strlen(desc) + 1);
  if (!storage)
    error("can't alloc storage");

  strcpy(storage->desc, desc);
  free(desc);

  *storage_slot = storage;

  do
  {
    struct item** item_slot = NULL;
    for (size_t i = 0; i <= MAXID; ++i)
    {
      if (!items_arr[i])
      {
        item_slot = &items_arr[i];
        break;
      }
    }
    if (!item_slot)
      error("no free item slots");

    printf("Enter item descripton: ");
    desc = readstr();

    struct item* item = calloc(1, sizeof(*item) + strlen(desc) + 1);
    if (item == NULL)
      error("can't alloc item");

    strcpy(item->desc, desc);
    free(desc);

    // FIXME: Integer Overflow: 
    //        item->sz is uint8_t 
    //        -> item->sz == (strlen(item->desc) + 1) & 0xFF
    //        -> strlen(item->desc) == 0x100 * N + 0xFF
    //        -> item->sz == 0
    item->sz         = strlen(item->desc) + 1;
    item->storage_id = storage_slot - storages_arr;
    *item_slot       = item;

    storage->nitems++;

    printf("Item #%03hhu was added to storage\n", 
      (uint8_t)(item_slot - items_arr)
    );

    printf("Do you want to add another one? (y/n) ");

  } while(readchar() == 'y');

  printf("Storage #%03hhu with %lu items was added\n", 
    (uint8_t)(storage_slot - storages_arr),
    storage->nitems
  );
}

void leave_feedback(void)
{
  if (feedback)
  {
    printf("You are alredy left feedback: \"%s\"\n",
      feedback->content
    );

    printf("Do you want to change it? (y/n) ");
    if (readchar() != 'y')
      return;

    printf("Enter new feedback: ");
    readstr2(feedback->content, FEEDBACKSZ);
    
    return;
  }

  feedback = calloc(1, sizeof(*feedback));
  if (!feedback)
    error("can't alloc feedback");

  feedback->content = calloc(FEEDBACKSZ, 1);
  if (!feedback->content)
    error("can't alloc feedback content");

  feedback->time = time(NULL);

  printf("Enter feedback: ");
  readstr2(feedback->content, FEEDBACKSZ);

  printf("Feedback is saved. Thank you for your time!\n");
}

enum MENU_OPTIONS
{
  ADD_STORAGE = 1,
  UPDATE_ITEM,
  DELETE_ITEM,
  LEAVE_FEEDBACK,
  EXIT
};

uint64_t menu(void)
{
  printf("Menu:\n");
  printf("%d. Add storage\n", ADD_STORAGE);
  printf("%d. Update iteam\n", UPDATE_ITEM);
  printf("%d. Delete item\n", DELETE_ITEM);
  printf("%d. Leave feedback\n", LEAVE_FEEDBACK);
  printf("%d. Exit\n", EXIT);
  printf("> ");

  char buf[0x20] = "";
  fgets(buf, sizeof(buf), stdin);

  // FIXME: Memory Leak: 
  //        variable isn't initialized 
  //        -> scanf can fail
  //        -> "junk" value (actually, leak) will be returned
  uint64_t result;
  sscanf(buf, "%lu", &result);
  return result;
}

void banner(void)
{
  printf("Storage Management System v0.01\n");
  printf("Special build for beta-testing\n");
  printf("May contain bugs\n");
  printf("Do not deploy in real production!\n");
  printf("\n");
}

void __attribute__((constructor)) init(void)
{
  setvbuf(stdin , NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
}

int main(void)
{
  banner();
  while (true)
  {
    uint64_t choice = menu();
    switch (choice)
    {
      case ADD_STORAGE:
        add_storage();
        break;
      case UPDATE_ITEM:
        update_item();
        break;
      case DELETE_ITEM:
        delete_item();
        break;
      case LEAVE_FEEDBACK:
        leave_feedback();
        break;
      case EXIT:
        return 0;
      default:
        printf("Bad option: %lu\n", choice);
        continue;
    }
  }
  return 0;
}
