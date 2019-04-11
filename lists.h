//Implementation of linked list
/* ---SAMPLE USE---
 struct ll_item* begin = init_ll(5);
 ll_append(begin, 10);
 ll_append(begin, 15);
 ll_append(begin, 8);
 printf("Finding at: 2, %d\n", findIndex(begin, 0)->data);
 print_list(begin);
 free_list(begin);
 */

struct ll_item {
  void* data;
  struct ll_item* next;
};
void ll_append_to(struct ll_item* end, void* data);
void print_list(struct ll_item* begin, void (*printer)(void*));
void free_list(struct ll_item* begin, void (*deleter)(void*));
struct ll_item* init_ll(void* data);
struct ll_item* ll_append(struct ll_item* element, void* data);
struct ll_item* find_list_end(struct ll_item* element);
struct ll_item* find_index(struct ll_item* begin, unsigned int index);
struct ll_item* ll_prepend_at(struct ll_item* begin, unsigned int index, void* data);
void ll_append_at(struct ll_item* begin, unsigned int index, void* data);
struct ll_item* ll_prepend(struct ll_item* begin, void* data);
void ll_append_to(struct ll_item* end, void* data);
unsigned int num_items(struct ll_item* begin);
struct ll_item* ll_delete(struct ll_item* begin, void* data);
