#include <stdlib.h>
#include <stdio.h>
#include "lists.h"

void ll_append_to(struct ll_item* end, void* data) {
  struct ll_item* temp = malloc(sizeof(struct ll_item));
  temp->data = data;
  temp->next = end->next;
  end->next = temp;
}
struct ll_item* ll_prepend(struct ll_item* begin, void* data) {
  struct ll_item* temp = malloc(sizeof(struct ll_item));
  temp->next = begin;
  temp->data = data;
  return temp;
}
void ll_append_at(struct ll_item* begin, unsigned int index, void* data) {
  ll_append_to(find_index(begin, index), data);
}
struct ll_item* ll_prepend_at(struct ll_item* begin, unsigned int index, void* data) {
  if(index == 0) {
    return ll_prepend(begin, data);
  } else {
    ll_append_at(begin, index-1, data);
    return NULL;
  }
}
struct ll_item* find_index(struct ll_item* begin, unsigned int index) {
  if(begin == NULL) return NULL;
  struct ll_item* current = begin;
  unsigned int item = 0;
  while(1) {
    if(index == item) {
      return current;
    }
    if(current->next == NULL) {
      return NULL;
    } else {
      current = current->next;
      item++;
    }
  }
}
unsigned int num_items(struct ll_item* begin) {
  struct ll_item* current = begin;
  if(begin == NULL) {
    return 0;
  }
  unsigned int num = 0;
  while(1) {
    num++;
    if(current->next == NULL) {
      return num;
    } else {
      current = current->next;
    }
  }
}
struct ll_item* find_list_end(struct ll_item* element) {
  if(element == NULL) {
     return NULL;
  }
  struct ll_item* current = element;
  unsigned int con = 1;
  while(con) {
    if(current->next == NULL) {
      con = 0;
    } else {
      current = current->next;
    }
  }
  return current;
}
struct ll_item* ll_append(struct ll_item* element, void* data) {
  if(element == NULL) {
      return ll_prepend(NULL, data);
  }
  struct ll_item* last = find_list_end(element);
  ll_append_to(last, data);
  return element;
}
struct ll_item* init_ll(void* data) {
  struct ll_item* temp = malloc(sizeof(struct ll_item));
  temp->data = data;
  temp->next = NULL;
  return temp;
}
//if return val is equal to data, that means there
//was an error deleting the list. otherwise, result
//will be the value of what should be the first
//item of the new list
struct ll_item* ll_delete(struct ll_item* begin, void* data) {
    struct ll_item* current = begin;
    struct ll_item* previous = 0;
    while(current) {
        if(current->data == data) {
            //we've found the item we want to delete.
            if(previous == 0) {
                //this is first element. free it and
                //return the next as new start.
                free(current);
                return current->next;
            } else {
                //this is somewhere in the middle of
                //the list. link previous with next
                //and we keep the start the same.
                previous->next = current->next;
                free(current);
                return begin;
            }
        }
        current = current->next;
    }
    return data;
}
void free_list(struct ll_item* begin, void (*deleter)(void*)) {
  if(begin == NULL) return;
  struct ll_item* current = begin;
  struct ll_item* temp = NULL;
  unsigned int con = 1;
  while(con) {
    if(current->next == NULL) {
      con = 0;
      deleter(current->data);
    } else {
      temp = current->next;
      deleter(current->data);
      current = temp;
    }
  }
}
void print_list(struct ll_item* begin, void (*printer)(void*)) {
  struct ll_item* current = begin;
  if(begin == 0) {
    printf("Empty list.\n");
    return;
  }
  unsigned int con = 1;
  while(con) {
    printf("Item: ");
    printer(current->data);
    if(current->next == NULL) {
      printf("End of list.\n");
      con = 0;
    } else {
      current = current->next;
    }
  }
}
