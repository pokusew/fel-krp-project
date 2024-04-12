#ifndef POKUSEW_LINKED_LIST_H
#define POKUSEW_LINKED_LIST_H

#include <stdlib.h>
#include <stdbool.h>

typedef struct ll_entry {
	struct ll_entry *prev;
	struct ll_entry *next;
} ll_entry_t;

typedef struct linked_list {
	size_t size;
	ll_entry_t *head;
	ll_entry_t *tail;
} linked_list_t;

void ll_init(linked_list_t *list);

linked_list_t *ll_alloc(void);

void ll_free_entries(linked_list_t *list);

void ll_free(linked_list_t *list);

bool ll_add_to_head(linked_list_t *list, ll_entry_t *entry);
bool ll_add_to_tail(linked_list_t *list, ll_entry_t *entry);

ll_entry_t *ll_remove_from_head(linked_list_t *list);
ll_entry_t *ll_remove_from_tail(linked_list_t *list);

#define queue_push(queue, entry) ll_add_to_tail(queue, entry)
#define queue_pop(queue) ll_remove_from_head(queue)

#define stack_push(stack, entry) ll_add_to_head(stack, entry)
#define stack_pop(stack) ll_remove_from_head(stack)

#endif // POKUSEW_LINKED_LIST_H
