#include "linked_list.h"

void ll_init(linked_list_t *list) {
	list->size = 0;
	list->head = NULL;
	list->tail = NULL;
}

bool ll_add_to_head(linked_list_t *list, ll_entry_t *entry) {

	if (entry == NULL) {
		return false;
	}

	list->size++;

	entry->prev = NULL;
	entry->next = list->head;

	if (entry->next == NULL) {
		list->tail = entry;
		list->head = entry;
		return true;
	}

	entry->next->prev = entry;

	list->head = entry;

	return true;

}

bool ll_add_to_tail(linked_list_t *list, ll_entry_t *entry) {

	if (entry == NULL) {
		return false;
	}

	list->size++;

	entry->prev = list->tail;
	entry->next = NULL;

	if (entry->prev == NULL) {
		list->tail = entry;
		list->head = entry;
		return true;
	}

	entry->prev->next = entry;

	list->tail = entry;

	return true;

}

ll_entry_t *ll_remove_from_head(linked_list_t *list) {

	if (list->head == NULL) {
		return NULL;
	}

	list->size--;

	ll_entry_t *entry = list->head;

	list->head = entry->next;

	if (entry->next == NULL) {
		list->tail = NULL;
	}

	entry->next = NULL;
	entry->prev = NULL;

	return entry;

}
