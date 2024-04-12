#include "linked_list.h"

void ll_init(linked_list_t *list) {
	list->size = 0;
	list->head = NULL;
	list->tail = NULL;
}

linked_list_t *ll_alloc(void) {

	linked_list_t *list = (linked_list_t *) malloc(sizeof(linked_list_t));

	if (list == NULL) {
		return NULL;
	}

	ll_init(list);

	return list;

}

void ll_free_entries(linked_list_t *list) {

	if (list == NULL) {
		return;
	}

	ll_entry_t *entry = list->head;

	ll_init(list);

	while (entry != NULL) {
		ll_entry_t *next = entry->next;
		free(entry);
		entry = next;
	}

}

void ll_free(linked_list_t *list) {

	ll_free_entries(list);

	free(list);

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
