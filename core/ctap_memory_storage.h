#ifndef LIONKEY_CTAP_MEMORY_STORAGE_H
#define LIONKEY_CTAP_MEMORY_STORAGE_H

#include "ctap_storage.h"

typedef struct ctap_memory_storage_context {
	const size_t memory_size;
	uint8_t *const memory;
	size_t write_index;
} ctap_memory_storage_context_t;

#define CTAP_MEMORY_STORAGE_CONST_INIT(context_ptr) \
    { \
        .context = (context_ptr), \
        .init = ctap_memory_storage_init, \
        .find_item = ctap_memory_storage_find_item, \
        .create_or_update_item = ctap_memory_storage_create_or_update_item, \
        .delete_item = ctap_memory_storage_delete_item, \
        .increment_counter = ctap_memory_storage_increment_counter, \
        .estimate_num_remaining_items = ctap_memory_storage_estimate_num_remaining_items, \
        .erase = ctap_memory_storage_erase, \
    }

ctap_storage_status_t ctap_memory_storage_init(
	const ctap_storage_t *storage
);

ctap_storage_status_t ctap_memory_storage_find_item(
	const ctap_storage_t *storage,
	ctap_storage_item_t *item
);

ctap_storage_status_t ctap_memory_storage_create_or_update_item(
	const ctap_storage_t *storage,
	ctap_storage_item_t *item
);

ctap_storage_status_t ctap_memory_storage_delete_item(
	const ctap_storage_t *storage,
	uint32_t item_handle
);

ctap_storage_status_t ctap_memory_storage_increment_counter(
	const ctap_storage_t *storage,
	uint32_t increment,
	uint32_t *counter_new_value
);

size_t ctap_memory_storage_estimate_num_remaining_items(
	const ctap_storage_t *storage,
	const ctap_storage_item_t *item
);

ctap_storage_status_t ctap_memory_storage_erase(
	const ctap_storage_t *storage
);

#endif // LIONKEY_CTAP_MEMORY_STORAGE_H
