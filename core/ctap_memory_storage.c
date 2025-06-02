#include "ctap_memory_storage.h"
#include "utils.h"
#include <string.h>

typedef struct LION_ATTR_PACKED ctap_memory_storage_item_header {
	uint32_t key;
	uint32_t size;
	uint32_t is_deleted;
	uint32_t padding;
} ctap_memory_storage_item_header_t;
static const size_t item_header_size = sizeof(ctap_memory_storage_item_header_t);
static_assert(
	sizeof(ctap_memory_storage_item_header_t) % 4 == 0,
	"sizeof(ctap_memory_storage_item_header_t) % 4 == 0"
);
static_assert(
	sizeof(ctap_memory_storage_item_header_t) % 8 == 0,
	"sizeof(ctap_memory_storage_item_header_t) % 8 == 0"
);


LION_ATTR_ALWAYS_INLINE static inline uint32_t handle_to_index(const uint32_t handle) {
	assert(handle > 0);
	return handle - 1;
}

LION_ATTR_ALWAYS_INLINE static inline uint32_t index_to_handle(const uint32_t index) {
	return index + 1;
}

LION_ATTR_ALWAYS_INLINE static inline uint32_t ceil_size_to_boundary(const size_t size) {
	static_assert((((0) + 3) & (~0x3u)) == 0, "ceil_size_to_boundary()");
	static_assert((((1) + 3) & (~0x3u)) == 4, "ceil_size_to_boundary()");
	static_assert((((2) + 3) & (~0x3u)) == 4, "ceil_size_to_boundary()");
	static_assert((((3) + 3) & (~0x3u)) == 4, "ceil_size_to_boundary()");
	static_assert((((4) + 3) & (~0x3u)) == 4, "ceil_size_to_boundary()");
	static_assert((((5) + 3) & (~0x3u)) == 8, "ceil_size_to_boundary()");
	static_assert((((6) + 3) & (~0x3u)) == 8, "ceil_size_to_boundary()");
	static_assert((((7) + 3) & (~0x3u)) == 8, "ceil_size_to_boundary()");
	static_assert((((8) + 3) & (~0x3u)) == 8, "ceil_size_to_boundary()");
	static_assert((((9) + 3) & (~0x3u)) == 12, "ceil_size_to_boundary()");
	return (size + 3) & (~0x3u);
}

LION_ATTR_ALWAYS_INLINE static inline size_t compute_total_item_size(const size_t size) {
	return item_header_size + ceil_size_to_boundary(size);
}

static uint32_t ctap_memory_storage_find_write_index(
	const ctap_storage_t *const storage
) {

	ctap_storage_item_t item = {
		.handle = 0u,
		.key = 0u,
	};

	while (ctap_memory_storage_find_item(storage, &item) == CTAP_STORAGE_OK) {
		// reset "search criteria" and continue iterating over the items
		item.key = 0u;
	}

	if (item.key != 0u) {
		return handle_to_index(item.handle) + compute_total_item_size(item.size);
	}

	assert(item.handle == 0u);

	return 0u;

}

ctap_storage_status_t ctap_memory_storage_init(
	const ctap_storage_t *const storage
) {
	ctap_memory_storage_context_t *context = storage->context;
	context->write_index = ctap_memory_storage_find_write_index(storage);
	return CTAP_STORAGE_OK;
}

ctap_storage_status_t ctap_memory_storage_find_item(
	const ctap_storage_t *const storage,
	ctap_storage_item_t *const item
) {

	ctap_memory_storage_context_t *context = storage->context;

	size_t index = 0u;

	// continue iteration
	if (item->handle != 0u) {
		index = handle_to_index(item->handle) + compute_total_item_size(item->size);
		assert(index <= context->write_index);
	}

	while (index < context->write_index) {

		const ctap_memory_storage_item_header_t *const header =
			(ctap_memory_storage_item_header_t *) &context->memory[index];
		const uint8_t *const data = &context->memory[index + item_header_size];

		if (header->key == 0u) {
			break;
		}

		if (header->is_deleted == 0u && (item->key == 0u || item->key == header->key)) {
			item->handle = index_to_handle(index);
			item->key = header->key;
			item->size = header->size;
			item->data = data;
			return CTAP_STORAGE_OK;
		}

		// next item
		index += compute_total_item_size(header->size);

	}

	return CTAP_STORAGE_ITEM_NOT_FOUND;

}

static ctap_storage_status_t ctap_memory_storage_create_item(
	const ctap_storage_t *const storage,
	ctap_storage_item_t *const item
) {

	assert(item->key != 0u);
	assert(item->size == 0u || item->data != NULL);

	ctap_memory_storage_context_t *context = storage->context;

	const size_t total_item_size = compute_total_item_size(item->size);

	if (context->write_index + total_item_size > context->memory_size) {
		// TODO: implement compaction
		error_log(red("ctap_memory_storage_create_item: out of memory") nl);
		return CTAP_STORAGE_OUT_OF_MEMORY_ERROR;
	}

	ctap_memory_storage_item_header_t *header = (ctap_memory_storage_item_header_t *)
		&context->memory[context->write_index];
	header->key = item->key;
	header->size = item->size;
	header->is_deleted = 0u;
	if (item->size > 0) {
		memcpy(
			&context->memory[context->write_index + item_header_size],
			item->data,
			item->size
		);
	}

	// update the item
	item->handle = index_to_handle(context->write_index);
	item->data = &context->memory[context->write_index + item_header_size];

	context->write_index += total_item_size;

	return CTAP_STORAGE_OK;

}

ctap_storage_status_t ctap_memory_storage_create_or_update_item(
	const ctap_storage_t *const storage,
	ctap_storage_item_t *const item
) {

	assert(item->key != 0u);

	if (item->handle != 0u) {
		ctap_storage_item_t new_item = *item;
		if (ctap_memory_storage_create_item(storage, &new_item) != CTAP_STORAGE_OK) {
			return CTAP_STORAGE_ERROR;
		}
		if (ctap_memory_storage_delete_item(storage, item->handle) != CTAP_STORAGE_OK) {
			return CTAP_STORAGE_ERROR;
		}
		*item = new_item;
		return CTAP_STORAGE_OK;
	}

	return ctap_memory_storage_create_item(storage, item);

}

ctap_storage_status_t ctap_memory_storage_delete_item(
	const ctap_storage_t *const storage,
	const uint32_t item_handle
) {

	ctap_memory_storage_context_t *context = storage->context;

	assert(item_handle > 0);

	const uint32_t index = handle_to_index(item_handle);

	assert(index < context->write_index);

	ctap_memory_storage_item_header_t *header = (ctap_memory_storage_item_header_t *)
		&context->memory[index];
	header->is_deleted = 1u;

	return CTAP_STORAGE_OK;

}

ctap_storage_status_t ctap_memory_storage_increment_counter(
	const ctap_storage_t *const storage,
	const uint32_t increment,
	uint32_t *const counter_new_value
) {
	ctap_storage_item_t item = {
		.handle = 0u,
		.key = CTAP_STORAGE_KEY_GLOBAL_SIGNATURE_COUNTER,
	};

	uint32_t tmp_counter_value = 0u;

	if (ctap_memory_storage_find_item(storage, &item) == CTAP_STORAGE_OK) {
		assert(item.size == sizeof(uint32_t));
		tmp_counter_value = *((uint32_t *) item.data);
	}

	tmp_counter_value += increment;

	item.size = sizeof(uint32_t);
	item.data = (const uint8_t *) &tmp_counter_value;

	if (ctap_memory_storage_create_or_update_item(storage, &item) == CTAP_STORAGE_OK) {
		*counter_new_value = *((uint32_t *) item.data);
		assert(*counter_new_value == tmp_counter_value);
		return CTAP_STORAGE_OK;
	}

	return CTAP_STORAGE_ERROR;

}

size_t ctap_memory_storage_estimate_num_remaining_items(
	const ctap_storage_t *const storage,
	const ctap_storage_item_t *const item
) {

	ctap_memory_storage_context_t *context = storage->context;

	const size_t total_item_size = compute_total_item_size(item->size);
	const size_t remaining_memory_size = context->memory_size - context->write_index;

	return remaining_memory_size / total_item_size;

}

ctap_storage_status_t ctap_memory_storage_erase(
	const ctap_storage_t *const storage
) {

	ctap_memory_storage_context_t *context = storage->context;

	if (context->write_index > 0) {
		memset(context->memory, 0, context->write_index);
		context->write_index = 0;
	}

	return CTAP_STORAGE_OK;

}
