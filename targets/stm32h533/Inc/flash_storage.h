#ifndef LIONKEY_STM32H533_FLASH_STORAGE_H
#define LIONKEY_STM32H533_FLASH_STORAGE_H

#include "ctap_storage.h"

typedef struct stm32h533_flash_storage_context {
	uint32_t write_address;
	uint32_t counter_write_address;
} stm32h533_flash_storage_context_t;

#define STM32H533_FLASH_STORAGE_CONST_INIT(context_ptr) \
    { \
        .context = (context_ptr), \
        .init = stm32h533_flash_storage_init, \
        .find_item = stm32h533_flash_storage_find_item, \
        .create_or_update_item = stm32h533_flash_storage_create_or_update_item, \
        .delete_item = stm32h533_flash_storage_delete_item, \
        .increment_counter = stm32h533_flash_storage_increment_counter, \
        .estimate_num_remaining_items = stm32h533_flash_storage_estimate_num_remaining_items, \
        .erase = stm32h533_flash_storage_erase, \
    }

ctap_storage_status_t stm32h533_flash_storage_init(
	const ctap_storage_t *storage
);

ctap_storage_status_t stm32h533_flash_storage_find_item(
	const ctap_storage_t *storage,
	ctap_storage_item_t *item
);

ctap_storage_status_t stm32h533_flash_storage_create_or_update_item(
	const ctap_storage_t *storage,
	ctap_storage_item_t *item
);

ctap_storage_status_t stm32h533_flash_storage_delete_item(
	const ctap_storage_t *storage,
	uint32_t item_handle
);

ctap_storage_status_t stm32h533_flash_storage_increment_counter(
	const ctap_storage_t *storage,
	uint32_t increment,
	uint32_t *counter_new_value
);

size_t stm32h533_flash_storage_estimate_num_remaining_items(
	const ctap_storage_t *storage,
	const ctap_storage_item_t *item
);

ctap_storage_status_t stm32h533_flash_storage_erase(
	const ctap_storage_t *storage
);

#endif // LIONKEY_STM32H533_FLASH_STORAGE_H
