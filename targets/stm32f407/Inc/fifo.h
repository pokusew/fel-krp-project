#ifndef FIDO2_FIFO_H
#define FIDO2_FIFO_H

#include <stdint.h>
#include <stddef.h>

#define RING_BUFFER_LENGTH (100 * 64)

typedef struct {
	uint8_t buf[RING_BUFFER_LENGTH];
	size_t head;
	size_t tail;
} RingBuffer;

typedef enum {
	RING_BUFFER_OK = 0x0,
	RING_BUFFER_FULL,
	RING_BUFFER_NO_SUFFICIENT_SPACE
} RingBuffer_Status;

extern RingBuffer hidmsg_buffer;

size_t RingBuffer_GetDataLength(RingBuffer *buf);

size_t RingBuffer_GetFreeSpace(RingBuffer *buf);

void RingBuffer_Init(RingBuffer *buf);

size_t RingBuffer_Read(RingBuffer *buf, uint8_t *data, const size_t len);

RingBuffer_Status RingBuffer_Write(RingBuffer *buf, const uint8_t *data, const size_t len);

#endif // FIDO2_FIFO_H
