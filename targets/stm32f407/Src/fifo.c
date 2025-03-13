#include "fifo.h"
#include <memory.h>

// FIFO_CREATE(debug,4096,1)
// FIFO_CREATE(hidmsg,100,64)
// FIFO_CREATE(test,10,100)

RingBuffer hidmsg_buffer;

// https://github.com/cnoviello/mastering-stm32/blob/master/nucleo-f103RB/Middlewares/RingBuffer/ringbuffer.c

size_t RingBuffer_GetFreeSpace(RingBuffer *buf) {
	if (buf->tail == buf->head) {
		return RING_BUFFER_LENGTH - 1;
	}

	if (buf->head > buf->tail) {
		return RING_BUFFER_LENGTH - ((buf->head - buf->tail) + 1);
	} else {
		return (buf->tail - buf->head) - 1;
	}
}

size_t RingBuffer_GetDataLength(RingBuffer *buf) {
	return RING_BUFFER_LENGTH - (RingBuffer_GetFreeSpace(buf) + 1);
}


void RingBuffer_Init(RingBuffer *buf) {
	buf->head = buf->tail = 0;
	memset(buf->buf, 0, RING_BUFFER_LENGTH);
}

size_t RingBuffer_Read(RingBuffer *buf, uint8_t *data, const size_t len) {

	size_t counter = 0;

	while (buf->tail != buf->head && counter < len) {
		data[counter++] = buf->buf[buf->tail];
		buf->tail = (buf->tail + 1) % RING_BUFFER_LENGTH;
	}

	return counter;

}

RingBuffer_Status RingBuffer_Write(RingBuffer *buf, const uint8_t *data, const size_t len) {

	size_t counter = 0;
	size_t free_space = RingBuffer_GetFreeSpace(buf);

	if (free_space == 0) {
		return RING_BUFFER_FULL;
	} else if (free_space < len) {
		return RING_BUFFER_NO_SUFFICIENT_SPACE;
	}

	while (counter < len) {
		buf->buf[buf->head] = data[counter++];
		buf->head = (buf->head + 1) % RING_BUFFER_LENGTH;
	}

	return RING_BUFFER_OK;

}
