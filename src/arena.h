#ifndef CODECRAFTER_ARENA_H
#define CODECRAFTER_ARENA_H

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

#include "base.h"

#ifndef DEFAULT_ALIGNMENT
#define DEFAULT_ALIGNMENT (2 * sizeof(void *))
#endif

// Arena
typedef struct Arena Arena;
struct Arena {
  uint8_t *buf;
  size_t buf_size;
  size_t prev_offset;
  size_t curr_offset;
};

// align will be 2's power
internal uintptr_t align_forward(uintptr_t ptr, size_t align) {
  assert((align & (align - 1)) == 0);

  uintptr_t p = ptr;
  uintptr_t a = align;
  uintptr_t modulo = p % a;

  if (modulo != 0) {
    p = p + (a - modulo);
  }
  return p;
}

internal void arena_init(Arena *a, void *backing_buffer,
                         size_t backing_buffer_size) {
  a->buf = (uint8_t *)backing_buffer;
  a->buf_size = backing_buffer_size;
  a->curr_offset = 0;
  a->prev_offset = 0;
}

internal void *arena_alloc_align(Arena *a, size_t size, size_t align) {
  uintptr_t curr_ptr = (uintptr_t)a->buf + a->curr_offset;
  uintptr_t aligned_ptr = align_forward(curr_ptr, align);
  uintptr_t aligned_offset = aligned_ptr - (uintptr_t)a->buf;

  if (aligned_offset + size <= a->buf_size) {
    a->prev_offset = aligned_offset;
    a->curr_offset = aligned_offset + size;

    // Zero memory
    memset((void *)aligned_ptr, 0, size);
    return (void *)aligned_ptr;
  }
  return NULL;
}

internal void *arena_alloc(Arena *a, size_t size) {
  return arena_alloc_align(a, size, DEFAULT_ALIGNMENT);
}

internal void *arena_realloc(Arena *a, void *old_ptr, size_t old_size,
                             size_t new_size) {
  if (old_ptr == NULL) {
    return arena_alloc(a, new_size);
  }

  if (new_size <= old_size) {
    return old_ptr;
  }

  uintptr_t arena_start = (uintptr_t)a->buf;
  uintptr_t arena_end = arena_start + a->buf_size;
  uintptr_t old_start = (uintptr_t)old_ptr;
  if (old_start < arena_start || old_start > arena_end) {
    return NULL;
  }

  uintptr_t old_end = (uintptr_t)old_ptr + old_size;
  uintptr_t arena_curr_end = (uintptr_t)a->buf + a->curr_offset;
  void *new_ptr = NULL;

  if (old_end == arena_curr_end) {
    // old_ptr is the last allocated memory on arena, allocate the diff
    void *grow_ptr = arena_alloc_align(a, new_size - old_size, 1);
    if (grow_ptr != NULL) {
      new_ptr = old_ptr;
    }
  } else {
    new_ptr = arena_alloc(a, new_size);
    if (new_ptr != NULL) {
      memcpy(new_ptr, old_ptr, old_size);
    }
  }

  return new_ptr;
}

internal void arena_free_all(Arena *a) {
  a->curr_offset = 0;
  a->prev_offset = 0;
}

typedef struct TempArenaMemory TempArenaMemory;
struct TempArenaMemory {
  Arena *arena;
  size_t prev_offset;
  size_t curr_offset;
};

internal TempArenaMemory temp_arena_memory_begin(Arena *a) {
  TempArenaMemory temp = {
      .arena = a,
      .prev_offset = a->prev_offset,
      .curr_offset = a->curr_offset,
  };

  return temp;
}

internal void temp_arena_memory_end(TempArenaMemory temp) {
  temp.arena->prev_offset = temp.prev_offset;
  temp.arena->curr_offset = temp.curr_offset;
}

#endif
