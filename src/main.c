#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <zlib.h>

#include "arena.h"
#include "base.h"
#include "base_string.h"

#define CHUNK 16384

internal int init() {
  // You can use print statements as follows for debugging, they'll be visible
  // when running tests.
  fprintf(stderr, "Logs from your program will appear here!\n");

  if (mkdir(".git", 0755) == -1 || mkdir(".git/objects", 0755) == -1 ||
      mkdir(".git/refs", 0755) == -1) {
    fprintf(stderr, "Failed to create directories: %s\n", strerror(errno));
    return 1;
  }

  FILE *headFile = fopen(".git/HEAD", "w");
  if (headFile == NULL) {
    fprintf(stderr, "Failed to create .git/HEAD file: %s\n", strerror(errno));
    return 1;
  }
  fprintf(headFile, "ref: refs/heads/main\n");
  fclose(headFile);

  printf("Initialized git directory\n");

  return 0;
}

// use zlib to decompress object and print
internal int decompress_object(Arena *a, String object_path) {
  TempArenaMemory temp = temp_arena_memory_begin(a);

  const char *path = to_cstring(a, object_path);
  FILE *file = fopen(path, "rb");
  if (file == NULL) {
    fprintf(stderr, "object %s not found\n", path);
    return -1;
  }

  // https://zlib.net/zlib_how.html
  z_stream stream = {0};
  int ret = inflateInit(&stream);
  if (ret != Z_OK) {
    fprintf(stderr, "Inflate failure\n");
    return ret;
  }

  uint8_t *inbuf = arena_alloc(a, CHUNK);
  uint8_t *outbuf = arena_alloc(a, CHUNK);

  uint8_t *databuf = NULL;
  uint64_t databuf_size = 0;

  do {
    stream.avail_in = fread(inbuf, sizeof(uint8_t), CHUNK, file);
    if (ferror(file)) {
      inflateEnd(&stream);
      return -1;
    }
    if (stream.avail_in == 0) {
      break;
    }

    int flush = feof(file) ? Z_FINISH : Z_NO_FLUSH;
    stream.next_in = inbuf;

    do {
      stream.avail_out = CHUNK;
      stream.next_out = outbuf;

      ret = inflate(&stream, flush);
      if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR) {
        inflateEnd(&stream);
        return ret;
      }

      int have = CHUNK - stream.avail_out;

      uint8_t *ptr = outbuf;
      if (databuf == NULL) {
        while (*ptr != '\0')
          ++ptr;
        ++ptr;

        String header = {
            .str = outbuf,
            .size = ptr - outbuf,
        };
        have -= header.size;

        // blob <size>\0<content>
        String blob_size = str_substr(header, 5, header.size);
        int size = atoi(to_cstring(a, blob_size));
        databuf = arena_alloc(a, size);
      }
      memcpy(databuf + databuf_size, ptr, have);
      databuf_size += have;

    } while (stream.avail_out == 0);

  } while (ret != Z_STREAM_END);

  fwrite(databuf, databuf_size, sizeof(uint8_t), stdout);

  inflateEnd(&stream);
  fclose(file);

  temp_arena_memory_end(temp);

  return 0;
}

internal int cat_file(Arena *a, const char *object_type,
                      const char *object_hash) {
  assert(strcmp(object_type, "-p") == 0);

  String hash = str_init(object_hash, strlen(object_hash));
  StringArray paths = {0};
  str_array_push(a, &paths, str_clone_from_cstring(a, ".git/objects"));
  str_array_push(a, &paths, str_substr(hash, 0, 2));
  str_array_push(a, &paths, str_substr(hash, 2, hash.size));

  String object_path =
      str_array_join(a, &paths, str_clone_from_cstring(a, "/"));

  decompress_object(a, object_path);

  return 0;
}

int main(int argc, char *argv[]) {
  // Disable output buffering
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  uint8_t *arena_backing_buffer = (uint8_t *)malloc(4 * MB);
  Arena arena = {0};
  arena_init(&arena, arena_backing_buffer, 4 * MB);

  if (argc < 2) {
    fprintf(stderr, "Usage: %s <command> [<args>]\n", argv[0]);
    return 1;
  }

  const char *command = argv[1];

  if (strcmp(command, "init") == 0) {
    return init();
  } else if (strcmp(command, "cat-file") == 0) {
    assert(argc == 4);

    return cat_file(&arena, argv[2], argv[3]);
  } else {
    fprintf(stderr, "Unknown command %s\n", command);
    return 1;
  }

  free(arena_backing_buffer);

  return 0;
}
