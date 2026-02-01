#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/evp.h>
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
// decompressed data will be written into dest
// returns: number of bytes decompressed into dest
internal int decompress_object(Arena *a, const char *object_type,
                               String object_path, uint8_t **dest) {
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

  uint64_t bytes_decompressed = 0;
  uint64_t object_size = 0;

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
      if (*dest == NULL) {
        while (*ptr != '\0')
          ++ptr;
        ++ptr;

        String header = {
            .str = outbuf,
            .size = ptr - outbuf,
        };
        have -= header.size;

        // <object_type> <size>\0<content>
        String blob_size =
            str_substr(header, strlen(object_type) + 1, header.size);
        object_size = atoi(to_cstring(a, blob_size));
        *dest = arena_alloc(a, object_size);
      }
      memcpy((*dest) + bytes_decompressed, ptr, have);
      bytes_decompressed += have;

    } while (stream.avail_out == 0);

  } while (ret != Z_STREAM_END);

  assert(bytes_decompressed == object_size);

  inflateEnd(&stream);
  fclose(file);

  return bytes_decompressed;
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

  uint8_t *content = NULL;
  uint64_t bytes_decompressed =
      decompress_object(a, "blob", object_path, &content);

  fwrite(content, sizeof(uint8_t), bytes_decompressed, stdout);

  return 0;
}

internal long get_file_size(FILE *fp) {
  if (fp == NULL) {
    return -1;
  }

  if (fseek(fp, 0L, SEEK_END) != 0) {
    return -1; // Error (e.g., if fp is stdin)
  }

  // 2. Get the current byte position
  long size = ftell(fp);

  // 3. Go back to the start so you can actually read the data
  rewind(fp);

  return size;
}

internal int hash_object(Arena *a, const char *flag, const char *file_name) {
  // TOOD: this is not always true, user can only hash and do not write to git
  // objects
  assert(strcmp(flag, "-w") == 0);

  // TODO: limitation 8192 characters for stdin, may need to store to tmp_file
  // to improve this.
  uint8_t *stdin_buffer = arena_alloc(a, 8192);

  FILE *file = NULL;
  if (strcmp(file_name, "--stdin") == 0) {
    int bytes_read = fread(stdin_buffer, sizeof(uint8_t), 8192, stdin);
    file = fmemopen(stdin_buffer, bytes_read, "rb");
  } else {
    file = fopen(file_name, "rb");
  }

  char tmp[] = ".git/objects/tmp_obj_XXXXXX";
  int tmp_fd = mkstemp(tmp);

  // calculate header
  long file_size = get_file_size(file);
  if (file_size < 0) {
    return -1;
  }

  String header = {0};
  header.str = arena_alloc(a, 256);
  header.size = snprintf((char *)header.str, 256, "blob %ld", file_size);
  header.size++; // include the '\0' at the end

  // do streaming SHA1 and zlib deflate
  uint8_t *inbuf = arena_alloc(a, CHUNK);
  uint8_t *outbuf = arena_alloc(a, CHUNK);

  z_stream stream = {0};
  int ret = deflateInit(&stream, Z_DEFAULT_COMPRESSION);
  int flush = Z_NO_FLUSH;
  if (ret != Z_OK) {
    fprintf(stderr, "Deflate init failure\n");
    return ret;
  }

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (mdctx == NULL) {
    fprintf(stderr, "Failed to create message digest context\n");
    deflateEnd(&stream);
    close(tmp_fd);
    fclose(file);
    return -1;
  }
  EVP_DigestInit(mdctx, EVP_sha1());

  // process header
  EVP_DigestUpdate(mdctx, header.str, header.size);

  stream.avail_in = header.size;
  stream.next_in = header.str;
  stream.next_out = outbuf;
  stream.avail_out = CHUNK;

  ret = deflate(&stream, flush);

  int have = CHUNK - stream.avail_out;
  write(tmp_fd, outbuf, have);

  // process content
  do {
    int bytes_read = fread(inbuf, sizeof(uint8_t), CHUNK, file);
    stream.avail_in = bytes_read;

    // do sha1 too
    EVP_DigestUpdate(mdctx, inbuf, bytes_read);

    if (ferror(file)) {
      deflateEnd(&stream);
      return -1;
    }
    if (stream.avail_in == 0) {
      break;
    }

    flush = feof(file) ? Z_FINISH : Z_NO_FLUSH;
    stream.next_in = inbuf;

    do {
      stream.avail_out = CHUNK;
      stream.next_out = outbuf;

      ret = deflate(&stream, flush);
      if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR) {
        deflateEnd(&stream);
        return ret;
      }

      int have = CHUNK - stream.avail_out;
      write(tmp_fd, outbuf, have);

    } while (stream.avail_out == 0);

    assert(stream.avail_in == 0);

  } while (ret != Z_STREAM_END);

  uint8_t sha1_digest[EVP_MAX_MD_SIZE];
  uint32_t hash_len;
  EVP_DigestFinal(mdctx, sha1_digest, &hash_len);

  char sha1_hex_sum[EVP_MAX_MD_SIZE * 2 + 1];
  for (int i = 0; i < hash_len; i++) {
    snprintf(sha1_hex_sum + 2 * i, sizeof(sha1_hex_sum), "%02x",
             sha1_digest[i]);
  }

  // create the object
  char object_dir[128];
  snprintf(object_dir, sizeof(object_dir), ".git/objects/%.2s", sha1_hex_sum);

  char object_path[128];
  snprintf(object_path, sizeof(object_path), "%s/%.38s", object_dir,
           sha1_hex_sum + 2);

  printf("%s\n", sha1_hex_sum);

  if (mkdir(object_dir, 0755) == -1 && errno != EEXIST) {
    perror("Failed to create object directory");
    return -1;
  }
  if (rename(tmp, object_path) == -1) {
    perror("rename");
  }

  // clean up
  EVP_MD_CTX_free(mdctx);
  deflateEnd(&stream);
  if (file != NULL) {
    fclose(file);
  }
  close(tmp_fd);

  return 0;
}

typedef struct Tree_Entry Tree_Entry;
struct Tree_Entry {
  String mode;
  String type;
  String name;
  String sha;
};

typedef struct Tree_Entry_Array Tree_Entry_Array;
struct Tree_Entry_Array {
  Tree_Entry *items;
  uint64_t count;
  uint64_t capacity;
};

internal void tree_entry_array_push(Arena *a, Tree_Entry_Array *arr,
                                    Tree_Entry entry) {
  if (arr->count >= arr->capacity) {
    uint64_t new_cap = arr->capacity == 0 ? 8 : arr->capacity * 2;
    Tree_Entry *new_items =
        (Tree_Entry *)arena_alloc(a, sizeof(Tree_Entry) * new_cap);
    if (arr->items != NULL) {
      memcpy(new_items, arr->items, sizeof(Tree_Entry) * arr->count);
    }
    arr->items = new_items;
    arr->capacity = new_cap;
  }
  arr->items[arr->count++] = entry;
}

internal int ls_tree(Arena *a, int argc, char *argv[]) {
  char *tree_sha = argv[argc - 1];
  bool name_only = strcmp(argv[2], "--name-only") == 0;

  String hash = str_init(tree_sha, strlen(tree_sha));
  StringArray paths = {0};
  str_array_push(a, &paths, str_clone_from_cstring(a, ".git/objects"));
  str_array_push(a, &paths, str_substr(hash, 0, 2));
  str_array_push(a, &paths, str_substr(hash, 2, hash.size));

  String object_path =
      str_array_join(a, &paths, str_clone_from_cstring(a, "/"));

  Tree_Entry_Array entries = {0};

  // decompress
  uint8_t *content = NULL;
  uint64_t bytes_decompressed =
      decompress_object(a, "tree", object_path, &content);

  int index = 0;
  while (index < bytes_decompressed) {
    // mode
    int mode_end = index;
    while (mode_end < bytes_decompressed && content[mode_end] != ' ') {
      ++mode_end;
    }

    String mode_str = {
        .str = content + index,
        .size = mode_end - index,
    };
    if (mode_str.size <= 0) {
      break;
    }

    // name
    int name_start = mode_end + 1;
    int name_end = mode_end + 1;
    while (name_end < bytes_decompressed && content[name_end] != '\0') {
      ++name_end;
    }

    String name_str = {
        .str = content + name_start,
        .size = name_end - name_start,
    };
    if (name_str.size <= 0) {
      break;
    }

    // sha
    int sha_start = name_end + 1;
    int sha_end = sha_start + 20;
    if (sha_end > bytes_decompressed) {
      break;
    }

    String sha_str = {
        .str = content + sha_start,
        .size = 20,
    };

    String type_str =
        str_init(str_equal_cstr(mode_str, "040000") ? "tree" : "blob", 4);

    char *sha_buf = arena_alloc(a, 40);
    for (int i = 0; i < 20; i++) {
      snprintf(sha_buf + 2 * i, 3, "%02x", sha_str.str[i]);
    }
    String sha = {
        .str = (uint8_t *)sha_buf,
        .size = 40,
    };

    Tree_Entry entry = {
        .mode = mode_str, .type = type_str, .name = name_str, .sha = sha};
    tree_entry_array_push(a, &entries, entry);

    index = sha_end;
  }

  for (int i = 0; i < entries.count; ++i) {
    Tree_Entry entry = entries.items[i];

    if (name_only) {
      printf("%.*s\n", (int)entry.name.size, entry.name.str);
    } else {
      printf("%.*s %.*s %.*s\t%.*s\n", (int)entry.mode.size, entry.mode.str,
             (int)entry.type.size, entry.type.str, (int)entry.sha.size,
             entry.sha.str, (int)entry.name.size, entry.name.str);
    }
  }

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

  int result = 0;

  if (strcmp(command, "init") == 0) {
    result = init();
  } else if (strcmp(command, "cat-file") == 0) {
    if (argc < 4) {
      fprintf(stderr, "Usage: %s cat-file <type> <hash>\n", argv[0]);
      result = 1;
    } else {
      result = cat_file(&arena, argv[2], argv[3]);
    }
  } else if (strcmp(command, "hash-object") == 0) {
    if (argc < 4) {
      fprintf(stderr, "Usage: %s hash-object <flag> <file>\n", argv[0]);
      result = 1;
    } else {
      result = hash_object(&arena, argv[2], argv[3]);
    }
  } else if (strcmp(command, "ls-tree") == 0) {
    if (argc < 3) {
      fprintf(stderr, "Usage: %s ls-tree [--name-only] <hash>\n", argv[0]);
      result = 1;
    } else {
      result = ls_tree(&arena, argc, argv);
    }
  } else {
    fprintf(stderr, "Unknown command %s\n", command);
    result = 1;
  }

  free(arena_backing_buffer);

  return result;
}
