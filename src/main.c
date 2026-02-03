#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <dirent.h>
#include <openssl/evp.h>
#include <unistd.h>
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
  int fd = fileno(fp);
  if (fd == -1) {
    return -1;
  }

  struct stat st;
  if (fstat(fd, &st) == 0) {
    return st.st_size;
  }

  return -1;
}

internal String get_object_file_path(Arena *a, String sha1) {
  StringArray paths = {0};
  str_array_push(a, &paths, str_clone_from_cstring(a, ".git/objects"));
  str_array_push(a, &paths, str_substr(sha1, 0, 2));
  str_array_push(a, &paths, str_substr(sha1, 2, sha1.size));

  String object_path =
      str_array_join(a, &paths, str_clone_from_cstring(a, "/"));

  return object_path;
}

internal String calc_header(Arena *a, const char *object_type, FILE *fp) {
  String header = {0};
  // calculate header
  long file_size = get_file_size(fp);
  if (file_size < 0) {
    return header;
  }

  header.str = arena_alloc(a, 256);
  header.size =
      snprintf((char *)header.str, 256, "%s %ld", object_type, file_size);
  header.size++; // include the '\0' at the end
  return header;
}

internal String calc_sha1(Arena *a, const char *object_type, FILE *fp) {
  String header = calc_header(a, object_type, fp);
  String sha1 = {0};

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (mdctx == NULL) {
    fprintf(stderr, "Failed to create message digest context\n");
    return sha1;
  }

  EVP_DigestInit(mdctx, EVP_sha1());

  // process header
  EVP_DigestUpdate(mdctx, header.str, header.size);

  int bytes_read = 0;
  char buffer[CHUNK];

  while ((bytes_read = fread(buffer, sizeof(char), CHUNK, fp)) > 0) {
    // do sha1 too
    EVP_DigestUpdate(mdctx, buffer, bytes_read);
  }

  uint8_t sha1_digest[EVP_MAX_MD_SIZE];
  uint32_t hash_len;
  EVP_DigestFinal(mdctx, sha1_digest, &hash_len);

  uint8_t *sha1_hex_sum = arena_alloc(a, EVP_MAX_MD_SIZE * 2);
  for (int i = 0; i < hash_len; i++) {
    snprintf((char *)sha1_hex_sum + 2 * i, sizeof(sha1_hex_sum), "%02x",
             sha1_digest[i]);
  }

  sha1.str = sha1_hex_sum;
  sha1.size = EVP_MAX_MD_SIZE * 2;

  EVP_MD_CTX_destroy(mdctx);
  rewind(fp);

  return sha1;
}

internal int write_object(Arena *a, FILE *infile, const char *object_type,
                          String sha1) {
  TempArenaMemory temp = temp_arena_memory_begin(a);

  String header = calc_header(a, object_type, infile);

  char *object_file_path = to_cstring(a, get_object_file_path(a, sha1));

  char object_dir[128];
  snprintf(object_dir, sizeof(object_dir), ".git/objects/%.2s", sha1.str);
  if (mkdir(object_dir, 0755) == -1 && errno != EEXIST) {
    perror("Failed to create object directory");
    return -1;
  }

  FILE *outfile = fopen(object_file_path, "wb");
  if (outfile == NULL) {
    return -1;
  }

  // do streaming zlib deflate
  uint8_t *inbuf = arena_alloc(a, CHUNK);
  uint8_t *outbuf = arena_alloc(a, CHUNK);

  z_stream stream = {0};
  int ret = deflateInit(&stream, Z_DEFAULT_COMPRESSION);
  int flush = Z_NO_FLUSH;
  if (ret != Z_OK) {
    fprintf(stderr, "Deflate init failure\n");
    return ret;
  }

  stream.avail_in = header.size;
  stream.next_in = header.str;
  stream.next_out = outbuf;
  stream.avail_out = CHUNK;

  ret = deflate(&stream, flush);

  int have = CHUNK - stream.avail_out;
  fwrite(outbuf, sizeof(uint8_t), have, outfile);

  // process content
  do {
    int bytes_read = fread(inbuf, sizeof(uint8_t), CHUNK, infile);
    stream.avail_in = bytes_read;

    if (ferror(infile)) {
      deflateEnd(&stream);
      return -1;
    }
    if (stream.avail_in == 0) {
      break;
    }

    flush = feof(infile) ? Z_FINISH : Z_NO_FLUSH;
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
      fwrite(outbuf, sizeof(uint8_t), have, outfile);

    } while (stream.avail_out == 0);

    assert(stream.avail_in == 0);

  } while (ret != Z_STREAM_END);

  // clean up
  deflateEnd(&stream);
  fclose(outfile);
  rewind(infile);

  temp_arena_memory_end(temp);

  return 0;
}

internal String hash_object(Arena *a, const char *flag, const char *file_name) {
  // TOOD: this is not always true, user can only hash and do not write to git
  // objects
  assert(strcmp(flag, "-w") == 0);

  FILE *file = NULL;
  if (strcmp(file_name, "--stdin") == 0) {
    file = tmpfile();
    char buffer[4092];

    ssize_t n;
    while ((n = fread(buffer, sizeof(char), sizeof(buffer), stdin)) > 0) {
      fwrite(buffer, sizeof(char), n, file);
    }
  } else {
    file = fopen(file_name, "rb");
  }

  String sha1 = calc_sha1(a, "blob", file);
  int ret = write_object(a, file, "blob", sha1);

  // if it's a tmp file, it will be deleted
  if (file != NULL) {
    fclose(file);
  }

  return sha1;
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

    bool is_tree = str_equal_cstr(mode_str, "40000");
    String type_str = str_init(is_tree ? "tree" : "blob", 4);
    if (is_tree) {
      mode_str = str_init("040000", 6);
    }

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

internal String write_tree_object(Arena *a, const char *dirname) {
  struct dirent *dir_entry;
  DIR *dp = opendir(dirname);

  String tree_sha1 = {0};

  if (dp == NULL) {
    perror(dirname);
    return tree_sha1;
  }

  FILE *tmp_out_file = tmpfile();

  while ((dir_entry = readdir(dp)) != NULL) {
    if (strcmp(dir_entry->d_name, ".") == 0 ||
        strcmp(dir_entry->d_name, "..") == 0 ||
        strcmp(dir_entry->d_name, ".git") == 0) {
      continue;
    }

    String entry_name = str_clone_from_cstring(a, dir_entry->d_name);
    String entry_sha1 = {0};
    String entry_mode = {0};
    char file_path[4096];
    snprintf(file_path, sizeof(file_path), "%s/%s", dirname, dir_entry->d_name);

    // TODO: unify the API a bit, currently it's a bit messy
    if (dir_entry->d_type == DT_DIR) {
      entry_mode = str_init("40000", 5);
      entry_sha1 = write_tree_object(a, file_path);
    } else if (dir_entry->d_type == DT_LNK) {
      entry_mode = str_init("120000", 6);
      // file path is the content
      FILE *content_fp = fmemopen(file_path, strlen(file_path), "rb");
      entry_sha1 = calc_sha1(a, "blob", content_fp);
      write_object(a, content_fp, "blob", entry_sha1);

      fclose(content_fp);
    } else if (dir_entry->d_type == DT_REG) {
      if (access(file_path, X_OK) == 0) {
        entry_mode = str_init("100755", 6);
      } else {
        entry_mode = str_init("100644", 6);
      }
      entry_sha1 = hash_object(a, "-w", file_path);
    }

    // Convert hex SHA to raw 20 bytes
    uint8_t *sha_raw = arena_alloc(a, 20);
    for (int i = 0; i < 20; i++) {
      char hex[3] = {entry_sha1.str[2 * i], entry_sha1.str[2 * i + 1], '\0'};
      sha_raw[i] = (uint8_t)strtol(hex, NULL, 16);
    }
    String sha_raw_str = {.str = sha_raw, .size = 20};

    StringArray arr = {0};
    str_array_push(a, &arr, entry_mode);
    str_array_push(a, &arr, str_init(" ", 1));
    str_array_push(a, &arr, entry_name);
    str_array_push(a, &arr, str_init("\0", 1));
    str_array_push(a, &arr, sha_raw_str);

    String output_line = str_array_join(a, &arr, str_init("", 0));

    fwrite(output_line.str, sizeof(uint8_t), output_line.size, tmp_out_file);
  }

  rewind(tmp_out_file);
  tree_sha1 = calc_sha1(a, "tree", tmp_out_file);
  write_object(a, tmp_out_file, "tree", tree_sha1);

  fclose(tmp_out_file);
  closedir(dp);

  return tree_sha1;
}

internal int write_tree(Arena *a, const char *dirname) {
  String sha1 = write_tree_object(a, dirname);
  printf("%.*s\n", (int)sha1.size, sha1.str);
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
      hash_object(&arena, argv[2], argv[3]);
    }
  } else if (strcmp(command, "ls-tree") == 0) {
    if (argc < 3) {
      fprintf(stderr, "Usage: %s ls-tree [--name-only] <hash>\n", argv[0]);
      result = 1;
    } else {
      result = ls_tree(&arena, argc, argv);
    }
  } else if (strcmp(command, "write-tree") == 0) {
    if (argc < 2) {
      fprintf(stderr, "Usage: %s write-tree\n", argv[0]);
      result = 1;
    } else {
      result = write_tree(&arena, ".");
    }
  } else {
    fprintf(stderr, "Unknown command %s\n", command);
    result = 1;
  }

  free(arena_backing_buffer);

  return result;
}
