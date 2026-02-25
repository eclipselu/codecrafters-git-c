#ifndef CLONE_H
#define CLONE_H

#include <stdbool.h>

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arena.h"
#include "base.h"
#include "base_string.h"

typedef struct CurlWriteContext CurlWriteContext;
struct CurlWriteContext {
  Arena *arena;
  String *chunk;
};

internal String str_to_pkt_line(Arena *a, String s) {
  if (s.str == NULL) {
    return str_literal("0000");
  }

  uint64_t pkt_len = s.size + 4;
  String pkt_line = {0};
  pkt_line.str = arena_alloc(a, pkt_len);
  pkt_line.size = pkt_len;

  snprintf((char *)pkt_line.str, 5, "%04lx", pkt_len);
  memcpy(pkt_line.str + 4, s.str, s.size);
  return pkt_line;
}

internal size_t curl_write_to_chunk(char *ptr, size_t size, size_t nmemb,
                                    void *userdata) {
  CurlWriteContext *ctx = (CurlWriteContext *)userdata;
  size_t bytes = size * nmemb;
  uint64_t new_size = ctx->chunk->size + bytes;
  uint64_t old_size = ctx->chunk->size;

  uint8_t *new_buf =
      arena_realloc(ctx->arena, ctx->chunk->str, old_size, new_size);
  if (new_buf == NULL) {
    return 0;
  }

  ctx->chunk->str = new_buf;
  ctx->chunk->size = new_size;

  memcpy(ctx->chunk->str + old_size, ptr, bytes);
  return bytes;
}

typedef struct PktLineParseResult PktLineParseResult;
struct PktLineParseResult {
  String pkt_line;
  uint64_t consumed;
  bool valid;
  bool is_flush;
};

internal PktLineParseResult parse_pkt_line(Arena *a, uint8_t *buf,
                                           uint64_t remaining) {
  PktLineParseResult result = {0};
  if (buf == NULL || remaining < 4) {
    return result;
  }

  char *endptr = NULL;
  char len_hex[5] = {0};
  memcpy(len_hex, buf, 4);

  int pkt_len = strtol(len_hex, &endptr, 16);
  if (endptr != (len_hex + 4) || pkt_len < 0) {
    return result;
  }

  if (pkt_len == 0) {
    result.valid = true;
    result.is_flush = true;
    result.consumed = 4;
    return result;
  }

  if (pkt_len < 4 || (uint64_t)pkt_len > remaining) {
    return result;
  }

  int actual_len = pkt_len - 4;
  result.pkt_line.str = arena_alloc(a, actual_len);
  result.pkt_line.size = actual_len;
  if (actual_len > 0) {
    memcpy(result.pkt_line.str, buf + 4, actual_len);
  }

  result.valid = true;
  result.consumed = pkt_len;
  return result;
}

internal StringArray parse_pkt_lines(Arena *a, String s) {
  StringArray result = {0};
  uint8_t *ptr = s.str;
  uint8_t *end = s.str + s.size;

  while (ptr < end) {
    uint64_t remaining = (uint64_t)(end - ptr);
    PktLineParseResult parsed = parse_pkt_line(a, ptr, remaining);
    if (!parsed.valid || parsed.consumed == 0) {
      break;
    }

    if (!parsed.is_flush) {
      str_array_push(a, &result, parsed.pkt_line);
    }

    ptr += parsed.consumed;
  }

  return result;
}

typedef struct ServerCapabilities ServerCapabilities;
struct ServerCapabilities {
  uint8_t version;
  String agent;

  struct {
    bool supported;
    bool unborn;
  } ls_refs;

  struct {
    bool supported;
    bool shallow;
    bool wait_for_done;
    bool filter;
  } fetch;

  bool server_option;
  String object_format;
};

internal ServerCapabilities capability_advertisement(Arena *a, CURL *curl,
                                                     String repo_url) {
  String query_path = str_literal("/info/refs?service=git-upload-pack");
  String url = str_concat(a, repo_url, query_path);

  struct curl_slist *headers = NULL;

  String chunk = {0};
  CurlWriteContext write_ctx = {
      .arena = a,
      .chunk = &chunk,
  };
  headers = curl_slist_append(headers, "git-protocol: version=2");
  headers = curl_slist_append(headers, "User-Agent: git/2.52.0-Linux");
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
  curl_easy_setopt(curl, CURLOPT_URL, to_cstring(a, url));
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_to_chunk);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &write_ctx);

  CURLcode success = curl_easy_perform(curl);
  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);

  StringArray pkt_lines = parse_pkt_lines(a, chunk);

  for (int i = 0; i < pkt_lines.count; ++i) {
    str_print(pkt_lines.items[i]);
  }
}

internal void do_clone(Arena *a, String repo_url) {
  CURL *handle = curl_easy_init();
  capability_advertisement(a, handle, repo_url);
}

#endif
