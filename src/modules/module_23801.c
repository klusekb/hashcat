/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Mode 23801: RAR3-p (Signature-based verification)
 *
 * Hash format: $RAR3a$*hex(salt)*method*filetype*unp_size*hex(ciphertext)
 *
 * For stored files (method 0x30): GPU decrypts first block, checks signature.
 * For compressed files (0x31-0x35): GPU derives key + decrypts first block,
 *   CPU hook decompresses prefix, checks signature.
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "memory.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_ARCHIVE;
static const char *HASH_NAME      = "RAR3-p (Signature)";
static const u64   KERN_TYPE      = 23801;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_REGISTER_LIMIT;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_HOOK23
                                  | OPTS_TYPE_POST_AMP_UTF16LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "abcd";
static const char *ST_HASH        = "$RAR3a$*8d77dbb441a49a15*30*png*692959*8d8731d1f227142e33e858acb646d3acfeac015b232f16b0d691b9e7fd04f8c12c51df3369599aba4a87f6d05ccf34aa7643f1c2a7d347be873c4cd60e87786f338e1f843a0c954ff4b493ddfc5e27068fe8c5132ea1e616325cc7dc989f80a4a3f1c13157234ccc09a0fb7badc3ca53db4605f7f1dec5b55e93c59ea087f599";

u32         module_attack_exec    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ATTACK_EXEC;     }
u32         module_dgst_pos0      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS0;       }
u32         module_dgst_pos1      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS1;       }
u32         module_dgst_pos2      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS2;       }
u32         module_dgst_pos3      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS3;       }
u32         module_dgst_size      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_SIZE;       }
u32         module_hash_category  (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_CATEGORY;   }
const char *module_hash_name      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME;       }
u64         module_kern_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE;       }
u32         module_opti_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTI_TYPE;       }
u64         module_opts_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE;       }
u32         module_salt_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return SALT_TYPE;       }
const char *module_st_hash        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_HASH;         }
const char *module_st_pass        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_PASS;         }

/*
 * Constants
 */

#define RAR3A_DATA_MAX 32  /* 128 bytes = 32 u32s */

#define FILETYPE_UNKNOWN  0
#define FILETYPE_JPEG     1
#define FILETYPE_PNG      2
#define FILETYPE_PDF      3
#define FILETYPE_ZIP      4
#define FILETYPE_GZ       5
#define FILETYPE_BMP      6
#define FILETYPE_GIF      7
#define FILETYPE_MP3      8
#define FILETYPE_7Z       9
#define FILETYPE_RAR     10

/*
 * Structures
 */

/* esalt: first encrypted block for GPU-side quick check */
typedef struct rar3a
{
  u32 first_block_encrypted[4];

} rar3a_t;

/* tmp: SHA-1 key derivation state between loop iterations */
typedef struct rar3a_tmp
{
  u32 dgst[5];
  u32 w[66];
  u32 iv[4];

} rar3a_tmp_t;

typedef struct rar3a_tmp_optimized
{
  u32 dgst[17][5];

} rar3a_tmp_optimized_t;

/* hook: GPU → CPU transfer (key, iv, first decrypted block) */
typedef struct rar3a_hook
{
  u32 key[4];
  u32 iv[4];

  u32 first_block_decrypted[4];

  u32 signature_matched;

} rar3a_hook_t;

/* hook_salt: per-hash data for CPU hook (full ciphertext + metadata) */
typedef struct rar3a_hook_salt
{
  u32 data[RAR3A_DATA_MAX];

  u32 pack_size;
  u32 unpack_size;
  u32 method;
  u32 filetype;

} rar3a_hook_salt_t;

/* hook_extra: per-device decompression buffers */
typedef struct rar3a_hook_extra
{
  void **win;
  void **inp;
  void **vm;
  void **ppm;

} rar3a_hook_extra_t;

static const int   ROUNDS_RAR3     = 262144;
static const char *SIGNATURE_RAR3A = "$RAR3a$";

/*
 * Filetype helpers
 */

static u32 filetype_from_string (const char *s, const int len)
{
  if (len == 4 && memcmp (s, "jpeg", 4) == 0) return FILETYPE_JPEG;
  if (len == 3 && memcmp (s, "png",  3) == 0) return FILETYPE_PNG;
  if (len == 3 && memcmp (s, "pdf",  3) == 0) return FILETYPE_PDF;
  if (len == 3 && memcmp (s, "zip",  3) == 0) return FILETYPE_ZIP;
  if (len == 2 && memcmp (s, "gz",   2) == 0) return FILETYPE_GZ;
  if (len == 3 && memcmp (s, "bmp",  3) == 0) return FILETYPE_BMP;
  if (len == 3 && memcmp (s, "gif",  3) == 0) return FILETYPE_GIF;
  if (len == 3 && memcmp (s, "mp3",  3) == 0) return FILETYPE_MP3;
  if (len == 2 && memcmp (s, "7z",   2) == 0) return FILETYPE_7Z;
  if (len == 3 && memcmp (s, "rar",  3) == 0) return FILETYPE_RAR;
  return FILETYPE_UNKNOWN;
}

static const char *filetype_to_string (const u32 filetype)
{
  switch (filetype)
  {
    case FILETYPE_JPEG: return "jpeg";
    case FILETYPE_PNG:  return "png";
    case FILETYPE_PDF:  return "pdf";
    case FILETYPE_ZIP:  return "zip";
    case FILETYPE_GZ:   return "gz";
    case FILETYPE_BMP:  return "bmp";
    case FILETYPE_GIF:  return "gif";
    case FILETYPE_MP3:  return "mp3";
    case FILETYPE_7Z:   return "7z";
    case FILETYPE_RAR:  return "rar";
  }
  return "unknown";
}

typedef struct filetype_sig
{
  u32  id;
  u32  len;
  u8   sig[16];
} filetype_sig_t;

static const filetype_sig_t filetype_sigs[] =
{
  { FILETYPE_PNG,  8, { 0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A } },
  { FILETYPE_7Z,   6, { 0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C } },
  { FILETYPE_RAR,  6, { 0x52, 0x61, 0x72, 0x21, 0x1A, 0x07 } },
  { FILETYPE_PDF,  5, { 0x25, 0x50, 0x44, 0x46, 0x2D } },
  { FILETYPE_ZIP,  4, { 0x50, 0x4B, 0x03, 0x04 } },
  { FILETYPE_GIF,  4, { 0x47, 0x49, 0x46, 0x38 } },
  { FILETYPE_JPEG, 3, { 0xFF, 0xD8, 0xFF } },
  { FILETYPE_BMP,  2, { 0x42, 0x4D } },
  { FILETYPE_GZ,   2, { 0x1F, 0x8B } },
};

#define FILETYPE_SIG_CNT (sizeof (filetype_sigs) / sizeof (filetype_sigs[0]))

static int check_signature (const u8 *data, const u32 data_len, const u32 filetype)
{
  for (u32 i = 0; i < FILETYPE_SIG_CNT; i++)
  {
    if (filetype_sigs[i].id == filetype)
    {
      if (filetype_sigs[i].len == 0) return 0;
      if (data_len < filetype_sigs[i].len) return 0;
      return (memcmp (data, filetype_sigs[i].sig, filetype_sigs[i].len) == 0) ? 1 : 0;
    }
  }
  return 0;
}

/*
 * Huffman check (from 23800) — early rejection for compressed files
 */

#define ADD_BITS(n)                                   \
{                                                     \
  if (bits < 9)                                       \
  {                                                   \
    hold |= ((unsigned int) *next++ << (24 - bits));  \
    bits += 8;                                        \
  }                                                   \
                                                      \
  hold <<= n;                                         \
  bits  -= n;                                         \
}

static int check_huffman (const unsigned char *next)
{
  unsigned int bits;
  unsigned int hold;
  unsigned int i;
  int left;
  unsigned int ncount[4];
  unsigned char *count = (unsigned char*) ncount;
  unsigned char bit_length[20];

  hold =                  next[3]
       + (((unsigned int) next[2]) <<  8)
       + (((unsigned int) next[1]) << 16)
       + (((unsigned int) next[0]) << 24);

  next  += 4;
  hold <<= 2;
  bits   = 32 - 2;

  for (i = 0; i < 20; i++)
  {
    int length, zero_count;

    length = hold >> 28;
    ADD_BITS (4);

    if (length == 15)
    {
      zero_count = hold >> 28;
      ADD_BITS (4);

      if (zero_count == 0)
      {
        bit_length[i] = 15;
      }
      else
      {
        zero_count += 2;
        while (zero_count-- > 0 && i < sizeof (bit_length) / sizeof (bit_length[0]))
        {
          bit_length[i++] = 0;
        }
        i--;
      }
    }
    else
    {
      bit_length[i] = length;
    }
  }

  memset (count, 0, 16);

  for (i = 0; i < 20; i++)
  {
    ++count[bit_length[i]];
  }

  count[0] = 0;

  if (!ncount[0] && !ncount[1] && !ncount[2] && !ncount[3]) return 0;

  left = 1;

  for (i = 1; i < 16; ++i)
  {
    left <<= 1;
    left -= count[i];
    if (left < 0) return 0;
  }

  if (left) return 0;

  return 1;
}

/*
 * Unstable warning
 */

bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU))
  {
    if (device_param->opencl_device_vendor_id == VENDOR_ID_INTEL_SDK)
    {
      return true;
    }
  }
  return false;
}

/*
 * Hook extra param (decompression buffers) — init and term
 */

bool module_hook_extra_param_init (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const folder_config_t *folder_config, MAYBE_UNUSED const backend_ctx_t *backend_ctx, void *hook_extra_param)
{
  rar3a_hook_extra_t *extra = (rar3a_hook_extra_t *) hook_extra_param;

  #define WINSIZE_23801 0x100000
  #define INPSIZE_23801 0x50000
  #define PPMSIZE_23801 216 * 1024 * 1024

  extra->win = hccalloc (backend_ctx->backend_devices_cnt, sizeof (void *));
  if (extra->win == NULL) return false;

  extra->inp = hccalloc (backend_ctx->backend_devices_cnt, sizeof (void *));
  if (extra->inp == NULL) return false;

  extra->vm  = hccalloc (backend_ctx->backend_devices_cnt, sizeof (void *));
  if (extra->vm  == NULL) return false;

  extra->ppm = hccalloc (backend_ctx->backend_devices_cnt, sizeof (void *));
  if (extra->ppm == NULL) return false;

  for (int i = 0; i < backend_ctx->backend_devices_cnt; i++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[i];

    if (device_param->skipped == true) continue;

    extra->win[i] = hcmalloc (WINSIZE_23801);
    if (extra->win[i] == NULL) return false;

    extra->inp[i] = hcmalloc (INPSIZE_23801);
    if (extra->inp[i] == NULL) return false;

    extra->vm[i]  = hcmalloc (INPSIZE_23801);
    if (extra->vm[i]  == NULL) return false;

    extra->ppm[i] = hcmalloc (PPMSIZE_23801);
    if (extra->ppm[i] == NULL) return false;
  }

  return true;
}

bool module_hook_extra_param_term (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const folder_config_t *folder_config, MAYBE_UNUSED const backend_ctx_t *backend_ctx, void *hook_extra_param)
{
  rar3a_hook_extra_t *extra = (rar3a_hook_extra_t *) hook_extra_param;

  for (int i = 0; i < backend_ctx->backend_devices_cnt; i++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[i];

    if (device_param->skipped == true) continue;

    hcfree (extra->ppm[i]);
    hcfree (extra->win[i]);
    hcfree (extra->inp[i]);
    hcfree (extra->vm[i]);
  }

  hcfree (extra->ppm);
  hcfree (extra->win);
  hcfree (extra->inp);
  hcfree (extra->vm);

  return true;
}

/*
 * Hook23 — CPU-side processing after GPU derives key
 */

unsigned int hc_decompress_rar (unsigned char *Win, unsigned char *Inp, unsigned char *VM, unsigned char *PPM, const unsigned int OutputSize, const unsigned char *Input, const unsigned int PackSize, const unsigned int UnpackSize, const unsigned char *Key, const unsigned char *IV, unsigned int *unpack_failed);

#define SIG_CHECK_BYTES 32

void module_hook23 (hc_device_param_t *device_param, const void *hook_extra_param, const void *hook_salts_buf, const u32 salt_pos, const u64 pw_pos)
{
  rar3a_hook_t *hook_items = (rar3a_hook_t *) device_param->hooks_buf;
  rar3a_hook_t *hook_item  = &hook_items[pw_pos];

  const rar3a_hook_salt_t *salts = (const rar3a_hook_salt_t *) hook_salts_buf;
  const rar3a_hook_salt_t *rar3a = &salts[salt_pos];

  const rar3a_hook_extra_t *extra = (const rar3a_hook_extra_t *) hook_extra_param;

  hook_item->signature_matched = 0;

  const u32 method   = rar3a->method;
  const u32 filetype = rar3a->filetype;
  const u8 *first_block_decrypted = (const u8 *) hook_item->first_block_decrypted;

  /*
   * Stored files: the GPU already decrypted the first block.
   * Check signature directly — no decompression needed.
   */
  if (method == 0x30)
  {
    hook_item->signature_matched = check_signature (first_block_decrypted, 16, filetype);
    return;
  }

  /*
   * Compressed files: early rejection using huffman/PPM checks
   */
  if (first_block_decrypted[0] & 0x80)
  {
    /* PPM */
    if (((first_block_decrypted[0] & 0x20) == 0)
     ||  (first_block_decrypted[1] & 0x80))
    {
      return;
    }
  }
  else
  {
    /* LZ */
    if ((first_block_decrypted[0] & 0x40)
     || (check_huffman (first_block_decrypted)) == 0)
    {
      return;
    }
  }

  /*
   * Passed early rejection — decompress a small prefix.
   * We pass SIG_CHECK_BYTES as UnpackSize so the decompressor
   * targets only a few bytes of output. We ignore unpack_failed
   * because the truncated compressed stream will cause the
   * decompressor to report failure even when it successfully
   * wrote valid decompressed bytes.
   */
  const u8 *data = (const u8 *) rar3a->data;
  const u8 *key  = (u8 *) hook_item->key;
  const u8 *iv   = (u8 *) hook_item->iv;

  const u32 pack_size = rar3a->pack_size;

  /* Clear the output buffer so we can detect if anything was written */
  memset (extra->win[device_param->device_id], 0, SIG_CHECK_BYTES);

  unsigned int unpack_failed = 1;

  hc_decompress_rar (
    extra->win[device_param->device_id],
    extra->inp[device_param->device_id],
    extra->vm [device_param->device_id],
    extra->ppm[device_param->device_id],
    SIG_CHECK_BYTES,
    data,
    pack_size,
    SIG_CHECK_BYTES,  /* UnpackSize = small target, not full file size */
    key,
    iv,
    &unpack_failed
  );

  /* Don't check unpack_failed — check the output directly */

  /* Check decompressed output for file signature */
  const u8 *decompressed = (const u8 *) extra->win[device_param->device_id];

  hook_item->signature_matched = check_signature (decompressed, SIG_CHECK_BYTES, filetype);
}

/*
 * Size functions
 */

u64 module_hook_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return (u64) sizeof (rar3a_hook_t);
}

u64 module_hook_salt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return (u64) sizeof (rar3a_hook_salt_t);
}

u64 module_hook_extra_param_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return (u64) sizeof (rar3a_hook_extra_t);
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = user_options->optimized_kernel;

  u64 tmp_size = (u64) sizeof (rar3a_tmp_t);

  if (optimized_kernel == true)
  {
    tmp_size = (u64) sizeof (rar3a_tmp_optimized_t);
  }

  return tmp_size;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return (u64) sizeof (rar3a_t);
}

u32 module_kernel_loops_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return ROUNDS_RAR3 / 16;
}

u32 module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return ROUNDS_RAR3 / 16;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  u32 pw_max = 128;

  if (optimized_kernel == true)
  {
    pw_max = 20;
  }

  return pw_max;
}

const char *module_benchmark_mask (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "?l?l?l?l?l";
}

/*
 * Hash parser
 *
 * Format: $RAR3a$*hex(salt)*method*filetype*unp_size*hex(ciphertext):::filename
 */

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  rar3a_t *rar3a = (rar3a_t *) esalt_buf;

  rar3a_hook_salt_t *rar3a_hook_salt = (rar3a_hook_salt_t *) hook_salt_buf;

  /* Strip trailing :::filename if present */
  int effective_len = line_len;

  const char *colon_pos = memchr (line_buf, ':', line_len);

  if (colon_pos != NULL)
  {
    effective_len = (int) (colon_pos - line_buf);
  }

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 6;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_RAR3A;

  /* [0] $RAR3a$ */
  token.sep[0]     = '*';
  token.len[0]     = 7;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  /* [1] salt: 16 hex chars */
  token.sep[1]     = '*';
  token.len[1]     = 16;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  /* [2] method: 2 hex chars */
  token.sep[2]     = '*';
  token.len[2]     = 2;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH;

  /* [3] filetype */
  token.sep[3]     = '*';
  token.len_min[3] = 2;
  token.len_max[3] = 7;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH;

  /* [4] unp_size */
  token.sep[4]     = '*';
  token.len_min[4] = 1;
  token.len_max[4] = 10;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  /* [5] ciphertext (last token, no separator) */
  token.len_min[5] = 2;
  token.len_max[5] = 256;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, effective_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  /* salt */
  const u8 *salt_pos = token.buf[1];

  salt->salt_buf[0] = hex_to_u32 (salt_pos + 0);
  salt->salt_buf[1] = hex_to_u32 (salt_pos + 8);

  salt->salt_len  = 8;
  salt->salt_iter = ROUNDS_RAR3;

  /* method */
  const u8 *method_pos = token.buf[2];
  const u32 method = hc_strtoul ((const char *) method_pos, NULL, 16);

  if (method < 0x30) return (PARSER_SALT_VALUE);
  if (method > 0x35) return (PARSER_SALT_VALUE);

  rar3a_hook_salt->method = method;

  /* filetype */
  const u8 *filetype_pos = token.buf[3];
  const u32 filetype_len = token.len[3];
  const u32 filetype = filetype_from_string ((const char *) filetype_pos, filetype_len);

  if (filetype == FILETYPE_UNKNOWN) return (PARSER_SALT_VALUE);

  rar3a_hook_salt->filetype = filetype;

  /* unpack size */
  const u8 *unpack_size_pos = token.buf[4];
  const u32 unpack_size = hc_strtoul ((const char *) unpack_size_pos, NULL, 10);

  if (unpack_size < 1) return (PARSER_SALT_VALUE);

  rar3a_hook_salt->unpack_size = unpack_size;

  /* ciphertext */
  const u8 *data_pos = token.buf[5];
  const u32 data_len = token.len[5];

  const u32 pack_size = data_len / 2;

  if (pack_size < 16) return (PARSER_SALT_VALUE);
  if (pack_size > 128) return (PARSER_SALT_VALUE);
  if ((pack_size % 16) != 0) return (PARSER_SALT_VALUE);

  rar3a_hook_salt->pack_size = pack_size;

  hex_decode (data_pos, data_len, (u8 *) rar3a_hook_salt->data);

  /* First encrypted block into esalt for GPU */
  rar3a->first_block_encrypted[0] = rar3a_hook_salt->data[0];
  rar3a->first_block_encrypted[1] = rar3a_hook_salt->data[1];
  rar3a->first_block_encrypted[2] = rar3a_hook_salt->data[2];
  rar3a->first_block_encrypted[3] = rar3a_hook_salt->data[3];

  /* digest: signature_matched == 1 means success */
  digest[0] = 1;
  digest[1] = 0;
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const rar3a_hook_salt_t *rar3a_hook_salt = (const rar3a_hook_salt_t *) hook_salt_buf;

  const u32 data_len = rar3a_hook_salt->pack_size;

  u8 *data = (u8 *) hcmalloc ((data_len * 2) + 1);

  hex_encode ((const u8 *) rar3a_hook_salt->data, data_len, data);

  data[data_len * 2] = 0;

  const int line_len = snprintf (line_buf, line_size, "%s*%08x%08x*%02x*%s*%u*%s",
      SIGNATURE_RAR3A,
      byte_swap_32 (salt->salt_buf[0]),
      byte_swap_32 (salt->salt_buf[1]),
      rar3a_hook_salt->method,
      filetype_to_string (rar3a_hook_salt->filetype),
      rar3a_hook_salt->unpack_size,
      data);

  hcfree (data);

  return line_len;
}

/*
 * Module init
 */

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = module_benchmark_mask;
  module_ctx->module_benchmark_charset        = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_bridge_name              = MODULE_DEFAULT;
  module_ctx->module_bridge_type              = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = MODULE_DEFAULT;
  module_ctx->module_deprecated_notice        = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_dictstat_disable         = MODULE_DEFAULT;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_buffer_size        = MODULE_DEFAULT;
  module_ctx->module_extra_tmp_size           = MODULE_DEFAULT;
  module_ctx->module_extra_tuningdb_block     = MODULE_DEFAULT;
  module_ctx->module_forced_outfile_format    = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
  module_ctx->module_hash_decode_postprocess  = MODULE_DEFAULT;
  module_ctx->module_hash_decode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash    = MODULE_DEFAULT;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode_status       = MODULE_DEFAULT;
  module_ctx->module_hash_encode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_init_selftest       = MODULE_DEFAULT;
  module_ctx->module_hash_mode                = MODULE_DEFAULT;
  module_ctx->module_hash_category            = module_hash_category;
  module_ctx->module_hash_name                = module_hash_name;
  module_ctx->module_hashes_count_min         = MODULE_DEFAULT;
  module_ctx->module_hashes_count_max         = MODULE_DEFAULT;
  module_ctx->module_hlfmt_disable            = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_size    = module_hook_extra_param_size;
  module_ctx->module_hook_extra_param_init    = module_hook_extra_param_init;
  module_ctx->module_hook_extra_param_term    = module_hook_extra_param_term;
  module_ctx->module_hook12                   = MODULE_DEFAULT;
  module_ctx->module_hook23                   = module_hook23;
  module_ctx->module_hook_salt_size           = module_hook_salt_size;
  module_ctx->module_hook_size                = module_hook_size;
  module_ctx->module_jit_build_options        = MODULE_DEFAULT;
  module_ctx->module_jit_cache_disable        = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max         = module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = module_kernel_loops_min;
  module_ctx->module_kernel_threads_max       = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_min       = MODULE_DEFAULT;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_kern_type_dynamic        = MODULE_DEFAULT;
  module_ctx->module_opti_type                = module_opti_type;
  module_ctx->module_opts_type                = module_opts_type;
  module_ctx->module_outfile_check_disable    = MODULE_DEFAULT;
  module_ctx->module_outfile_check_nocomp     = MODULE_DEFAULT;
  module_ctx->module_potfile_custom_check     = MODULE_DEFAULT;
  module_ctx->module_potfile_disable          = MODULE_DEFAULT;
  module_ctx->module_potfile_keep_all_hashes  = MODULE_DEFAULT;
  module_ctx->module_pwdump_column            = MODULE_DEFAULT;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_pw_min                   = MODULE_DEFAULT;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = module_unstable_warning;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}