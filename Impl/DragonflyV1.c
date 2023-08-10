/* Copyright (c) 2020-2023 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information. */
#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include "DragonflyV1.h"
#include "CSPRNG.h"
#include <SSC/Memory.h>
#include <SSC/MemMap.h>

#ifdef SSC_MEMLOCK_H
 #define LOCK_MEMORY_(Address, Size)   SSC_mlock_or_die(Address, Size)
 #define UNLOCK_MEMORY_(Address, Size) SSC_munlock_or_die(Address, Size)
#else
 #define LOCK_MEMORY_(nil_0, nil_1)   /* Nil */
 #define UNLOCK_MEMORY_(nil_0, nil_1) /* Nil */
#endif

#define CLEANUP_MMAP_(MMapPtr) \
 SSC_MemMap_unmapOrDie(MMapPtr);\
 SSC_File_closeOrDie(MMapPtr->file)

#define CLEANUP_ERROR_(Secret) \
 SSC_secureZero(&(Secret), sizeof(Secret));\
 UNLOCK_MEMORY_(&(Secret), sizeof(Secret));\
 CLEANUP_MMAP_(output_mmap);\
 CLEANUP_MMAP_(input_mmap);\
 remove(output_filepath)

#define CLEANUP_SUCCESS_(Secret) \
 SSC_secureZero(&Secret, sizeof(Secret));\
 UNLOCK_MEMORY_(&Secret, sizeof(Secret));\
 SSC_MemMap_syncOrDie(output_mmap);\
 CLEANUP_MMAP_(output_mmap);\
 CLEANUP_MMAP_(input_mmap)

#define R_  SSC_RESTRICT
#define AL_ SSC_ALIGNAS(uint64_t)

AL_ static const uint8_t PPQ_Dragonfly_V1_NoPhi_Cfg [PPQ_THREEFISH512_BLOCK_BYTES] = {
 0x79,0xb5,0x79,0x1e,0x9a,0xac,0x02,0x64,
 0x2a,0xaa,0x99,0x1b,0xd5,0x47,0xed,0x14,
 0x74,0x4d,0x72,0xbf,0x13,0x22,0x54,0xc9,
 0xad,0xd6,0xb9,0xbe,0xe8,0x70,0x18,0xe2,
 0xaa,0x51,0x50,0xe2,0x1f,0xcd,0x90,0x19,
 0xb6,0x1f,0x0e,0xc6,0x05,0x00,0xd6,0xed,
 0x7c,0xf2,0x03,0x53,0xfd,0x42,0xa5,0xa3,
 0x7a,0x0e,0xbb,0xb4,0xa7,0xeb,0xdb,0xab
};
AL_ static const uint8_t PPQ_Dragonfly_V1_Phi_Cfg [PPQ_THREEFISH512_BLOCK_BYTES] = {
 0x1f,0x23,0x89,0x58,0x4a,0x4a,0xbb,0xa5,
 0x9f,0x09,0xca,0xd4,0xef,0xac,0x43,0x1d,
 0xde,0x9a,0xb0,0xf8,0x69,0xaa,0x50,0xf3,
 0xed,0xcc,0xb4,0x7d,0x6d,0x4f,0x10,0xb9,
 0x8e,0x6a,0x68,0xab,0x6e,0x53,0xbc,0xd6,
 0xcf,0xfc,0xa7,0x63,0x94,0x44,0xbd,0xc7,
 0xb9,0x6d,0x09,0xf5,0x66,0x31,0xa3,0xc5,
 0xf3,0x26,0xeb,0x6f,0xa6,0xac,0xb0,0xa6
};

const uint8_t* const PPQ_Dragonfly_V1_NoPhi_Cfg_g = PPQ_Dragonfly_V1_NoPhi_Cfg;
const uint8_t* const PPQ_Dragonfly_V1_Phi_Cfg_g   = PPQ_Dragonfly_V1_Phi_Cfg;


void
PPQ_DragonflyV1_encrypt(
 PPQ_DragonflyV1Encrypt* const R_ ctx,
 SSC_MemMap* const R_             input_mmap,
 SSC_MemMap* const R_             output_mmap,
 const char* const R_             output_filepath)
{
  uint8_t* const enc_key = ctx->secret.hash_out;
  uint8_t* const auth_key = enc_key + PPQ_THREEFISH512_BLOCK_BYTES;
  { /* Setup the output map. */
    /* Assume the output file's size to be the plaintext size with a visibile header. */
    output_mmap->size = input_mmap->size + PPQ_DRAGONFLY_V1_VISIBLE_METADATA_BYTES + ctx->secret.input.padding_bytes;
    SSC_File_setSizeOrDie(output_mmap->file, output_mmap->size);
    SSC_MemMap_mapOrDie(output_mmap, false);
  }
  LOCK_MEMORY_(&ctx->secret, sizeof(ctx->secret));
  PPQ_Catena512Input* const input = &ctx->secret.input;
  {
    PPQ_CSPRNG* rng = &input->csprng;
    PPQ_CSPRNG_get(rng, (uint8_t*)ctx->tf_tweak, PPQ_THREEFISH512_TWEAK_BYTES);
    PPQ_CSPRNG_get(rng, ctx->ctr_iv            , sizeof(ctx->ctr_iv));
    PPQ_CSPRNG_get(rng, ctx->catena512_salt    , sizeof(ctx->catena512_salt));
    PPQ_CSPRNG_del(rng);
  }
  {
    memcpy(
     ctx->secret.catena512.salt,
     ctx->catena512_salt,
     sizeof(ctx->catena512_salt)
    );
    SSC_Error_t status;
    if (!input->use_phi) {
      status = PPQ_Catena512_noPhi(
       &ctx->secret.catena512,
       ctx->secret.hash_out,
       input->password_buffer,
       input->password_size,
       input->g_low,
       input->g_high,
       input->lambda
      );
    } else {
      status = PPQ_Catena512_usePhi(
       &ctx->secret.catena512,
       ctx->secret.hash_out,
       input->password_buffer,
       input->password_size,
       input->g_low,
       input->g_high,
       input->lambda
      );
    }
    if (status) {
      CLEANUP_ERROR_(ctx->secret);
      SSC_errx("Error: Catena512 failed with error code %d...\nAllocating too much memory?\n", status);
    }
    SSC_secureZero(&ctx->secret.catena512, sizeof(ctx->secret.catena512));
    SSC_secureZero(input->password_buffer, sizeof(input->password_buffer));
    /* Catena512 will output 512 bits. We will hash these 512 bits into 1024 output bits using Skein
     * with the first 512 bits as the encryption key, and the second 512 bits as the authentication key. */
    PPQ_Skein512_hash(
     &ctx->secret.ubi512,
     ctx->secret.hash_out, /*output*/
     ctx->secret.hash_out, /*input*/
     PPQ_THREEFISH512_BLOCK_BYTES, /*input size*/
     (PPQ_THREEFISH512_BLOCK_BYTES * 2) /*output size*/
    );
    SSC_STATIC_ASSERT(sizeof(ctx->secret.hash_out) == (PPQ_THREEFISH512_BLOCK_BYTES * 2), "Size reminder.");
    /* Get the encryption and authentication keys respectively. */
    memcpy(ctx->secret.enc_key , enc_key , PPQ_THREEFISH512_BLOCK_BYTES);
    memcpy(ctx->secret.auth_key, auth_key, PPQ_THREEFISH512_BLOCK_BYTES);
    /* Scrub the hash buffer and initialize the Threefish cipher. */
    SSC_secureZero(ctx->secret.hash_out, sizeof(ctx->secret.hash_out));
    PPQ_Threefish512Static_init(
     &ctx->secret.threefish512_ctr.threefish512,
     ctx->secret.enc_key,
     ctx->tf_tweak
    );
  }
  uint8_t* out = output_mmap->ptr;
  memcpy(out, PPQ_DRAGONFLY_V1_ID, PPQ_DRAGONFLY_V1_ID_NBYTES);
  out += PPQ_DRAGONFLY_V1_ID_NBYTES;
  SSC_storeLittleEndian64(out, output_mmap->size);
  out += sizeof(uint64_t);
  (*out++) = input->g_low;
  (*out++) = input->g_high;
  (*out++) = input->lambda;
  (*out++) = input->use_phi;
  memcpy(out, ctx->tf_tweak, PPQ_THREEFISH512_TWEAK_BYTES);
  out += PPQ_THREEFISH512_TWEAK_BYTES;
  memcpy(out, ctx->catena512_salt, PPQ_CATENA512_SALT_BYTES);
  out += PPQ_CATENA512_SALT_BYTES;
  memcpy(out, ctx->ctr_iv, PPQ_THREEFISH512COUNTERMODE_IV_BYTES);
  out += PPQ_THREEFISH512COUNTERMODE_IV_BYTES;
  {
          uint64_t crypt_header [2] = {0};
	  SSC_storeLittleEndian64(crypt_header, input->padding_bytes);
          PPQ_Threefish512CounterMode_init(&ctx->secret.threefish512_ctr, ctx->ctr_iv);
          PPQ_Threefish512CounterMode_xorKeystream(
           &ctx->secret.threefish512_ctr,
           out,
           (uint8_t*)crypt_header,
           sizeof(crypt_header),
           0
          );
          out += sizeof(crypt_header);
          if (input->padding_bytes) {
                  PPQ_Threefish512CounterMode_xorKeystream(
                   &ctx->secret.threefish512_ctr,
                   out,
                   out,
                   input->padding_bytes,
                   sizeof(crypt_header)
                  );
                  out += input->padding_bytes;
          }
          PPQ_Threefish512CounterMode_xorKeystream(
           &ctx->secret.threefish512_ctr,
           out,
           input_mmap->ptr,
           input_mmap->size,
           sizeof(crypt_header) + input->padding_bytes
          );
          out += input_mmap->size;
  }
  PPQ_Skein512_mac(
   &ctx->secret.ubi512,
   out,
   output_mmap->ptr,
   ctx->secret.auth_key,
   output_mmap->size - PPQ_COMMON_MAC_BYTES,
   PPQ_COMMON_MAC_BYTES
  );
  CLEANUP_SUCCESS_(ctx->secret);
}
void PPQ_DragonflyV1_decrypt(
 PPQ_DragonflyV1Decrypt* const R_ ctx,
 SSC_MemMap*   const R_           input_mmap,
 SSC_MemMap*   const R_           output_mmap,
 const char* const R_             output_filepath)
{
        output_mmap->size = input_mmap->size - PPQ_DRAGONFLY_V1_VISIBLE_METADATA_BYTES;
	#define MIN_POSSIBLE_FILE_SIZE_ (PPQ_DRAGONFLY_V1_VISIBLE_METADATA_BYTES + 1)
        if (input_mmap->size < MIN_POSSIBLE_FILE_SIZE_) {
                SSC_File_closeOrDie(output_mmap->file);
                remove(output_filepath);
                SSC_errx("Error: Input file doesn't appear to be large enough to be a SSC_DRAGONFLY_V1 encrypted file.\n");
        }
        const uint8_t* in = input_mmap->ptr;
        uint64_t tweak          [PPQ_THREEFISH512_EXTERNAL_TWEAK_WORDS];
        uint8_t  catena512_salt [PPQ_CATENA512_SALT_BYTES];
        uint8_t  ctr_iv         [PPQ_THREEFISH512COUNTERMODE_IV_BYTES];
        uint64_t header_size;
        uint8_t  header_id      [PPQ_DRAGONFLY_V1_ID_NBYTES];
        uint8_t  g_low;
        uint8_t  g_high;
        uint8_t  lambda;
        uint8_t  use_phi;
        memcpy(header_id, in, sizeof(header_id));
        in += sizeof(header_id);
	header_size = SSC_loadLittleEndian64(in);
        in += sizeof(header_size);
        g_low   = (*in++);
        g_high  = (*in++);
        lambda  = (*in++);
        use_phi = (*in++);
        memcpy(tweak, in, PPQ_THREEFISH512_TWEAK_BYTES);
        in += PPQ_THREEFISH512_TWEAK_BYTES;
        memcpy(catena512_salt, in, PPQ_CATENA512_SALT_BYTES);
        in += PPQ_CATENA512_SALT_BYTES;
        memcpy(ctr_iv, in, PPQ_THREEFISH512COUNTERMODE_IV_BYTES);
        in += PPQ_THREEFISH512COUNTERMODE_IV_BYTES;

        if (memcmp(header_id, PPQ_DRAGONFLY_V1_ID, PPQ_DRAGONFLY_V1_ID_NBYTES)) {
		SSC_MemMap_unmapOrDie(input_mmap);
		SSC_File_closeOrDie(input_mmap->file);
		SSC_File_closeOrDie(output_mmap->file);
                remove(output_filepath);
                SSC_errx("Error: Not a Dragonfly_V1 encrypted file.\n");
        }
        LOCK_MEMORY_(ctx, sizeof(*ctx));
        memcpy(ctx->catena512.salt, catena512_salt, sizeof(catena512_salt));
        if (!use_phi) {
                SSC_STATIC_ASSERT(sizeof(catena512_salt) == sizeof(ctx->catena512.salt), "These must be the same size.");
                SSC_Error_t ret = PPQ_Catena512_noPhi(
                 &ctx->catena512,
                 ctx->hash_buf,
                 ctx->password,
                 ctx->password_size,
                 g_low,
                 g_high,
                 lambda
                );
                if (ret != PPQ_CATENA512_SUCCESS) {
                        SSC_secureZero(ctx, sizeof(*ctx));
                        UNLOCK_MEMORY_(ctx, sizeof(*ctx));
                        CLEANUP_MMAP_(input_mmap);
			SSC_File_closeOrDie(output_mmap->file);
                        remove(output_filepath);
                        SSC_errx("Error: Catena512 failed with error code %d...\nDo you have enough memory to decrypt this file?\n", ret);
                }
                SSC_secureZero(&ctx->catena512, sizeof(ctx->catena512));
        } else {
                SSC_Error_t ret = PPQ_Catena512_usePhi(
                 &ctx->catena512,
                 ctx->hash_buf,
                 ctx->password,
                 ctx->password_size,
                 g_low,
                 g_high,
                 lambda
                );
                if (ret != PPQ_CATENA512_SUCCESS) {
                        SSC_secureZero(ctx, sizeof(*ctx));
                        UNLOCK_MEMORY_(ctx, sizeof(*ctx));
                        CLEANUP_MMAP_(input_mmap);
                        SSC_File_closeOrDie(output_mmap->file);
                        remove(output_filepath);
                        SSC_errx("Error: Catena512 failed with error code %d...\nDo you have enough memory to decrypt this file?\n", ret);
                }
                SSC_secureZero(&ctx->catena512, sizeof(ctx->catena512));
        }
        { /*Generate the keys.*/
                PPQ_Skein512_hash(
                 &ctx->ubi512,
                 ctx->hash_buf,
                 ctx->hash_buf,
                 PPQ_THREEFISH512_BLOCK_BYTES,
                 (PPQ_THREEFISH512_BLOCK_BYTES * 2)
                );
                uint8_t* const enc_key = ctx->hash_buf;
                uint8_t* const auth_key = enc_key + PPQ_THREEFISH512_BLOCK_BYTES;
                memcpy(ctx->enc_key , enc_key , PPQ_THREEFISH512_BLOCK_BYTES);
                memcpy(ctx->auth_key, auth_key, PPQ_THREEFISH512_BLOCK_BYTES);
                SSC_secureZero(ctx->hash_buf, sizeof(ctx->hash_buf));
                {
                        PPQ_Skein512_mac(
                         &ctx->ubi512,
                         ctx->mac,
                         input_mmap->ptr,
                         ctx->auth_key,
                         input_mmap->size - PPQ_COMMON_MAC_BYTES,
                         PPQ_COMMON_MAC_BYTES
                        );
                        if (
                          0 != SSC_constTimeMemDiff(
                           ctx->mac,
                           input_mmap->ptr + input_mmap->size - PPQ_COMMON_MAC_BYTES,
                           PPQ_COMMON_MAC_BYTES
                          )
                        )
                          {
                            SSC_secureZero(ctx, sizeof(*ctx));
                            UNLOCK_MEMORY_(ctx, sizeof(*ctx));
                            CLEANUP_MMAP_(input_mmap);
			    SSC_File_closeOrDie(output_mmap->file);
                            remove(output_filepath);
                            SSC_errx(
                             "Error: Authentication failed.\n"
                             "Possibilities: Wrong password, the file is corrupted, or it has been tampered with!\n"
                            );
                          }
                }
                PPQ_Threefish512Static_init(&ctx->threefish512_ctr.threefish512, ctx->enc_key, tweak);
                {
                        PPQ_Threefish512CounterMode_init(&ctx->threefish512_ctr, ctr_iv);
                        uint64_t padding_bytes;
                        PPQ_Threefish512CounterMode_xorKeystream(
                         &ctx->threefish512_ctr,
                         (uint8_t*)&padding_bytes,
                         in,
                         sizeof(padding_bytes),
                         0
                        );
                        const uint64_t step = padding_bytes + (sizeof(uint64_t) * 2);
                        output_mmap->size -= padding_bytes;
			SSC_File_setSizeOrDie(output_mmap->file, output_mmap->size);
			SSC_MemMap_mapOrDie(output_mmap, false);
                        in += step;
                        PPQ_Threefish512CounterMode_xorKeystream(
                         &ctx->threefish512_ctr,
                         output_mmap->ptr,
                         in,
                         output_mmap->size,
                         step
                        );
                }
                SSC_secureZero(ctx, sizeof(*ctx));
                UNLOCK_MEMORY_(ctx, sizeof(*ctx));
		SSC_MemMap_syncOrDie(output_mmap);
                CLEANUP_MMAP_(output_mmap);
                CLEANUP_MMAP_(input_mmap);
        }
}
void PPQ_DragonflyV1_dumpHeader(
 SSC_MemMap* const R_ mem_map,
 const char* const R_ filepath)
{
#define MIN_SIZE_ (PPQ_DRAGONFLY_V1_VISIBLE_METADATA_BYTES + 1)
        if (mem_map->size < MIN_SIZE_) {
                CLEANUP_MMAP_(mem_map);
                SSC_errx(
                 "Filepath %s looks too small to be SSC_DRAGONFLY_V1 encrypted.\n"
                 "Minimum size: %i\n",
                 filepath,
                 MIN_SIZE_
                );
        }
        uint8_t  id [PPQ_DRAGONFLY_V1_ID_NBYTES];
        uint64_t total_size;
        uint8_t  g_low;
        uint8_t  g_high;
        uint8_t  lambda;
        uint8_t  use_phi;
        uint8_t  tweak  [PPQ_THREEFISH512_TWEAK_BYTES];
        uint8_t  salt   [PPQ_CATENA512_SALT_BYTES];
        uint8_t  ctr_iv [PPQ_THREEFISH512COUNTERMODE_IV_BYTES];
        uint8_t  mac    [PPQ_COMMON_MAC_BYTES];
        {
                const uint8_t* p = mem_map->ptr;
                memcpy(id, p, sizeof(id));
                p += sizeof(id);
		total_size = SSC_loadLittleEndian64(p);
                p += sizeof(total_size);
                g_low = (*p++);
                g_high = (*p++);
                lambda = (*p++);
                use_phi = (*p++);
                memcpy(tweak, p, sizeof(tweak));
                p += sizeof(tweak);
                memcpy(salt, p, sizeof(salt));
                p += sizeof(salt);
                memcpy(ctr_iv, p, sizeof(ctr_iv));
                p = mem_map->ptr + mem_map->size - PPQ_COMMON_MAC_BYTES;
                memcpy(mac, p, sizeof(mac));
        }
        CLEANUP_MMAP_(mem_map);
        id[sizeof(id) - 1] = 0; /* Manually null-terminating it. */
        printf("File Header ID : %s\n", (char*)id);
        printf("File Size      : %" PRIu64 "\n", total_size);
        printf("Garlic Low     : 0x%02" PRIx8 "\n", g_low);
        printf("Garlic High    : 0x%02" PRIx8 "\n", g_high);
        printf("Lambda         : 0x%02" PRIx8 "\n", lambda);
        printf("Phi            : 0x%02" PRIx8 "\n", use_phi);
        if (use_phi)
                puts("WARNING: The Phi function is used! Beware side-channel timing attacks when decrypting this file!");
        puts("Threefish-512 Tweak:");
        SSC_printBytes(tweak, sizeof(tweak));
        fputs("\nCatena-512 Salt:\n", stdout);
        SSC_printBytes(salt, sizeof(salt));
        fputs("\nThreefish-512 Ctr Mode IV:\n", stdout);
        SSC_printBytes(ctr_iv, sizeof(ctr_iv));
        fputs("\nSkein-512 Message Authentication Code:\n", stdout);
        SSC_printBytes(mac, (sizeof(mac) / 2)); putchar('\n');
        SSC_printBytes(mac + (sizeof(mac) / 2), (sizeof(mac) / 2)); putchar('\n');
}
