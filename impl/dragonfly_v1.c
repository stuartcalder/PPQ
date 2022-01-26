#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include "dragonfly_v1.h"
#include "csprng.h"
#include <Base/mem.h>
#include <Base/mmap.h>

#ifdef BASE_MLOCK_H
#	define LOCK_MEMORY_(address, size)	Base_mlock_or_die(address, size)
#	define UNLOCK_MEMORY_(address, size)	Base_munlock_or_die(address, size)
#else
#	define LOCK_MEMORY_(nil_0, nil_1)	/* Nil */
#	define UNLOCK_MEMORY_(nil_0, nil_1)	/* Nil */
#endif

#define CLEANUP_MMAP_(mmap_ptr) \
	Base_MMap_unmap_or_die(mmap_ptr); \
	Base_close_file_or_die(mmap_ptr->file);

#define CLEANUP_ERROR_(secret) \
	Base_secure_zero(&(secret), sizeof(secret)); \
	UNLOCK_MEMORY_(&(secret), sizeof(secret)); \
	CLEANUP_MMAP_(output_mmap); \
	CLEANUP_MMAP_(input_mmap); \
	remove(output_filepath)

#define CLEANUP_SUCCESS_(secret) \
	Base_secure_zero(&secret, sizeof(secret)); \
	UNLOCK_MEMORY_(&secret, sizeof(secret)); \
	Base_MMap_sync_or_die(output_mmap); \
	CLEANUP_MMAP_(output_mmap); \
	CLEANUP_MMAP_(input_mmap)

#define R_(p) p BASE_RESTRICT
#define AL_   BASE_ALIGNAS(8)

AL_ static const uint8_t Skc_Dragonfly_V1_NoPhi_Cfg  [SKC_THREEFISH512_BLOCK_BYTES] = {
	0x79,0xb5,0x79,0x1e,0x9a,0xac,0x02,0x64,
	0x2a,0xaa,0x99,0x1b,0xd5,0x47,0xed,0x14,
	0x74,0x4d,0x72,0xbf,0x13,0x22,0x54,0xc9,
	0xad,0xd6,0xb9,0xbe,0xe8,0x70,0x18,0xe2,
	0xaa,0x51,0x50,0xe2,0x1f,0xcd,0x90,0x19,
	0xb6,0x1f,0x0e,0xc6,0x05,0x00,0xd6,0xed,
	0x7c,0xf2,0x03,0x53,0xfd,0x42,0xa5,0xa3,
	0x7a,0x0e,0xbb,0xb4,0xa7,0xeb,0xdb,0xab
};
AL_ static const uint8_t Skc_Dragonfly_V1_Phi_Cfg  [SKC_THREEFISH512_BLOCK_BYTES] = {
	0x1f,0x23,0x89,0x58,0x4a,0x4a,0xbb,0xa5,
	0x9f,0x09,0xca,0xd4,0xef,0xac,0x43,0x1d,
	0xde,0x9a,0xb0,0xf8,0x69,0xaa,0x50,0xf3,
	0xed,0xcc,0xb4,0x7d,0x6d,0x4f,0x10,0xb9,
	0x8e,0x6a,0x68,0xab,0x6e,0x53,0xbc,0xd6,
	0xcf,0xfc,0xa7,0x63,0x94,0x44,0xbd,0xc7,
	0xb9,0x6d,0x09,0xf5,0x66,0x31,0xa3,0xc5,
	0xf3,0x26,0xeb,0x6f,0xa6,0xac,0xb0,0xa6
};

const uint8_t* const Skc_Dragonfly_V1_NoPhi_Cfg_g = Skc_Dragonfly_V1_NoPhi_Cfg;
const uint8_t* const Skc_Dragonfly_V1_Phi_Cfg_g   = Skc_Dragonfly_V1_Phi_Cfg;


void Skc_Dragonfly_V1_encrypt (R_(Skc_Dragonfly_V1_Encrypt* const) ctx,
                               R_(Base_MMap*  const)               input_mmap,
			       R_(Base_MMap*  const)               output_mmap,
			       R_(const char* const)               output_filepath)
{
	uint8_t* const enc_key = ctx->secret.hash_out;
	uint8_t* const auth_key = enc_key + SKC_THREEFISH512_BLOCK_BYTES;
	{ /* Setup the output map. */
		/* Assume the output file's size to be the plaintext size with a visibile header. */
		output_mmap->size = input_mmap->size + SKC_DRAGONFLY_V1_VISIBLE_METADATA_BYTES + ctx->secret.input.padding_bytes;
		Base_set_file_size_or_die(output_mmap->file, output_mmap->size);
		Base_MMap_map_or_die(output_mmap, false);
	}
	LOCK_MEMORY_(&ctx->secret, sizeof(ctx->secret));
	Skc_Catena512_Input* const input = &ctx->secret.input;
	{
		Skc_CSPRNG* csprng = &input->csprng;
		Skc_CSPRNG_get(csprng, (uint8_t*)ctx->tf_tweak, SKC_THREEFISH512_TWEAK_BYTES);
		Skc_CSPRNG_get(csprng, ctx->ctr_iv            , sizeof(ctx->ctr_iv));
		Skc_CSPRNG_get(csprng, ctx->catena512_salt    , sizeof(ctx->catena512_salt));
		Skc_CSPRNG_del(csprng);
	}
	{
                memcpy(
                 ctx->secret.catena512.salt,
                 ctx->catena512_salt,
                 sizeof(ctx->catena512_salt)
                );
		int status;
		if (!input->use_phi) {
                        status = Skc_Catena512_without_phi(
                         &ctx->secret.catena512,
                         ctx->secret.hash_out,
                         input->password_buffer,
                         input->password_size,
                         input->g_low,
                         input->g_high,
                         input->lambda
                        );
		} else {
                        status = Skc_Catena512_with_phi(
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
			Base_errx("Error: Catena512 failed with error code %d...\nAllocating too much memory?\n", status);
		}
		Base_secure_zero(&ctx->secret.catena512, sizeof(ctx->secret.catena512));
		Base_secure_zero(input->password_buffer, sizeof(input->password_buffer));
		/* Catena512 will output 512 bits. We will hash these 512 bits into 1024 output bits using Skein
		 * with the first 512 bits as the encryption key, and the second 512 bits as the authentication key.
		 */
                Skc_Skein512_hash(
                 &ctx->secret.ubi512,
                 ctx->secret.hash_out, /*output*/
                 ctx->secret.hash_out, /*input*/
                 SKC_THREEFISH512_BLOCK_BYTES, /*input size*/
                 (SKC_THREEFISH512_BLOCK_BYTES * 2) /*output size*/
                );
		BASE_STATIC_ASSERT(sizeof(ctx->secret.hash_out) == (SKC_THREEFISH512_BLOCK_BYTES * 2), "Size reminder.");
		memcpy(ctx->secret.enc_key , enc_key , SKC_THREEFISH512_BLOCK_BYTES);
		memcpy(ctx->secret.auth_key, auth_key, SKC_THREEFISH512_BLOCK_BYTES);
		/* Scrub the hash buffer and initialize the Threefish cipher. */
		Base_secure_zero(ctx->secret.hash_out, sizeof(ctx->secret.hash_out));
                Skc_Threefish512_Static_init(
                 &ctx->secret.threefish512_ctr.threefish512,
                 ctx->secret.enc_key,
                 ctx->tf_tweak
                );
	}
	uint8_t* out = output_mmap->ptr;
	memcpy(out, SKC_DRAGONFLY_V1_ID, sizeof(SKC_DRAGONFLY_V1_ID));
	out += sizeof(SKC_DRAGONFLY_V1_ID);
	Base_store_le64(out, output_mmap->size);
	out += sizeof(output_mmap->size);
	(*out++) = input->g_low;
	(*out++) = input->g_high;
	(*out++) = input->lambda;
	(*out++) = input->use_phi;
	memcpy(out, ctx->tf_tweak, SKC_THREEFISH512_TWEAK_BYTES);
	out += SKC_THREEFISH512_TWEAK_BYTES;
	memcpy(out, ctx->catena512_salt, SKC_CATENA512_SALT_BYTES);
	out += SKC_CATENA512_SALT_BYTES;
	memcpy(out, ctx->ctr_iv, SKC_THREEFISH512_CTR_IV_BYTES);
	out += SKC_THREEFISH512_CTR_IV_BYTES;
	{
		uint64_t crypt_header [2] = {0};
		Base_store_le64(crypt_header, input->padding_bytes);
		Skc_Threefish512_CTR_init(&ctx->secret.threefish512_ctr, ctx->ctr_iv);
                Skc_Threefish512_CTR_xor_keystream(
                 &ctx->secret.threefish512_ctr,
                 out,
                 (uint8_t*)crypt_header,
                 sizeof(crypt_header),
                 0
                );
		out += sizeof(crypt_header);
		if (input->padding_bytes) {
                        Skc_Threefish512_CTR_xor_keystream(
                         &ctx->secret.threefish512_ctr,
                         out,
                         out,
                         input->padding_bytes,
                         sizeof(crypt_header)
                        );
			out += input->padding_bytes;
		}
                Skc_Threefish512_CTR_xor_keystream(
                 &ctx->secret.threefish512_ctr,
                 out,
                 input_mmap->ptr,
                 input_mmap->size,
                 sizeof(crypt_header) + input->padding_bytes
                );
		out += input_mmap->size;
	}
        Skc_Skein512_mac(
         &ctx->secret.ubi512,
         out,
         output_mmap->ptr,
         ctx->secret.auth_key,
         output_mmap->size - SKC_COMMON_MAC_BYTES,
         SKC_COMMON_MAC_BYTES
        );
	CLEANUP_SUCCESS_(ctx->secret);
}
void Skc_Dragonfly_V1_decrypt (R_(Skc_Dragonfly_V1_Decrypt* const) ctx,
                               R_(Base_MMap*   const)              input_mmap,
			       R_(Base_MMap*   const)              output_mmap,
			       R_(const char* const)               output_filepath)
{
	output_mmap->size = input_mmap->size - SKC_DRAGONFLY_V1_VISIBLE_METADATA_BYTES;
#define MIN_POSSIBLE_FILE_SIZE_ (SKC_DRAGONFLY_V1_VISIBLE_METADATA_BYTES + 1)
	if (input_mmap->size < MIN_POSSIBLE_FILE_SIZE_) {
		Base_close_file_or_die(output_mmap->file);
		remove(output_filepath);
		Base_errx("Error: Input file doesn't appear to be large enough to be a SSC_DRAGONFLY_V1 encrypted file.\n");
	}
	const uint8_t* in = input_mmap->ptr;
	uint64_t tweak          [SKC_THREEFISH512_EXTERNAL_TWEAK_WORDS];
	uint8_t  catena512_salt [SKC_CATENA512_SALT_BYTES];
	uint8_t  ctr_iv         [SKC_THREEFISH512_CTR_IV_BYTES];
	uint64_t header_size;
	uint8_t  header_id      [sizeof(SKC_DRAGONFLY_V1_ID)];
	uint8_t  g_low;
	uint8_t  g_high;
	uint8_t  lambda;
	uint8_t  use_phi;
	memcpy(header_id, in, sizeof(header_id));
	in += sizeof(header_id);
	header_size = Base_load_le64(in);
	in += sizeof(header_size);
	g_low   = (*in++);
	g_high  = (*in++);
	lambda  = (*in++);
	use_phi = (*in++);
	memcpy(tweak, in, SKC_THREEFISH512_TWEAK_BYTES);
	in += SKC_THREEFISH512_TWEAK_BYTES;
	memcpy(catena512_salt, in, SKC_CATENA512_SALT_BYTES);
	in += SKC_CATENA512_SALT_BYTES;
	memcpy(ctr_iv, in, SKC_THREEFISH512_CTR_IV_BYTES);
	in += SKC_THREEFISH512_CTR_IV_BYTES;

	if (memcmp(header_id, SKC_DRAGONFLY_V1_ID, sizeof(SKC_DRAGONFLY_V1_ID))) {
		Base_MMap_unmap_or_die(input_mmap);
		Base_close_file_or_die(input_mmap->file);
		Base_close_file_or_die(output_mmap->file);
		remove(output_filepath);
		Base_errx("Error: Not a Dragonfly_V1 encrypted file.\n");
	}
	LOCK_MEMORY_(ctx, sizeof(*ctx));
	memcpy(ctx->catena512.salt, catena512_salt, sizeof(catena512_salt));
	if (!use_phi) {
		BASE_STATIC_ASSERT(sizeof(catena512_salt) == sizeof(ctx->catena512.salt), "These must be the same size.");
                int ret = Skc_Catena512_without_phi(
                 &ctx->catena512,
                 ctx->hash_buf,
                 ctx->password,
                 ctx->password_size,
                 g_low,
                 g_high,
                 lambda
                );
		if (ret != SKC_CATENA512_SUCCESS) {
			Base_secure_zero(ctx, sizeof(*ctx));
			UNLOCK_MEMORY_(ctx, sizeof(*ctx));
			CLEANUP_MMAP_(input_mmap);
			Base_close_file_or_die(output_mmap->file);
			remove(output_filepath);
			Base_errx("Error: Catena512 failed with error code %d...\nDo you have enough memory to decrypt this file?\n", ret);
		}
		Base_secure_zero(&ctx->catena512, sizeof(ctx->catena512));
	} else {
                int ret = Skc_Catena512_with_phi(
                 &ctx->catena512,
                 ctx->hash_buf,
                 ctx->password,
                 ctx->password_size,
                 g_low,
                 g_high,
                 lambda
                );
		if (ret != SKC_CATENA512_SUCCESS) {
			Base_secure_zero(ctx, sizeof(*ctx));
			UNLOCK_MEMORY_(ctx, sizeof(*ctx));
			CLEANUP_MMAP_(input_mmap);
			Base_close_file_or_die(output_mmap->file);
			remove(output_filepath);
			Base_errx("Error: Catena512 failed with error code %d...\nDo you have enough memory to decrypt this file?\n", ret);
		}
		Base_secure_zero(&ctx->catena512, sizeof(ctx->catena512));
	}
	{ /*Generate the keys.*/
                Skc_Skein512_hash(
                 &ctx->ubi512,
                 ctx->hash_buf,
                 ctx->hash_buf,
                 SKC_THREEFISH512_BLOCK_BYTES,
                 (SKC_THREEFISH512_BLOCK_BYTES * 2)
                );
		uint8_t* const enc_key = ctx->hash_buf;
		uint8_t* const auth_key = enc_key + SKC_THREEFISH512_BLOCK_BYTES;
		memcpy(ctx->enc_key , enc_key , SKC_THREEFISH512_BLOCK_BYTES);
		memcpy(ctx->auth_key, auth_key, SKC_THREEFISH512_BLOCK_BYTES);
		Base_secure_zero(ctx->hash_buf, sizeof(ctx->hash_buf));
		{
                        Skc_Skein512_mac(
                         &ctx->ubi512,
                         ctx->mac,
                         input_mmap->ptr,
                         ctx->auth_key,
                         input_mmap->size - SKC_COMMON_MAC_BYTES,
                         SKC_COMMON_MAC_BYTES
                        );
                        if (
                          0 != Base_ctime_memdiff(
                           ctx->mac,
                           input_mmap->ptr + input_mmap->size - SKC_COMMON_MAC_BYTES,
                           SKC_COMMON_MAC_BYTES
                          )
                        )
                          {
                            Base_secure_zero(ctx, sizeof(*ctx));
                            UNLOCK_MEMORY_(ctx, sizeof(*ctx));
                            CLEANUP_MMAP_(input_mmap);
                            Base_close_file_or_die(output_mmap->file);
                            remove(output_filepath);
                            Base_errx(
                             "Error: Authentication failed.\n"
                             "Possibilities: Wrong password, the file is corrupted, or it has been tampered with!\n"
                            );
                          }
		}
		Skc_Threefish512_Static_init(&ctx->threefish512_ctr.threefish512, ctx->enc_key, tweak);
		{
			Skc_Threefish512_CTR_init(&ctx->threefish512_ctr, ctr_iv);
			uint64_t padding_bytes;
                        Skc_Threefish512_CTR_xor_keystream(
                         &ctx->threefish512_ctr,
                         (uint8_t*)&padding_bytes,
                         in,
                         sizeof(padding_bytes),
                         0
                        );
			const uint64_t step = padding_bytes + (sizeof(uint64_t) * 2);
			output_mmap->size -= padding_bytes;
			Base_set_file_size_or_die(output_mmap->file, output_mmap->size);
			Base_MMap_map_or_die(output_mmap, false);
			in += step;
                        Skc_Threefish512_CTR_xor_keystream(
                         &ctx->threefish512_ctr,
                         output_mmap->ptr,
                         in,
                         output_mmap->size,
                         step
                        );
		}
		Base_secure_zero(ctx, sizeof(*ctx));
		UNLOCK_MEMORY_(ctx, sizeof(*ctx));
		Base_MMap_sync_or_die(output_mmap);
		CLEANUP_MMAP_(output_mmap);
		CLEANUP_MMAP_(input_mmap);
	}
}
void Skc_Dragonfly_V1_dump_header (R_(Base_MMap* const) mem_map, R_(const char* const) filepath) {
#define MIN_SIZE_ (SKC_DRAGONFLY_V1_VISIBLE_METADATA_BYTES + 1)
	if (mem_map->size < MIN_SIZE_) {
		CLEANUP_MMAP_(mem_map);
		Base_errx(
                 "Filepath %s looks too small to be SSC_DRAGONFLY_V1 encrypted.\n"
		 "Minimum size: %i\n",
                 filepath,
                 MIN_SIZE_
                );
	}
	uint8_t  id [sizeof(SKC_DRAGONFLY_V1_ID)];
	uint64_t total_size;
	uint8_t  g_low;
	uint8_t  g_high;
	uint8_t  lambda;
	uint8_t  use_phi;
	uint8_t  tweak  [SKC_THREEFISH512_TWEAK_BYTES];
	uint8_t  salt   [SKC_CATENA512_SALT_BYTES];
	uint8_t  ctr_iv [SKC_THREEFISH512_CTR_IV_BYTES];
	uint8_t  mac    [SKC_COMMON_MAC_BYTES];
	{
		const uint8_t* p = mem_map->ptr;
		memcpy(id, p, sizeof(id));
		p += sizeof(id);
		total_size = Base_load_le64(p);
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
		p = mem_map->ptr + mem_map->size - SKC_COMMON_MAC_BYTES;
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
	Base_print_bytes(tweak, sizeof(tweak));
	fputs("\nCatena-512 Salt:\n", stdout);
	Base_print_bytes(salt, sizeof(salt));
	fputs("\nThreefish-512 Ctr Mode IV:\n", stdout);
	Base_print_bytes(ctr_iv, sizeof(ctr_iv));
	fputs("\nSkein-512 Message Authentication Code:\n", stdout);
	Base_print_bytes(mac, (sizeof(mac) / 2)); putchar('\n');
	Base_print_bytes(mac + (sizeof(mac) / 2), (sizeof(mac) / 2)); putchar('\n');
}
