#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#include "dragonfly_v1.h"
#include "csprng.h"

#ifdef BASE_HAS_MEMORYLOCKING
#	define LOCK_MEMORY_(address, size)	Base_mlock_or_die(address, size)
#	define UNLOCK_MEMORY_(address, size)	Base_munlock_or_die(address, size)
#else
#	define LOCK_MEMORY_(nil_0, nil_1)	/* Nil */
#	define UNLOCK_MEMORY_(nil_0, nil_1)	/* Nil */
#endif

#define CLEANUP_MMAP_(mmap_ptr) \
	Base_MMap_unmap_or_die(mmap_ptr); \
	Base_close_file_or_die(mmap_ptr->file)

#define CLEANUP_ERROR_(secret) \
	Base_secure_zero(&secret, sizeof(secret)); \
	UNLOCK_MEMORY_(&secret, sizeof(secret)); \
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
		memcpy(ctx->secret.catena512.salt,
		       ctx->catena512_salt,
		       sizeof(ctx->catena512_salt));
		int status;
		if (!input->use_phi) {
			status = Skc_Catena512_without_phi(&ctx->secret.catena512,
			                                   ctx->secret.hash_out,
							   input->password_buffer,
							   input->password_size,
							   input->g_low,
							   input->g_high,
							   input->lambda);
		} else {
			status = Skc_Catena512_with_phi(&ctx->secret.catena512,
			                                ctx->secret.hash_out,
							input->password_buffer,
							input->password_size,
							input->g_low,
							input->g_high,
							input->lambda);
		}
		if (status) {
			CLEANUP_ERROR_(ctx->secret);
			Base_errx("Error: Catena512 failed with error code %d...\nAllocating too much memory?\n", status);
		}
		Base_secure_zero(&ctx->secret.catena512, sizeof(ctx->secret.catena512));
		Base_secure_zero(input->password_buffer, sizeof(input->password_buffer));
		/* Catena512 will output 512 bits. We will has these 512 bits into 1024 output bits using Skein
		 * and the first 512 bits as the encryption key, and the second 512 bits as the authentication key.
		 */
		Skc_Skein512_hash(&ctx->secret.ubi512,
		                  ctx->secret.hash_out,
				  ctx->secret.hash_out,
				  SKC_THREEFISH512_BLOCK_BYTES,
				  (SKC_THREEFISH512_BLOCK_BYTES * 2));
		BASE_STATIC_ASSERT(sizeof(ctx->secret.hash_out) == (SKC_THREEFISH512_BLOCK_BYTES * 2), "Size reminder.");
		memcpy(ctx->secret.enc_key , enc_key , SKC_THREEFISH512_BLOCK_BYTES);
		memcpy(ctx->secret.auth_key, auth_key, SKC_THREEFISH512_BLOCK_BYTES);
		/* Scrub the hash buffer and initialize the Threefish cipher. */
		Base_secure_zero(ctx->secret.hash_out, sizeof(ctx->secret.hash_out));
		Skc_Threefish512_Static_init(&ctx->secret.threefish512_ctr.threefish512,
		                             ctx->secret.enc_key,
					     ctx->tf_tweak);
	}
	uint8_t* out = output_mmap->ptr;
	memcpy(out, SKC_DRAGONFLY_V1_ID, sizeof(SKC_DRAGONFLY_V1_ID));
	out += sizeof(SKC_DRAGONFLY_V1_ID);
	memcpy(out, &output_mmap->size, sizeof(output_mmap->size));
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
		crypt_header[0] = input->padding_bytes;
		Skc_Threefish512_CTR_init(&ctx->secret.threefish512_ctr, ctx->ctr_iv);
		Skc_Threefish512_CTR_xor_keystream(&ctx->secret.threefish512_ctr,
		                                   out,
						   (uint8_t*)crypt_header,
						   sizeof(crypt_header),
						   0);
		out += sizeof(crypt_header);
		if (input->padding_bytes) {
			Skc_Threefish512_CTR_xor_keystream(&ctx->secret.threefish512_ctr,
			                                   out,
							   out,
							   input->padding_bytes,
							   sizeof(crypt_header));
			out += input->padding_bytes;
		}
		Skc_Threefish512_CTR_xor_keystream(&ctx->secret.threefish512_ctr,
		                                   out,
						   input_mmap->ptr,
						   input_mmap->size,
						   sizeof(crypt_header) + input->padding_bytes);
		out += input_mmap->size;
	}
	{
		Skc_Skein512_mac(&ctx->secret.ubi512,
		                 out,
				 output_mmap->ptr,
				 ctx->secret.auth_key,
				 output_mmap->size - SKC_COMMON_MAC_BYTES,
				 SKC_COMMON_MAC_BYTES);
	}
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
	memcpy(&header_size, in, sizeof(header_size));
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
		int ret = Skc_Catena512_without_phi(&ctx->catena512,
		                                    ctx->hash_buf,
						    ctx->password,
						    ctx->password_size,
						    g_low,
						    g_high,
						    lambda);
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
		int ret = Skc_Catena512_with_phi(&ctx->catena512,
		                                 ctx->hash_buf,
						 ctx->password,
						 ctx->password_size,
						 g_low,
						 g_high,
						 lambda);
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
		Skc_Skein512_hash(&ctx->ubi512,
		                  ctx->hash_buf,
				  ctx->hash_buf,
				  SKC_THREEFISH512_BLOCK_BYTES,
				  (SKC_THREEFISH512_BLOCK_BYTES * 2));
		uint8_t* const enc_key = ctx->hash_buf;
		uint8_t* const auth_key = enc_key + SKC_THREEFISH512_BLOCK_BYTES;
		memcpy(ctx->enc_key , enc_key , SKC_THREEFISH512_BLOCK_BYTES);
		memcpy(ctx->auth_key, auth_key, SKC_THREEFISH512_BLOCK_BYTES);
		Base_secure_zero(ctx->hash_buf, sizeof(ctx->hash_buf));
		{
			Skc_Skein512_mac(&ctx->ubi512,
			                 ctx->mac,
					 input_mmap->ptr,
					 ctx->auth_key,
					 input_mmap->size - SKC_COMMON_MAC_BYTES,
					 sizeof(ctx->mac));
			if (Base_ctime_memdiff(ctx->mac, (input_mmap->ptr + input_mmap->size - SKC_COMMON_MAC_BYTES), SKC_COMMON_MAC_BYTES)) {
				Base_secure_zero(ctx, sizeof(*ctx));
				UNLOCK_MEMORY_(ctx, sizeof(*ctx));
				CLEANUP_MMAP_(input_mmap);
				Base_close_file_or_die(output_mmap->file);
				remove(output_filepath);
				Base_errx("Error: Authentication failed.\nPossibilities: Wrong password, the file is corrupted, or it has been tampered with!\n");
			}
		}
		Skc_Threefish512_Static_init(&ctx->threefish512_ctr.threefish512, ctx->enc_key, tweak);
		{
			Skc_Threefish512_CTR_init(&ctx->threefish512_ctr, ctr_iv);
			uint64_t padding_bytes;
			Skc_Threefish512_CTR_xor_keystream(&ctx->threefish512_ctr, (uint8_t*)&padding_bytes,
			                                   in, sizeof(padding_bytes), 0);
			const uint64_t step = padding_bytes + (sizeof(uint64_t) * 2);
			output_mmap->size -= padding_bytes;
			Base_set_file_size_or_die(output_mmap->file, output_mmap->size);
			Base_MMap_map(output_mmap, false);
			in += step;
			Skc_Threefish512_CTR_xor_keystream(&ctx->threefish512_ctr, output_mmap->ptr,
			                                   in, output_mmap->size, step);
		}
		Base_secure_zero(ctx, sizeof(*ctx));
		UNLOCK_MEMORY_(ctx, sizeof(*ctx));
		Base_MMap_sync_or_die(output_mmap);
		CLEANUP_MMAP_(output_mmap);
		CLEANUP_MMAP_(input_mmap);
	}
}
#if 0
void
symm_dragonfly_v1_encrypt (Symm_Dragonfly_V1_Encrypt * BASE_RESTRICT dragonfly_v1_ptr,
			   Shim_Map * const    BASE_RESTRICT input_map_ptr,
			   Shim_Map * const    BASE_RESTRICT output_map_ptr,
			   char const * const  BASE_RESTRICT output_filename)
{
	{ /* Setup the output map. */
		/* Assume the output file's size to be the plaintext size with a visible header. */
		output_map_ptr->size = input_map_ptr->size + SYMM_DRAGONFLY_V1_VISIBLE_METADATA_BYTES + dragonfly_v1_ptr->secret.catena_input.padding_bytes;
		shim_enforce_set_file_size(output_map_ptr->file, output_map_ptr->size);
		shim_enforce_map_memory(output_map_ptr, false);
	}
	LOCK_MEMORY_(&dragonfly_v1_ptr->secret, sizeof(dragonfly_v1_ptr->secret));
	Symm_Catena_Input * catena_input_ptr = &dragonfly_v1_ptr->secret.catena_input;
	{
		Symm_CSPRNG * csprng_p = &catena_input_ptr->csprng;
		symm_csprng_get(csprng_p,
				(uint8_t *)dragonfly_v1_ptr->pub.tf_tweak,
				SYMM_THREEFISH512_TWEAK_BYTES);
		symm_csprng_get(csprng_p,
				dragonfly_v1_ptr->pub.ctr_iv,
				sizeof(dragonfly_v1_ptr->pub.ctr_iv));
		symm_csprng_get(csprng_p,
				dragonfly_v1_ptr->pub.catena_salt,
				sizeof(dragonfly_v1_ptr->pub.catena_salt));
		symm_csprng_delete(csprng_p);
	}
	{
		memcpy(dragonfly_v1_ptr->secret.catena.salt, dragonfly_v1_ptr->pub.catena_salt,
			sizeof(dragonfly_v1_ptr->pub.catena_salt));

		int catena_status;
		if (!catena_input_ptr->use_phi) {
			catena_status = symm_catena_nophi(&dragonfly_v1_ptr->secret.catena,
							  dragonfly_v1_ptr->secret.hash_out,
							  catena_input_ptr->password_buffer,
							  catena_input_ptr->password_size,
							  catena_input_ptr->g_low,
							  catena_input_ptr->g_high,
							  catena_input_ptr->lambda);
		} else {
			catena_status = symm_catena_usephi(&dragonfly_v1_ptr->secret.catena,
							   dragonfly_v1_ptr->secret.hash_out,
							   catena_input_ptr->password_buffer,
							   catena_input_ptr->password_size,
							   catena_input_ptr->g_low,
							   catena_input_ptr->g_high,
							   catena_input_ptr->lambda);
		}
		if (catena_status == SYMM_CATENA_ALLOC_FAILURE) {
			CLEANUP_ERROR_(dragonfly_v1_ptr->secret);
			shim_errx("Error: Catena failed with error code %d...\nAllocating too much memory?\n", catena_status);
		}
		shim_secure_zero(&dragonfly_v1_ptr->secret.catena , sizeof(dragonfly_v1_ptr->secret.catena));
		shim_secure_zero(catena_input_ptr->password_buffer, sizeof(catena_input_ptr->password_buffer));
		/* CATENA will output 512 bits. We will hash these 512 bits into 1024 output bits using Skein,
		 * and use the first 512 bits as the encryption key, and the second 512 bits as the authentication key.
		 */
		symm_skein512_hash(&dragonfly_v1_ptr->secret.ubi512,
				   dragonfly_v1_ptr->secret.hash_out,
				   dragonfly_v1_ptr->secret.hash_out,
				   SYMM_THREEFISH512_BLOCK_BYTES,
				   (SYMM_THREEFISH512_BLOCK_BYTES * 2));
		BASE_STATIC_ASSERT(sizeof(dragonfly_v1_ptr->secret.hash_out) == (SYMM_THREEFISH512_BLOCK_BYTES * 2), "Size reminder.");
		memcpy(dragonfly_v1_ptr->secret.enc_key, dragonfly_v1_ptr->secret.hash_out, SYMM_THREEFISH512_BLOCK_BYTES);
		memcpy(dragonfly_v1_ptr->secret.auth_key, dragonfly_v1_ptr->secret.hash_out + SYMM_THREEFISH512_BLOCK_BYTES,
			SYMM_THREEFISH512_BLOCK_BYTES);
		/* Scrub the hash buffer and re-key the 'stored' Threefish cipher variant.
		 */
		shim_secure_zero(dragonfly_v1_ptr->secret.hash_out, sizeof(dragonfly_v1_ptr->secret.hash_out));
		symm_threefish512_stored_rekey(&dragonfly_v1_ptr->secret.threefish512_ctr.threefish_stored,
			dragonfly_v1_ptr->secret.enc_key, dragonfly_v1_ptr->pub.tf_tweak);
	}
	uint8_t * out = output_map_ptr->ptr;
	memcpy(out, SYMM_DRAGONFLY_V1_ID, sizeof(SYMM_DRAGONFLY_V1_ID));
	out += sizeof(SYMM_DRAGONFLY_V1_ID);
	memcpy(out, &output_map_ptr->size, sizeof(output_map_ptr->size));
	out += sizeof(output_map_ptr->size);
	(*out++) = catena_input_ptr->g_low;
	(*out++) = catena_input_ptr->g_high;
	(*out++) = catena_input_ptr->lambda;
	(*out++) = catena_input_ptr->use_phi;
	memcpy(out, dragonfly_v1_ptr->pub.tf_tweak, SYMM_THREEFISH512_TWEAK_BYTES);
	out += SYMM_THREEFISH512_TWEAK_BYTES;
	memcpy(out, dragonfly_v1_ptr->pub.catena_salt, SYMM_CATENA_SALT_BYTES);
	out += SYMM_CATENA_SALT_BYTES;
	memcpy(out, dragonfly_v1_ptr->pub.ctr_iv, SYMM_THREEFISH512_CTR_IV_BYTES);
	out += SYMM_THREEFISH512_CTR_IV_BYTES;
	{
		uint64_t crypt_header[2] = { 0 };
		crypt_header[ 0 ] = catena_input_ptr->padding_bytes;
		symm_threefish512_ctr_setiv(&dragonfly_v1_ptr->secret.threefish512_ctr,
					    dragonfly_v1_ptr->pub.ctr_iv);
		symm_threefish512_ctr_xorcrypt(&dragonfly_v1_ptr->secret.threefish512_ctr,
						out,
						(uint8_t *)crypt_header,
						sizeof(crypt_header),
						0);
		out += sizeof(crypt_header);
		if (catena_input_ptr->padding_bytes) {
			symm_threefish512_ctr_xorcrypt(&dragonfly_v1_ptr->secret.threefish512_ctr,
							out,
							out,
							catena_input_ptr->padding_bytes,
							sizeof(crypt_header));
			out += catena_input_ptr->padding_bytes;
		}
		symm_threefish512_ctr_xorcrypt(&dragonfly_v1_ptr->secret.threefish512_ctr,
						out,
						input_map_ptr->ptr,
						input_map_ptr->size,
						sizeof(crypt_header) + catena_input_ptr->padding_bytes);
		out += input_map_ptr->size;
	}
	{
		symm_skein512_mac(&dragonfly_v1_ptr->secret.ubi512,
				  out,
				  output_map_ptr->ptr,
				  dragonfly_v1_ptr->secret.auth_key,
				  output_map_ptr->size - SYMM_COMMON_MAC_BYTES,
				  SYMM_COMMON_MAC_BYTES);
	}
	CLEANUP_SUCCESS_(dragonfly_v1_ptr->secret);
}

void
symm_dragonfly_v1_decrypt (Symm_Dragonfly_V1_Decrypt * const BASE_RESTRICT dfly_dcrypt_p,
			   Shim_Map * const 		     BASE_RESTRICT input_map_p,
			   Shim_Map * const 		     BASE_RESTRICT output_map_p,
			   char const *     		     BASE_RESTRICT output_fname)
{
	output_map_p->size = input_map_p->size - SYMM_DRAGONFLY_V1_VISIBLE_METADATA_BYTES;
#define MINIMUM_POSSIBLE_FILE_SIZE_	(SYMM_DRAGONFLY_V1_VISIBLE_METADATA_BYTES + 1)
	if (input_map_p->size < MINIMUM_POSSIBLE_FILE_SIZE_) {
		shim_enforce_close_file(output_map_p->file);
		remove(output_fname);
		shim_errx("Error: Input file doesn't appear to be large enough to be a SSC_DRAGONFLY_V1 encryped file\n");
	}
#define U64_ALIGN_ BASE_ALIGNAS (uint64_t)
	uint8_t const * in = input_map_p->ptr;
	struct {
		uint64_t                        tweak       [SYMM_THREEFISH512_EXTERNAL_TWEAK_WORDS];
		U64_ALIGN_ uint8_t catena_salt [SYMM_CATENA_SALT_BYTES];
		U64_ALIGN_ uint8_t ctr_iv      [SYMM_THREEFISH512_CTR_IV_BYTES];
		uint64_t                        header_size;
		uint8_t                         header_id   [sizeof(SYMM_DRAGONFLY_V1_ID)];
		uint8_t                         g_low;
		uint8_t                         g_high;
		uint8_t                         lambda;
		uint8_t                         use_phi;
	} pub;
	{
		memcpy(pub.header_id, in, sizeof(pub.header_id));
		in += sizeof(pub.header_id);
		memcpy(&pub.header_size, in, sizeof(pub.header_size));
		in += sizeof(pub.header_size);
		pub.g_low   = (*in++);
		pub.g_high  = (*in++);
		pub.lambda  = (*in++);
		pub.use_phi = (*in++);
		memcpy(pub.tweak, in, SYMM_THREEFISH512_TWEAK_BYTES);
		in += SYMM_THREEFISH512_TWEAK_BYTES;
		memcpy(pub.catena_salt, in, SYMM_CATENA_SALT_BYTES);
		in += SYMM_CATENA_SALT_BYTES;
		memcpy(pub.ctr_iv, in, SYMM_THREEFISH512_CTR_IV_BYTES);
		in += SYMM_THREEFISH512_CTR_IV_BYTES;
	}
	if (memcmp(pub.header_id, SYMM_DRAGONFLY_V1_ID, sizeof(SYMM_DRAGONFLY_V1_ID))) {
		shim_enforce_unmap_memory(input_map_p);
		shim_enforce_close_file(input_map_p->file);
		shim_enforce_close_file(output_map_p->file);
		remove(output_fname);
		shim_errx("Error: Not a Dragonfly_V1 encryped file.\n");
	}
	LOCK_MEMORY_(dfly_dcrypt_p, sizeof(*dfly_dcrypt_p));
	memcpy(dfly_dcrypt_p->catena.salt, pub.catena_salt, sizeof(pub.catena_salt));
	if (!pub.use_phi) {
		BASE_STATIC_ASSERT(sizeof(pub.catena_salt) == sizeof(dfly_dcrypt_p->catena.salt), "These must be the same size.");
		int ret = symm_catena_nophi(&dfly_dcrypt_p->catena,
					    dfly_dcrypt_p->hash_buf,
					    dfly_dcrypt_p->password,
					    dfly_dcrypt_p->password_size,
					    pub.g_low,
					    pub.g_high,
					    pub.lambda);
		if (ret != SYMM_CATENA_SUCCESS) {
			shim_secure_zero(dfly_dcrypt_p, sizeof(*dfly_dcrypt_p));
			UNLOCK_MEMORY_(dfly_dcrypt_p, sizeof(*dfly_dcrypt_p));
			CLEANUP_MMAP_(input_map_p);
			shim_enforce_close_file(output_map_p->file);
			remove(output_fname);
			shim_errx("Error: Catena failed with error code %d...\nDo you have enough memory to decrypt this file?\n", ret);

		}
		shim_secure_zero(&dfly_dcrypt_p->catena, sizeof(dfly_dcrypt_p->catena));
	} else {
		int ret = symm_catena_usephi(&dfly_dcrypt_p->catena,
					     dfly_dcrypt_p->hash_buf,
					     dfly_dcrypt_p->password,
					     dfly_dcrypt_p->password_size,
					     pub.g_low,
					     pub.g_high,
					     pub.lambda);

		if (ret != SYMM_CATENA_SUCCESS) {
			shim_secure_zero(dfly_dcrypt_p, sizeof(*dfly_dcrypt_p));
			UNLOCK_MEMORY_(dfly_dcrypt_p, sizeof(*dfly_dcrypt_p));
			CLEANUP_MMAP_(input_map_p);
			shim_enforce_close_file(output_map_p->file);
			remove(output_fname);
			shim_errx("Error: Catena failed with error code %d...\nDo you have enough memory to decrypt this file?\n", ret);
		}
		shim_secure_zero(&dfly_dcrypt_p->catena, sizeof(dfly_dcrypt_p->catena));
	}
	{ /* Generate the keys. */
		symm_skein512_hash(&dfly_dcrypt_p->ubi512,
				   dfly_dcrypt_p->hash_buf,
				   dfly_dcrypt_p->hash_buf,
				   SYMM_THREEFISH512_BLOCK_BYTES,
				   (SYMM_THREEFISH512_BLOCK_BYTES * 2));
		memcpy(dfly_dcrypt_p->enc_key, dfly_dcrypt_p->hash_buf, SYMM_THREEFISH512_BLOCK_BYTES);
		memcpy(dfly_dcrypt_p->auth_key, dfly_dcrypt_p->hash_buf + SYMM_THREEFISH512_BLOCK_BYTES,
			SYMM_THREEFISH512_BLOCK_BYTES);
		shim_secure_zero(dfly_dcrypt_p->hash_buf, sizeof(dfly_dcrypt_p->hash_buf));
		{
			symm_skein512_mac(&dfly_dcrypt_p->ubi512,
					  dfly_dcrypt_p->mac,
					  input_map_p->ptr,
					  dfly_dcrypt_p->auth_key,
					  input_map_p->size - SYMM_COMMON_MAC_BYTES,
					  sizeof(dfly_dcrypt_p->mac));

			if (shim_ctime_memdiff(dfly_dcrypt_p->mac, (input_map_p->ptr + input_map_p->size - SYMM_COMMON_MAC_BYTES), SYMM_COMMON_MAC_BYTES)) {
				shim_secure_zero(dfly_dcrypt_p, sizeof(*dfly_dcrypt_p));
				UNLOCK_MEMORY_(dfly_dcrypt_p, sizeof(*dfly_dcrypt_p));
				CLEANUP_MMAP_(input_map_p);
				shim_enforce_close_file(output_map_p->file);
				remove(output_fname);
				shim_errx("Error: Authentication failed.\nPossibilities: Wrong password, the file is corrupted, or it has been tampered with.\n");
			}
		}
		symm_threefish512_stored_rekey(&dfly_dcrypt_p->threefish512_ctr.threefish_stored, dfly_dcrypt_p->enc_key,
			pub.tweak);
		{
			symm_threefish512_ctr_setiv(&dfly_dcrypt_p->threefish512_ctr,
						    pub.ctr_iv);
			uint64_t padding_bytes;
			symm_threefish512_ctr_xorcrypt(&dfly_dcrypt_p->threefish512_ctr, (uint8_t *)&padding_bytes,
						       in, sizeof(padding_bytes), 0);
			uint64_t const step = padding_bytes + (sizeof(uint64_t) * 2);
			output_map_p->size -= padding_bytes;
			shim_enforce_set_file_size(output_map_p->file, output_map_p->size);
			shim_enforce_map_memory(output_map_p, false);
			in += step;
			symm_threefish512_ctr_xorcrypt(&dfly_dcrypt_p->threefish512_ctr, output_map_p->ptr,
							in, output_map_p->size, step);
		}
		shim_secure_zero(dfly_dcrypt_p, sizeof(*dfly_dcrypt_p));
		UNLOCK_MEMORY_(dfly_dcrypt_p, sizeof(*dfly_dcrypt_p));
		shim_enforce_sync_map(output_map_p);
		CLEANUP_MMAP_(output_map_p);
		CLEANUP_MMAP_(input_map_p);
	}
}
void Skc_Dragonfly_V1_dump_header (R_(Base_MMap* const) mem_map, R_(const char* const) filepath) {
#define MIN_SIZE_ (SKC_DRAGONFLY_V1_VISIBLE_METADATA_BYTES + 1)
	if (mem_map->size < MIN_SIZE_) {
		CLEANUP_MAP_(mem_map);
		Base_errx("Filepath %s looks too small to be SSC_DRAGONFLY_V1 encrypted.\n", filepath);
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
		memcpy(&total_size, p, sizeof(total_size));
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
	id[sizeof(id) - 1] = 0;
	fprintf(stdout, "File Header ID : %s\n", (char*)id);
	fprintf(stdout, "File Size      : %" PRIu64 "\n", total_size);
	fprintf(stdout, "Garlic Low     : %" PRIu8  "\n", g_low);
	fprintf(stdout, "Garlic High    : %" PRIu8  "\n", g_high);
	fprintf(stdout, "Lambda         : %" PRIu8  "\n", lambda);
	if (!use_phi)
		fprintf(stdout, "The Phi function is not used.\n");
	else
		fprintf(stdout, "WARNING: The Phi function is used. Beware side-channel timing attacks when decrypting this file.\n");
	fputs("Threefish-512 Tweak:\n", stdout);
	Base_print_byte_buffer(tweak, sizeof(tweak));
	fputs("\nCatena-512 Salt:\n", stdout);
	Base_print_byte_buffer(salt, sizeof(salt));
	fputs("\nThreefish-512 Ctr Mode IV:\n", stdout);
	Base_print_byte_buffer(ctr_iv, sizeof(ctr_iv));
	fputs("\nSkein-512 Message Authentication Code:\n", stdout);
	Base_print_byte_buffer(mac, sizeof(mac));
	fputs("\n", stdout);
}
#endif
