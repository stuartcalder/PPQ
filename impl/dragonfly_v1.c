#include <symm/dragonfly_v1.h>
#include <symm/csprng.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#ifdef SHIM_FEATURE_MEMORYLOCKING
#	define LOCK_MEMORY_(address, size)	shim_enforce_lock_memory( address, size )
#	define UNLOCK_MEMORY_(address, size)	shim_enforce_unlock_memory( address, size )
#else
#	define LOCK_MEMORY_(nil_0, nil_1)	/* Nil */
#	define UNLOCK_MEMORY_(nil_0, nil_1)	/* Nil */
#endif

#define CLEANUP_MAP_(shim_map_ptr) \
	shim_enforce_unmap_memory( shim_map_ptr ); \
	shim_enforce_close_file( shim_map_ptr->file )

#define CLEANUP_ERROR_(secret_data) \
	shim_secure_zero( &secret_data, sizeof(secret_data) ); \
	UNLOCK_MEMORY_ (&secret_data, sizeof(secret_data)); \
	CLEANUP_MAP_ (output_map_ptr); \
	CLEANUP_MAP_ (input_map_ptr); \
	remove( output_filename )

#define CLEANUP_SUCCESS_(secret_data) \
	shim_secure_zero( &secret_data, sizeof(secret_data) ); \
	UNLOCK_MEMORY_ (&secret_data, sizeof(secret_data)); \
	shim_enforce_sync_map( output_map_ptr ); \
	CLEANUP_MAP_ (output_map_ptr); \
	CLEANUP_MAP_ (input_map_ptr)

void
symm_dragonfly_v1_encrypt (Symm_Dragonfly_V1_Encrypt * SHIM_RESTRICT dragonfly_v1_ptr,
			   Shim_Map * const    SHIM_RESTRICT input_map_ptr,
			   Shim_Map * const    SHIM_RESTRICT output_map_ptr,
			   char const * const  SHIM_RESTRICT output_filename)
{
	{ /* Setup the output map. */
		/* Assume the output file's size to be the plaintext size with a visible header. */
		output_map_ptr->size = input_map_ptr->size + SYMM_DRAGONFLY_V1_VISIBLE_METADATA_BYTES + dragonfly_v1_ptr->secret.catena_input.padding_bytes;
		shim_enforce_set_file_size( output_map_ptr->file, output_map_ptr->size );
		shim_enforce_map_memory( output_map_ptr, false );
	}
	LOCK_MEMORY_ (&dragonfly_v1_ptr->secret, sizeof(dragonfly_v1_ptr->secret));
	Symm_Catena_Input *catena_input_ptr = &dragonfly_v1_ptr->secret.catena_input;
	{
		Symm_CSPRNG * csprng_p = &catena_input_ptr->csprng;
		symm_csprng_get( csprng_p,
				 (uint8_t *)dragonfly_v1_ptr->pub.tf_tweak,
				 SYMM_THREEFISH512_TWEAK_BYTES );
		symm_csprng_get( csprng_p,
				 dragonfly_v1_ptr->pub.ctr_iv,
				 sizeof(dragonfly_v1_ptr->pub.ctr_iv) );
		symm_csprng_get( csprng_p,
				 dragonfly_v1_ptr->pub.catena_salt,
				 sizeof(dragonfly_v1_ptr->pub.catena_salt) );
		symm_csprng_delete( csprng_p );
	}
	{
		memcpy( dragonfly_v1_ptr->secret.catena.salt,
			dragonfly_v1_ptr->pub.catena_salt,
			sizeof(dragonfly_v1_ptr->pub.catena_salt) );

		int catena_status;
		if( !catena_input_ptr->use_phi ) {
			catena_status = symm_catena_nophi( &dragonfly_v1_ptr->secret.catena,
							   dragonfly_v1_ptr->secret.hash_out,
							   catena_input_ptr->password_buffer,
							   catena_input_ptr->password_size,
							   catena_input_ptr->g_low,
							   catena_input_ptr->g_high,
							   catena_input_ptr->lambda );
		} else {
			catena_status = symm_catena_usephi( &dragonfly_v1_ptr->secret.catena,
							    dragonfly_v1_ptr->secret.hash_out,
							    catena_input_ptr->password_buffer,
							    catena_input_ptr->password_size,
							    catena_input_ptr->g_low,
							    catena_input_ptr->g_high,
							    catena_input_ptr->lambda );
		}
		switch( catena_status ) {
			case SYMM_CATENA_ALLOC_FAILURE: {
				CLEANUP_ERROR_ (dragonfly_v1_ptr->secret);
				SHIM_ERRX ("Error: Catena failed with error code %d...\nAllocating too much memory?\n", catena_status);
			} break;
		}
		shim_secure_zero( &dragonfly_v1_ptr->secret.catena , sizeof(dragonfly_v1_ptr->secret.catena)   );
		shim_secure_zero( catena_input_ptr->password_buffer, sizeof(catena_input_ptr->password_buffer) );
		/* CATENA will output 512 bits. We will hash these 512 bits into 1024 output bits using Skein,
		 * and use the first 512 bits as the encryption key, and the second 512 bits as the authentication key.
		 */
		symm_skein512_hash( &dragonfly_v1_ptr->secret.ubi512,
				    dragonfly_v1_ptr->secret.hash_out,
				    dragonfly_v1_ptr->secret.hash_out,
				    SYMM_THREEFISH512_BLOCK_BYTES,
				    (SYMM_THREEFISH512_BLOCK_BYTES * 2) );
		SHIM_STATIC_ASSERT (sizeof(dragonfly_v1_ptr->secret.hash_out) == (SYMM_THREEFISH512_BLOCK_BYTES * 2), "Size reminder.");
		memcpy( dragonfly_v1_ptr->secret.enc_key,
			dragonfly_v1_ptr->secret.hash_out,
			SYMM_THREEFISH512_BLOCK_BYTES );
		memcpy( dragonfly_v1_ptr->secret.auth_key,
			dragonfly_v1_ptr->secret.hash_out + SYMM_THREEFISH512_BLOCK_BYTES,
			SYMM_THREEFISH512_BLOCK_BYTES );
		/* Scrub the hash buffer and re-key the 'stored' Threefish cipher variant.
		 */
		shim_secure_zero( dragonfly_v1_ptr->secret.hash_out, sizeof(dragonfly_v1_ptr->secret.hash_out) );
		symm_threefish512_stored_rekey( &dragonfly_v1_ptr->secret.threefish512_ctr.threefish_stored,
						dragonfly_v1_ptr->secret.enc_key,
						dragonfly_v1_ptr->pub.tf_tweak );
	}
	uint8_t * out = output_map_ptr->ptr;
	memcpy( out, SYMM_DRAGONFLY_V1_ID, sizeof(SYMM_DRAGONFLY_V1_ID) );
	out += sizeof(SYMM_DRAGONFLY_V1_ID);
	memcpy( out, &output_map_ptr->size, sizeof(output_map_ptr->size) );
	out += sizeof(output_map_ptr->size);
	(*out++) = catena_input_ptr->g_low;
	(*out++) = catena_input_ptr->g_high;
	(*out++) = catena_input_ptr->lambda;
	(*out++) = catena_input_ptr->use_phi;
	memcpy( out, dragonfly_v1_ptr->pub.tf_tweak, SYMM_THREEFISH512_TWEAK_BYTES );
	out += SYMM_THREEFISH512_TWEAK_BYTES;
	memcpy( out, dragonfly_v1_ptr->pub.catena_salt, SYMM_CATENA_SALT_BYTES );
	out += SYMM_CATENA_SALT_BYTES;
	memcpy( out, dragonfly_v1_ptr->pub.ctr_iv, SYMM_THREEFISH512_CTR_IV_BYTES );
	out += SYMM_THREEFISH512_CTR_IV_BYTES;
	{
		uint64_t crypt_header [2] = { 0 };
		crypt_header[ 0 ] = catena_input_ptr->padding_bytes;
		symm_threefish512_ctr_setiv( &dragonfly_v1_ptr->secret.threefish512_ctr,
					     dragonfly_v1_ptr->pub.ctr_iv );
		symm_threefish512_ctr_xorcrypt( &dragonfly_v1_ptr->secret.threefish512_ctr,
						out,
						(uint8_t *)crypt_header,
						sizeof(crypt_header),
						0 );
		out += sizeof(crypt_header);
		if( catena_input_ptr->padding_bytes ) {
			symm_threefish512_ctr_xorcrypt( &dragonfly_v1_ptr->secret.threefish512_ctr,
							out,
							out,
							catena_input_ptr->padding_bytes,
							sizeof(crypt_header) );
			out += catena_input_ptr->padding_bytes;
		}
		symm_threefish512_ctr_xorcrypt( &dragonfly_v1_ptr->secret.threefish512_ctr,
						out,
						input_map_ptr->ptr,
						input_map_ptr->size,
						sizeof(crypt_header) + catena_input_ptr->padding_bytes );
		out += input_map_ptr->size;
	}
	{
		symm_skein512_mac( &dragonfly_v1_ptr->secret.ubi512,
				   out,
				   output_map_ptr->ptr,
				   dragonfly_v1_ptr->secret.auth_key,
				   output_map_ptr->size - SYMM_COMMON_MAC_BYTES,
				   SYMM_COMMON_MAC_BYTES );
	}
	CLEANUP_SUCCESS_ (dragonfly_v1_ptr->secret);
}

void
symm_dragonfly_v1_decrypt (Symm_Dragonfly_V1_Decrypt * const SHIM_RESTRICT dfly_dcrypt_p,
			   Shim_Map * const 		     SHIM_RESTRICT input_map_p,
			   Shim_Map * const 		     SHIM_RESTRICT output_map_p,
			   char const *     		     SHIM_RESTRICT output_fname)
{
	output_map_p->size = input_map_p->size - SYMM_DRAGONFLY_V1_VISIBLE_METADATA_BYTES;
#define MINIMUM_POSSIBLE_FILE_SIZE_	(SYMM_DRAGONFLY_V1_VISIBLE_METADATA_BYTES + 1)
	if( input_map_p->size < MINIMUM_POSSIBLE_FILE_SIZE_ ) {
		shim_enforce_close_file( output_map_p->file );
		remove( output_fname );
		SHIM_ERRX ("Error: Input file doesn't appear to be large enough to be a SSC_DRAGONFLY_V1 encryped file\n");
	}
#define U64_ALIGN_ SHIM_ALIGNAS (uint64_t)
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
		memcpy( pub.header_id, in, sizeof(pub.header_id) );
		in += sizeof(pub.header_id);
		memcpy( &pub.header_size, in, sizeof(pub.header_size) );
		in += sizeof(pub.header_size);
		pub.g_low   = (*in++);
		pub.g_high  = (*in++);
		pub.lambda  = (*in++);
		pub.use_phi = (*in++);
		memcpy( pub.tweak, in, SYMM_THREEFISH512_TWEAK_BYTES );
		in += SYMM_THREEFISH512_TWEAK_BYTES;
		memcpy( pub.catena_salt, in, SYMM_CATENA_SALT_BYTES );
		in += SYMM_CATENA_SALT_BYTES;
		memcpy( pub.ctr_iv, in, SYMM_THREEFISH512_CTR_IV_BYTES );
		in += SYMM_THREEFISH512_CTR_IV_BYTES;
	}
	if( memcmp( pub.header_id, SYMM_DRAGONFLY_V1_ID, sizeof(SYMM_DRAGONFLY_V1_ID) ) ) {
		shim_enforce_unmap_memory( input_map_p );
		shim_enforce_close_file( input_map_p->file );
		shim_enforce_close_file( output_map_p->file );
		remove( output_fname );
		SHIM_ERRX ("Error: Not a Dragonfly_V1 encryped file.\n");
	}
	LOCK_MEMORY_ (dfly_dcrypt_p, sizeof(*dfly_dcrypt_p) );
	memcpy( dfly_dcrypt_p->catena.salt,
		pub.catena_salt,
		sizeof(pub.catena_salt) );
	if( !pub.use_phi ) {
		SHIM_STATIC_ASSERT (sizeof(pub.catena_salt) == sizeof(dfly_dcrypt_p->catena.salt), "These must be the same size.");
		int ret = symm_catena_nophi( &dfly_dcrypt_p->catena,
					     dfly_dcrypt_p->hash_buf,
					     dfly_dcrypt_p->password,
					     dfly_dcrypt_p->password_size,
					     pub.g_low,
					     pub.g_high,
					     pub.lambda );
		if( ret != SYMM_CATENA_SUCCESS ) {
			shim_secure_zero( dfly_dcrypt_p, sizeof(*dfly_dcrypt_p) );
			UNLOCK_MEMORY_ (dfly_dcrypt_p, sizeof(*dfly_dcrypt_p));
			CLEANUP_MAP_ (input_map_p);
			shim_enforce_close_file( output_map_p->file );
			remove( output_fname );
			SHIM_ERRX ("Error: Catena failed with error code %d...\nDo you have enough memory to decrypt this file?\n", ret);

		}
		shim_secure_zero( &dfly_dcrypt_p->catena, sizeof(dfly_dcrypt_p->catena) );
	} else {
		int ret = symm_catena_usephi( &dfly_dcrypt_p->catena,
					      dfly_dcrypt_p->hash_buf,
					      dfly_dcrypt_p->password,
					      dfly_dcrypt_p->password_size,
					      pub.g_low,
					      pub.g_high,
					      pub.lambda );

		if( ret != SYMM_CATENA_SUCCESS ) {
			shim_secure_zero( dfly_dcrypt_p, sizeof(*dfly_dcrypt_p) );
			UNLOCK_MEMORY_ (dfly_dcrypt_p, sizeof(*dfly_dcrypt_p));
			CLEANUP_MAP_ (input_map_p);
			shim_enforce_close_file( output_map_p->file );
			remove( output_fname );
			SHIM_ERRX ("Error: Catena failed with error code %d...\nDo you have enough memory to decrypt this file?\n", ret);
		}
		shim_secure_zero( &dfly_dcrypt_p->catena, sizeof(dfly_dcrypt_p->catena) );
	}
	{ /* Generate the keys. */
		symm_skein512_hash( &dfly_dcrypt_p->ubi512,
				    dfly_dcrypt_p->hash_buf,
				    dfly_dcrypt_p->hash_buf,
				    SYMM_THREEFISH512_BLOCK_BYTES,
				    (SYMM_THREEFISH512_BLOCK_BYTES * 2) );
		memcpy( dfly_dcrypt_p->enc_key,
			dfly_dcrypt_p->hash_buf,
			SYMM_THREEFISH512_BLOCK_BYTES );
		memcpy( dfly_dcrypt_p->auth_key,
			dfly_dcrypt_p->hash_buf + SYMM_THREEFISH512_BLOCK_BYTES,
			SYMM_THREEFISH512_BLOCK_BYTES );
		shim_secure_zero( dfly_dcrypt_p->hash_buf, sizeof(dfly_dcrypt_p->hash_buf) );
		{
			symm_skein512_mac( &dfly_dcrypt_p->ubi512,
					   dfly_dcrypt_p->mac,
					   input_map_p->ptr,
					   dfly_dcrypt_p->auth_key,
					   input_map_p->size - SYMM_COMMON_MAC_BYTES,
					   sizeof(dfly_dcrypt_p->mac) );
			if( shim_ctime_memdiff( dfly_dcrypt_p->mac, (input_map_p->ptr + input_map_p->size - SYMM_COMMON_MAC_BYTES), SYMM_COMMON_MAC_BYTES ) ) {
				shim_secure_zero( dfly_dcrypt_p, sizeof(*dfly_dcrypt_p) );
				UNLOCK_MEMORY_ (dfly_dcrypt_p, sizeof(*dfly_dcrypt_p));
				CLEANUP_MAP_ (input_map_p);
				shim_enforce_close_file( output_map_p->file );
				remove( output_fname );
				SHIM_ERRX ("Error: Authentication failed.\nPossibilities: Wrong password, the file is corrupted, or it has been tampered with.\n");
			}
		}
		symm_threefish512_stored_rekey( &dfly_dcrypt_p->threefish512_ctr.threefish_stored,
						dfly_dcrypt_p->enc_key,
						pub.tweak );
		{
			symm_threefish512_ctr_setiv( &dfly_dcrypt_p->threefish512_ctr,
						     pub.ctr_iv );
			uint64_t padding_bytes;
			symm_threefish512_ctr_xorcrypt( &dfly_dcrypt_p->threefish512_ctr,
							(uint8_t *)&padding_bytes,
							in,
							sizeof(padding_bytes),
							0 );
			uint64_t const step = padding_bytes + (sizeof(uint64_t) * 2);
			output_map_p->size -= padding_bytes;
			shim_enforce_set_file_size( output_map_p->file, output_map_p->size );
			shim_enforce_map_memory( output_map_p, false );
			in += step;
			symm_threefish512_ctr_xorcrypt( &dfly_dcrypt_p->threefish512_ctr,
							output_map_p->ptr,
							in,
							output_map_p->size,
							step );
		}
		shim_secure_zero( dfly_dcrypt_p, sizeof(*dfly_dcrypt_p) );
		UNLOCK_MEMORY_ (dfly_dcrypt_p, sizeof(*dfly_dcrypt_p));
		shim_enforce_sync_map( output_map_p );
		CLEANUP_MAP_ (output_map_p);
		CLEANUP_MAP_ (input_map_p);
	}
}
void
symm_dragonfly_v1_dump_header (Shim_Map * const SHIM_RESTRICT input_map_p,
			       char const *     SHIM_RESTRICT filename)
{
#define MIN_SIZE_	(SYMM_DRAGONFLY_V1_VISIBLE_METADATA_BYTES + 1)
	if( input_map_p->size < MIN_SIZE_ ) {
		CLEANUP_MAP_ (input_map_p);
		SHIM_ERRX ("File %s looks too small to be SSC_DRAGONFLY_V1 encrypted\n", filename);
	}
	struct {
		uint8_t id [sizeof(SYMM_DRAGONFLY_V1_ID)];
		uint64_t total_size;
		uint8_t g_low;
		uint8_t g_high;
		uint8_t lambda;
		uint8_t use_phi;
		uint8_t tweak  [SYMM_THREEFISH512_TWEAK_BYTES];
		uint8_t salt   [SYMM_CATENA_SALT_BYTES];
		uint8_t ctr_iv [SYMM_THREEFISH512_CTR_IV_BYTES];
	} header;
	uint8_t mac [SYMM_COMMON_MAC_BYTES];
	{
		uint8_t const *p = input_map_p->ptr;
		memcpy( header.id, p, sizeof(header.id) );
		p += sizeof(header.id);
		memcpy( &header.total_size, p, sizeof(header.total_size) );
		p += sizeof(header.total_size);
		header.g_low   = (*p++);
		header.g_high  = (*p++);
		header.lambda  = (*p++);
		header.use_phi = (*p++);
		memcpy( header.tweak, p, sizeof(header.tweak) );
		p += sizeof(header.tweak);
		memcpy( header.salt, p, sizeof(header.salt) );
		p += sizeof(header.salt);
		memcpy( header.ctr_iv, p, sizeof(header.ctr_iv) );
		p = input_map_p->ptr + input_map_p->size - SYMM_COMMON_MAC_BYTES;
		memcpy( mac, p, sizeof(mac) );
	}
	CLEANUP_MAP_ (input_map_p);

	header.id[ sizeof(header.id) - 1 ] = UINT8_C (0);
	fprintf( stdout, "File Header ID : %s\n", (char *)header.id );
	fprintf( stdout, "File Size      : %" PRIu64 "\n", header.total_size );
	fprintf( stdout, "Garlic Low     : %" PRIu8  "\n", header.g_low );
	fprintf( stdout, "Garlic High    : %" PRIu8  "\n", header.g_high );
	fprintf( stdout, "Lambda         : %" PRIu8  "\n", header.lambda );
	if( !header.use_phi )
		fprintf( stdout, "The Phi function is not used.\n" );
	else
		fprintf( stdout, "WARNING: The Phi function is used. Beware side-channel timing attacks when decrypting this.\n" );
	fputs(   "Threefish Tweak :\n", stdout );
	shim_print_byte_buffer( header.tweak, sizeof(header.tweak) );
	fputs( "\nCatena Salt     :\n", stdout );
	shim_print_byte_buffer( header.salt, sizeof(header.salt) );
	fputs( "\nThreefish CTR-Mode IV:\n", stdout );
	shim_print_byte_buffer( header.ctr_iv, sizeof(header.ctr_iv) );
	fputs( "\nSkein Message Authentication Code:\n", stdout );
	shim_print_byte_buffer( mac, sizeof(mac) );
	fputs( "\n", stdout );
}
