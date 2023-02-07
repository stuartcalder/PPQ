/* Copyright (c) 2020-2023 Stuart Steven Calder
 * See accompanying LICENSE file for licensing information. */
#include "skein512.h"

#define R_ BASE_RESTRICT

void Skc_Skein512_hash(
 Skc_UBI512* const R_ ubi512,
 uint8_t*             out,
 const uint8_t*       in,
 const uint64_t       num_in,
 const uint64_t       num_out)
{
  memset(ubi512->key_state, 0, SKC_THREEFISH512_BLOCK_BYTES);
  Skc_UBI512_chain_config(ubi512, (num_out * CHAR_BIT));
  Skc_UBI512_chain_message(ubi512, in, num_in);
  Skc_UBI512_chain_output(ubi512, out, num_out);
}

void Skc_Skein512_hash_native(
 Skc_UBI512* const R_ ubi512,
 uint8_t*             out,
 const uint8_t*       in,
 const uint64_t       num_in)
{
  static const uint8_t init [SKC_THREEFISH512_BLOCK_BYTES] = {
    0xce,0x51,0x9c,0x74,0xff,0xad,0x03,0x49,
    0x03,0xdf,0x46,0x97,0x39,0xde,0x95,0x0d,
    0xce,0x9b,0xc7,0x27,0x41,0x93,0xd1,0x8f,
    0xb1,0x2c,0x35,0xff,0x29,0x56,0x25,0x9a,
    0xb0,0xa7,0x6c,0xdf,0x99,0x25,0xb6,0x5d,
    0xf4,0xc3,0xd5,0xa9,0x4c,0x39,0xbe,0xea,
    0x23,0xb5,0x75,0x1a,0xc7,0x12,0x11,0x99,
    0x33,0xcc,0x0f,0x66,0x0b,0xa4,0x18,0xae
  };
  memcpy(ubi512->key_state, init, sizeof(init));
  Skc_UBI512_chain_message(ubi512, in, num_in);
  Skc_UBI512_chain_native_output(ubi512, out);
}

void Skc_Skein512_mac(
 Skc_UBI512* const R_ ubi512,
 uint8_t*             out,
 const uint8_t*       in,
 const uint8_t* R_    key_in,
 const uint64_t       num_in,
 const uint64_t       num_out)
{
  memset(ubi512->key_state, 0, SKC_THREEFISH512_BLOCK_BYTES);
  Skc_UBI512_chain_key(ubi512, key_in);
  Skc_UBI512_chain_config(ubi512, (num_out * CHAR_BIT));
  Skc_UBI512_chain_message(ubi512, in, num_in);
  Skc_UBI512_chain_output(ubi512, out, num_out);
}
