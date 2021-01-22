/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_rp.h"
#include "inc_rp.cl"
#include "inc_scalar.cl"
#include "inc_hash_sha256.cl"
#include "inc_ecc_secp256k1.cl"
#endif

#define PUBLIC_KEY_LENGTH_WITH_PARITY 9
#define PRIVATE_KEY_LENGTH 8

typedef struct secp256k1_salt
{
  secp256k1_t coords;
} secp256k1_salt_t;

KERNEL_FQ void m09999_mxx (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * base
   */

  COPY_PW (pws[gid]);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    sha256_ctx_t ctx;

    sha256_init (&ctx);

    sha256_update_swap (&ctx, tmp.i, tmp.pw_len);

    sha256_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m09999_sxx (KERN_ATTR_RULES_ESALT (secp256k1_salt_t))
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[digests_offset].digest_buf[DGST_R0],
    digests_buf[digests_offset].digest_buf[DGST_R1],
    digests_buf[digests_offset].digest_buf[DGST_R2],
    digests_buf[digests_offset].digest_buf[DGST_R3]
  };

  /**
   * base
   */

  COPY_PW (pws[gid]);

  u32 ec_result[PUBLIC_KEY_LENGTH_WITH_PARITY];
  u32 k_local[PRIVATE_KEY_LENGTH];

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    pw_t tmp = PASTE_PW;

    tmp.pw_len = apply_rules (rules_buf[il_pos].cmds, tmp.i, tmp.pw_len);

    sha256_ctx_t ctx;

    sha256_init (&ctx);

    sha256_update_swap (&ctx, tmp.i, tmp.pw_len);

    sha256_final (&ctx);

    // Compute SECP256K1 public key
    k_local[0] = ctx.h[7];
    k_local[1] = ctx.h[6];
    k_local[2] = ctx.h[5];
    k_local[3] = ctx.h[4];
    k_local[4] = ctx.h[3];
    k_local[5] = ctx.h[2];
    k_local[6] = ctx.h[1];
    k_local[7] = ctx.h[0];
    
    point_mul(ec_result, k_local, &esalt_bufs[digests_offset].coords);
    // make sure it's calculated correctly
    // printf ("Private key: %08x%08x%08x%08x%08x%08x%08x%08x\n", ctx.h[0], ctx.h[1], ctx.h[2], ctx.h[3], ctx.h[4], ctx.h[5], ctx.h[6], ctx.h[7]);
    // printf ("Public key: %08x%08x%08x%08x%08x%08x%08x%08x\n\n", ec_result[0], ec_result[1], ec_result[2], ec_result[3], ec_result[4], ec_result[5], ec_result[6], ec_result[7]);
    //

    const u32 r0 = ctx.h[DGST_R0];
    const u32 r1 = ctx.h[DGST_R1];
    const u32 r2 = ctx.h[DGST_R2];
    const u32 r3 = ctx.h[DGST_R3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
