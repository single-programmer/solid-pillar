#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>

/////////////////
/// Utilities ///
/////////////////
#define FOR_T(type, i, start, end) for (type i = (start); i < (end); i++)
#define FOR(i, start, end)         FOR_T(size_t, i, start, end)
#define COPY(dst, src, size)       FOR(_i_, 0, size) (dst)[_i_] = (src)[_i_]
#define ZERO(buf, size)            FOR(_i_, 0, size) (buf)[_i_] = 0
#define WIPE_CTX(ctx)              crypto_wipe(ctx   , sizeof(*(ctx)))
#define WIPE_BUFFER(buffer)        crypto_wipe(buffer, sizeof(buffer))
#define MIN(a, b)                  ((a) <= (b) ? (a) : (b))
#define MAX(a, b)                  ((a) >= (b) ? (a) : (b))

typedef int8_t   i8;
typedef uint8_t  u8;
typedef int16_t  i16;
typedef uint32_t u32;
typedef int32_t  i32;
typedef int64_t  i64;
typedef uint64_t u64;


// Incremental interface
typedef struct {
	// Do not rely on the size or contents of this type,
	// for they may change without notice.
	uint8_t  c[16];  // chunk of the message
	size_t   c_idx;  // How many bytes are there in the chunk.
	uint32_t r  [4]; // constant multiplier (from the secret key)
	uint32_t pad[4]; // random number added at the end (from the secret key)
	uint32_t h  [5]; // accumulated hash
} crypto_poly1305_ctx;

// returns the smallest positive integer y such that
// (x + y) % pow_2  == 0
// Basically, it's how many bytes we need to add to "align" x.
// Only works when pow_2 is a power of 2.
// Note: we use ~x+1 instead of -x to avoid compiler warnings
static size_t align(size_t x, size_t pow_2)
{
	return (~x + 1) & (pow_2 - 1);
}

static void store32_le(u8 out[4], u32 in)
{
	out[0] =  in        & 0xff;
	out[1] = (in >>  8) & 0xff;
	out[2] = (in >> 16) & 0xff;
	out[3] = (in >> 24) & 0xff;
}

static u32 load32_le(const u8 s[4])
{
	return
		((u32)s[0] <<  0) |
		((u32)s[1] <<  8) |
		((u32)s[2] << 16) |
		((u32)s[3] << 24);
}

static u64 load64_le(const u8 s[8])
{
	return load32_le(s) | ((u64)load32_le(s+4) << 32);
}

static void store64_le(u8 out[8], u64 in)
{
	store32_le(out    , (u32)in );
	store32_le(out + 4, in >> 32);
}

static void load32_le_buf (u32 *dst, const u8 *src, size_t size) {
	FOR(i, 0, size) { dst[i] = load32_le(src + i*4); }
}
static void load64_le_buf (u64 *dst, const u8 *src, size_t size) {
	FOR(i, 0, size) { dst[i] = load64_le(src + i*8); }
}
static void store32_le_buf(u8 *dst, const u32 *src, size_t size) {
	FOR(i, 0, size) { store32_le(dst + i*4, src[i]); }
}
static void store64_le_buf(u8 *dst, const u64 *src, size_t size) {
	FOR(i, 0, size) { store64_le(dst + i*8, src[i]); }
}

void crypto_wipe(void *secret, size_t size)
{
	volatile u8 *v_secret = (u8*)secret;
	ZERO(v_secret, size);
}

/////////////////
/// Poly 1305 ///
/////////////////

// h = (h + c) * r
// preconditions:
//   ctx->h <= 4_ffffffff_ffffffff_ffffffff_ffffffff
//   ctx->r <=   0ffffffc_0ffffffc_0ffffffc_0fffffff
//   end    <= 1
// Postcondition:
//   ctx->h <= 4_ffffffff_ffffffff_ffffffff_ffffffff
static void poly_block(crypto_poly1305_ctx *ctx, const u8 in[16], unsigned end)
{
    u32 s[4];
	load32_le_buf(s, in, 4);

	//- PROOF Poly1305
	//-
	//- # Inputs & preconditions
	//- ctx->h[0] = u32()
	//- ctx->h[1] = u32()
	//- ctx->h[2] = u32()
	//- ctx->h[3] = u32()
	//- ctx->h[4] = u32(limit = 4)
	//-
	//- ctx->r[0] = u32(limit = 0x0fffffff)
	//- ctx->r[1] = u32(limit = 0x0ffffffc)
	//- ctx->r[2] = u32(limit = 0x0ffffffc)
	//- ctx->r[3] = u32(limit = 0x0ffffffc)
	//-
	//- s[0] = u32()
	//- s[1] = u32()
	//- s[2] = u32()
	//- s[3] = u32()
	//-
	//- end = unsigned(limit = 1)

	// s = h + c, without carry propagation
	const u64 s0 = ctx->h[0] + (u64)s[0]; // s0 <= 1_fffffffe
	const u64 s1 = ctx->h[1] + (u64)s[1]; // s1 <= 1_fffffffe
	const u64 s2 = ctx->h[2] + (u64)s[2]; // s2 <= 1_fffffffe
	const u64 s3 = ctx->h[3] + (u64)s[3]; // s3 <= 1_fffffffe
	const u32 s4 = ctx->h[4] + end;       // s4 <=          5

	// Local all the things!
	const u32 r0 = ctx->r[0];       // r0  <= 0fffffff
	const u32 r1 = ctx->r[1];       // r1  <= 0ffffffc
	const u32 r2 = ctx->r[2];       // r2  <= 0ffffffc
	const u32 r3 = ctx->r[3];       // r3  <= 0ffffffc
	const u32 rr0 = (r0 >> 2) * 5;  // rr0 <= 13fffffb // lose 2 bits...
	const u32 rr1 = (r1 >> 2) + r1; // rr1 <= 13fffffb // rr1 == (r1 >> 2) * 5
	const u32 rr2 = (r2 >> 2) + r2; // rr2 <= 13fffffb // rr1 == (r2 >> 2) * 5
	const u32 rr3 = (r3 >> 2) + r3; // rr3 <= 13fffffb // rr1 == (r3 >> 2) * 5

	// (h + c) * r, without carry propagation
	const u64 x0 = s0*r0+ s1*rr3+ s2*rr2+ s3*rr1+ s4*rr0; // <= 97ffffe007fffff8
	const u64 x1 = s0*r1+ s1*r0 + s2*rr3+ s3*rr2+ s4*rr1; // <= 8fffffe20ffffff6
	const u64 x2 = s0*r2+ s1*r1 + s2*r0 + s3*rr3+ s4*rr2; // <= 87ffffe417fffff4
	const u64 x3 = s0*r3+ s1*r2 + s2*r1 + s3*r0 + s4*rr3; // <= 7fffffe61ffffff2
	const u32 x4 = s4 * (r0 & 3); // ...recover 2 bits    // <=                f

	// partial reduction modulo 2^130 - 5
	const u32 u5 = x4 + (x3 >> 32); // u5 <= 7ffffff5
	const u64 u0 = (u5 >>  2) * 5 + (x0 & 0xffffffff);
	const u64 u1 = (u0 >> 32)     + (x1 & 0xffffffff) + (x0 >> 32);
	const u64 u2 = (u1 >> 32)     + (x2 & 0xffffffff) + (x1 >> 32);
	const u64 u3 = (u2 >> 32)     + (x3 & 0xffffffff) + (x2 >> 32);
	const u64 u4 = (u3 >> 32)     + (u5 & 3);

	// Update the hash
	ctx->h[0] = u0 & 0xffffffff; // u0 <= 1_9ffffff0
	ctx->h[1] = u1 & 0xffffffff; // u1 <= 1_97ffffe0
	ctx->h[2] = u2 & 0xffffffff; // u2 <= 1_8fffffe2
	ctx->h[3] = u3 & 0xffffffff; // u3 <= 1_87ffffe4
	ctx->h[4] = u4 & 0xffffffff; // u4 <=          4

	//- # postconditions
	//- ASSERT(ctx->h[4].limit() <= 4)
	//- CQFD Poly1305
}

void crypto_poly1305_init(crypto_poly1305_ctx *ctx, const u8 key[32])
{
	ZERO(ctx->h, 5); // Initial hash is zero
	ctx->c_idx = 0;
	// load r and pad (r has some of its bits cleared)
	load32_le_buf(ctx->r  , key   , 4);
	load32_le_buf(ctx->pad, key+16, 4);
	FOR (i, 0, 1) { ctx->r[i] &= 0x0fffffff; }
	FOR (i, 1, 4) { ctx->r[i] &= 0x0ffffffc; }
    printf("r = [\n");
    FOR(i, 0, 4) { printf("  %" PRIu32 ",\n", ctx->r[i]); }
    printf("]\n");
    printf("s = [");
    FOR(i, 0, 4) { printf("  %" PRIu32 ",\n", ctx->pad[i]); }
    printf("]\n");
}

void crypto_poly1305_update(crypto_poly1305_ctx *ctx,
                            const u8 *message, size_t message_size)
{
	// Align ourselves with block boundaries
	size_t aligned = MIN(align(ctx->c_idx, 16), message_size);
	FOR (i, 0, aligned) {
		ctx->c[ctx->c_idx] = *message;
		ctx->c_idx++;
		message++;
		message_size--;
	}

	// If block is complete, process it
	if (ctx->c_idx == 16) {
		poly_block(ctx, ctx->c, 1);
		ctx->c_idx = 0;
	}

	// Process the message block by block
	size_t nb_blocks = message_size >> 4;
	FOR (i, 0, nb_blocks) {
		poly_block(ctx, message, 1);
		message += 16;
	}
	message_size &= 15;

	// remaining bytes (we never complete a block here)
	FOR (i, 0, message_size) {
		ctx->c[ctx->c_idx] = message[i];
		ctx->c_idx++;
	}
}

void crypto_poly1305_final(crypto_poly1305_ctx *ctx, u8 mac[16])
{
	// Process the last block (if any)
	// We move the final 1 according to remaining input length
	// (this will add less than 2^130 to the last input block)
	if (ctx->c_idx != 0) {
		ZERO(ctx->c + ctx->c_idx, 16 - ctx->c_idx);
		ctx->c[ctx->c_idx] = 1;
		poly_block(ctx, ctx->c, 0);
    }

    // check if we should subtract 2^130-5 by performing the
	// corresponding carry propagation.
	u64 c = 5;
	FOR (i, 0, 4) {
		c  += ctx->h[i];
		c >>= 32;
	}
    printf("carry = %" PRIu64 "\n", c);
	c += ctx->h[4];
	c  = (c >> 2) * 5; // shift the carry back to the beginning
	// c now indicates how many times we should subtract 2^130-5 (0 or 1)
	FOR (i, 0, 4) {
		c += (u64)ctx->h[i] + ctx->pad[i];
		store32_le(mac + i*4, (u32)c);
		c = c >> 32;
	}
	WIPE_CTX(ctx);
}

void crypto_poly1305(u8     mac[16],  const u8 *message,
                     size_t message_size, const u8  key[32])
{
	crypto_poly1305_ctx ctx;
	crypto_poly1305_init  (&ctx, key);
	crypto_poly1305_update(&ctx, message, message_size);
	crypto_poly1305_final (&ctx, mac);
}

int main (void) {
  u8 mac[16];
  u8 message[34] = "Cryptographic Forum Research Group";
  u8 key[32] = {0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x6, 0xa8, 0x1, 0x3, 0x80, 0x8a, 0xfb, 0xd, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b};
  int i;

  crypto_poly1305(mac, message, 34, key);

  for (i = 0; i < 16; ++i) {
    printf("%02x", mac[i]);
  }
  printf("\n");

  return 0;
}
