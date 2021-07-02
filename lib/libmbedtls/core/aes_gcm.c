// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2014-2019, Linaro Limited
 */

#include <assert.h>
#include <crypto/crypto.h>
#include <crypto/crypto_impl.h>
#include <mbedtls/gcm.h>
#include <stdlib.h>
#include <string.h>
#include <string_ext.h>
#include <tee_api_types.h>
#include <util.h>

#include "mbed_helpers.h"

#define TEE_GCM_TAG_MAX_LENGTH		16

struct mbed_aes_gcm_ctx {
	struct crypto_authenc_ctx aectx;
	mbedtls_gcm_context gcm_ctx;
	size_t tag_len;
	size_t aad_len;
	size_t iv_len;
	unsigned char *aad;
	unsigned char *iv;
	bool valid;
	bool started;
};

static const struct crypto_authenc_ops aes_gcm_ops;

static struct mbed_aes_gcm_ctx *
to_mbed_aes_gcm_ctx(struct crypto_authenc_ctx *aectx)
{
	assert(aectx && aectx->ops == &aes_gcm_ops);

	return container_of(aectx, struct mbed_aes_gcm_ctx, aectx);
}

static void mbed_aes_gcm_free_ctx(struct crypto_authenc_ctx *aectx)
{
	struct mbed_aes_gcm_ctx *gcm = to_mbed_aes_gcm_ctx(aectx);

	mbedtls_gcm_free(&gcm->gcm_ctx);
	free(gcm->aad);
	free(gcm->iv);
	free(gcm);
}

static void mbed_aes_gcm_copy_state(struct crypto_authenc_ctx *dctx,
				    struct crypto_authenc_ctx *sctx __unused)
{
	struct mbed_aes_gcm_ctx *dst = to_mbed_aes_gcm_ctx(dctx);

	/* Not supported by MBed TLS */
	dst->valid = false;
}

static TEE_Result mbed_aes_gcm_init(struct crypto_authenc_ctx *aectx,
				    TEE_OperationMode mode __unused,
				    const uint8_t *key, size_t key_len,
				    const uint8_t *nonce, size_t nonce_len,
				    size_t tag_len, size_t aad_len __unused,
				    size_t payload_len __unused)
{
	struct mbed_aes_gcm_ctx *gcm = to_mbed_aes_gcm_ctx(aectx);
	TEE_Result res = TEE_SUCCESS;
	int mbed_res = 0;

	mbedtls_gcm_init(&gcm->gcm_ctx);
	mbed_res = mbedtls_gcm_setkey(&gcm->gcm_ctx, MBEDTLS_CIPHER_ID_AES, key,
				      key_len * 8);
	if (mbed_res) {
		res = TEE_ERROR_BAD_STATE;
		goto err;
	}
	gcm->iv = malloc(nonce_len);
	if (!gcm->iv) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	memcpy(gcm->iv, nonce, nonce_len);
	gcm->iv_len = nonce_len;
	gcm->tag_len = tag_len;

	return TEE_SUCCESS;
err:
	mbedtls_gcm_free(&gcm->gcm_ctx);
	free(gcm->iv);
	return res;
}

static TEE_Result mbed_aes_gcm_update_aad(struct crypto_authenc_ctx *aectx,
					  const uint8_t *data, size_t len)
{
	struct mbed_aes_gcm_ctx *gcm = to_mbed_aes_gcm_ctx(aectx);
	void *ptr = NULL;

	ptr = realloc(gcm->aad, gcm->aad_len + len);
	if (!ptr)
		return TEE_ERROR_OUT_OF_MEMORY;
	gcm->aad = ptr;
	memcpy(gcm->aad + gcm->aad_len, data, len);
	gcm->aad_len += len;

	return TEE_SUCCESS;
}

static TEE_Result
mbed_aes_gcm_update_payload(struct crypto_authenc_ctx *aectx,
			    TEE_OperationMode mode, const uint8_t *src_data,
			    size_t len, uint8_t *dst_data)
{
	struct mbed_aes_gcm_ctx *gcm = to_mbed_aes_gcm_ctx(aectx);
	int mbed_mode = 0;
	int mbed_res = 0;

	if (!gcm->valid)
		return TEE_ERROR_BAD_STATE;

	if (!gcm->started) {
		if (mode == TEE_MODE_ENCRYPT)
			mbed_mode = MBEDTLS_GCM_ENCRYPT;
		else
			mbed_mode = MBEDTLS_GCM_DECRYPT;
		mbed_res = mbedtls_gcm_starts(&gcm->gcm_ctx, mbed_mode, gcm->iv,
					      gcm->iv_len, gcm->aad,
					      gcm->aad_len);
		if (mbed_res)
			return TEE_ERROR_BAD_STATE;
		gcm->started = true;
	}

	mbed_res = mbedtls_gcm_update(&gcm->gcm_ctx, len, src_data, dst_data);
	if (mbed_res)
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

static TEE_Result mbed_aes_gcm_enc_final(struct crypto_authenc_ctx *aectx,
					 const uint8_t *src_data, size_t len,
					 uint8_t *dst_data, uint8_t *dst_tag,
					 size_t *dst_tag_len)
{
	struct mbed_aes_gcm_ctx *gcm = to_mbed_aes_gcm_ctx(aectx);
	TEE_Result res = TEE_SUCCESS;
	int mbed_res = 0;

	if (!gcm->valid)
		return TEE_ERROR_BAD_STATE;

	/* Finalize the remaining buffer */
	res = mbed_aes_gcm_update_payload(aectx, TEE_MODE_ENCRYPT, src_data,
					len, dst_data);
	if (res != TEE_SUCCESS)
		return res;

	/* Check the tag length */
	if (*dst_tag_len < gcm->tag_len) {
		*dst_tag_len = gcm->tag_len;
		return TEE_ERROR_SHORT_BUFFER;
	}
	*dst_tag_len = gcm->tag_len;

	/* Compute the tag */
	mbed_res = mbedtls_gcm_finish(&gcm->gcm_ctx, dst_tag, *dst_tag_len);
	if (mbed_res)
		return TEE_ERROR_BAD_STATE;

	return TEE_SUCCESS;
}

static TEE_Result mbed_aes_gcm_dec_final(struct crypto_authenc_ctx *aectx,
					 const uint8_t *src_data, size_t len,
					 uint8_t *dst_data,
					 const uint8_t *tag, size_t tag_len)
{
	struct mbed_aes_gcm_ctx *gcm = to_mbed_aes_gcm_ctx(aectx);
	uint8_t dst_tag[TEE_GCM_TAG_MAX_LENGTH] = { 0 };
	TEE_Result res = TEE_ERROR_BAD_STATE;
	int mbed_res = 0;

	if (!gcm->valid)
		return TEE_ERROR_BAD_STATE;

	if (tag_len == 0)
		return TEE_ERROR_SHORT_BUFFER;
	if (tag_len > TEE_GCM_TAG_MAX_LENGTH)
		return TEE_ERROR_BAD_STATE;

	/* Process the last buffer, if any */
	res = mbed_aes_gcm_update_payload(aectx, TEE_MODE_DECRYPT, src_data,
					  len, dst_data);
	if (res)
		return res;

	/* Finalize the authentication */
	mbed_res = mbedtls_gcm_finish(&gcm->gcm_ctx, dst_tag, tag_len);
	if (mbed_res)
		return TEE_ERROR_BAD_STATE;

	if (consttime_memcmp(dst_tag, tag, tag_len) != 0)
		res = TEE_ERROR_MAC_INVALID;
	else
		res = TEE_SUCCESS;
	return res;
}

static void mbed_aes_gcm_final(struct crypto_authenc_ctx *aectx __unused)
{
}

static const struct crypto_authenc_ops aes_gcm_ops = {
	.init = mbed_aes_gcm_init,
	.update_aad = mbed_aes_gcm_update_aad,
	.update_payload = mbed_aes_gcm_update_payload,
	.enc_final = mbed_aes_gcm_enc_final,
	.dec_final = mbed_aes_gcm_dec_final,
	.final = mbed_aes_gcm_final,
	.free_ctx = mbed_aes_gcm_free_ctx,
	.copy_state = mbed_aes_gcm_copy_state,
};

TEE_Result crypto_aes_gcm_alloc_ctx(struct crypto_authenc_ctx **ctx_ret)
{
	struct mbed_aes_gcm_ctx *ctx = calloc(1, sizeof(*ctx));

	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;
	mbedtls_gcm_init(&ctx->gcm_ctx);
	ctx->aectx.ops = &aes_gcm_ops;
	ctx->valid = true;
	*ctx_ret = &ctx->aectx;

	return TEE_SUCCESS;
}

