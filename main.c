#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

#define DEBUG

#ifdef DEBUG
#       define _DEBUG_MSG(e,...) fprintf(stderr, "[%s:%d] " e "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#       define _DEBUG_MSG(e,...) do {} while(0);
#endif

#define _ERROR_MSG(e,...) fprintf(stderr, "[%s:%d] " e "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define MAX_STRING 4096

//#define PRIVATE_KEY "private.pem"
#define PRIVATE_KEY "pkcs1.pem"
#define PUBLIC_KEY "public.pem"
//#define STRING "encr.txt"
#define STRING "15c8133a-6e36-4bb1-927f-fbb3c726f0b50000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

static const char *codes =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static const unsigned char map[256] = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255,  62, 255, 255, 255,  63,
    52,  53,  54,  55,  56,  57,  58,  59,  60,  61, 255, 255,
    255, 254, 255, 255, 255,   0,   1,   2,   3,   4,   5,   6,
    7,   8,   9,  10,  11,  12,  13,  14,  15,  16,  17,  18,
    19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255, 255,
    255,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,
    37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
    49,  50,  51, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255 };


int base64_decode(const unsigned char *in,  unsigned long inlen,
        unsigned char *out, unsigned long *outlen)
{
    unsigned long t, x, y, z;
    unsigned char c;
    int           g;

    g = 3;
   
    for (x = y = z = t = 0; x < inlen; x++) {
        c = map[in[x]&0xFF];
        if (c == 255) continue;
        if (c == 254) { c = 0; g--; }
        t = (t<<6)|c;
        if (++y == 4) {
            if (z + g > *outlen) {
                return 0;
            }
            out[z++] = (unsigned char)((t>>16)&255);
            if (g > 1) out[z++] = (unsigned char)((t>>8)&255);
            if (g > 2) out[z++] = (unsigned char)(t&255);
            y = t = 0;
        }
    }
    if (y != 0) {
        return 0;
    }
    *outlen = z;
    return 1;
}

int base64_encode(const unsigned char *in,  unsigned long inlen,
        unsigned char *out, unsigned long *outlen)
{
    unsigned long i, len2, leven;
    unsigned char *p;

    /* valid output size ? */
    len2 = 4 * ((inlen + 2) / 3);
    if (*outlen < len2 + 1) {
        return 0;
    }
    p = out;
    leven = 3*(inlen / 3);
    for (i = 0; i < leven; i += 3) {
        *p++ = codes[(in[0] >> 2) & 0x3F];
        *p++ = codes[(((in[0] & 3) << 4) + (in[1] >> 4)) & 0x3F];
        *p++ = codes[(((in[1] & 0xf) << 2) + (in[2] >> 6)) & 0x3F];
        *p++ = codes[in[2] & 0x3F];
        in += 3;
    }
    /* Pad it if necessary...  */
    if (i < inlen) {
        unsigned a = in[0];
        unsigned b = (i+1 < inlen) ? in[1] : 0;

        *p++ = codes[(a >> 2) & 0x3F];
        *p++ = codes[(((a & 3) << 4) + (b >> 4)) & 0x3F];
        *p++ = (i+1 < inlen) ? codes[(((b & 0xf) << 2)) & 0x3F] : '=';
        *p++ = '=';
    }

    /* append a NULL byte */
    *p = '\0';

    /* return ok */
    *outlen = p - out;
    return 1;
}

EVP_PKEY *generatePriEVPKEY() {
    char private_key[4096] = {0};
    int ret, flen, bio_len;
    BIO *bio = NULL;
    RSA *r = NULL;

    if ((bio = BIO_new_file(PRIVATE_KEY, "r")) == NULL){
        _ERROR_MSG("Get private key file fail.");
	ERR_print_errors_fp(stdout);
	return NULL;
    }

    if(!PEM_read_bio_RSAPrivateKey(bio, &r, NULL, NULL)){
        _ERROR_MSG("PEM_read_bio_RSAPrivateKey fail.");
	ERR_print_errors_fp(stdout);
	return NULL;
    }

    flen = RSA_size(r);

    EVP_PKEY *evp_key = EVP_PKEY_new();
    if (evp_key == NULL) {
        _ERROR_MSG("New EVP_PKEY fail.");
        RSA_free(r);
        return NULL;
    }

    if (EVP_PKEY_set1_RSA(evp_key, r) != 1){
	_ERROR_MSG("EVP_PKEY setting fail.");
	ERR_print_errors_fp(stdout);
        RSA_free(r);
        EVP_PKEY_free(evp_key);
        return NULL;
    }

    RSA_free(r);
    return evp_key;
}

EVP_PKEY *generatePubEVPKEY(char * keyChar) {
    int ret, flen, bio_len;
    BIO *bio = NULL;
    RSA *r = NULL;

    if ((bio = BIO_new_mem_buf((void *)keyChar, strlen(keyChar))) == NULL){
        _ERROR_MSG("Get memory buffer fail.");
	ERR_print_errors_fp(stdout);
    }
    PEM_read_bio_RSA_PUBKEY(bio, &r, 0, 0);

    flen = RSA_size(r);
    EVP_PKEY *evp_key = EVP_PKEY_new();
    if (evp_key == NULL) {
        _ERROR_MSG("New EVP_PKEY fail.");
        RSA_free(r);
        return NULL;
    }
    if (EVP_PKEY_set1_RSA(evp_key, r) != 1){
	_ERROR_MSG("EVP_PKEY setting fail.");
        RSA_free(r);
        EVP_PKEY_free(evp_key);
        return NULL;
    }

    RSA_free(r);
    return evp_key;
}

unsigned int _crc16_update(unsigned int crc, int len){
    int i;

    crc ^= len;
    for(i = 0; i < 8;i++){
	if(crc & 1)
	    crc = (crc >> 1) ^ 0xA001;
	else 
	    crc = (crc >> 1);
    }
    return crc;
}

unsigned int ctc16Modbus(char str[], int len){
   unsigned int crc = 0xFFFF;
   int x = 0;
   for(x = 0; x < len; x++){
       crc = _crc16_update(crc, str[x]);
   }
   return crc;
}

void decode_oaep_rsa_sha256(char * str, int str_len){
    int len, res ;
    unsigned char *encode_str;
    FILE *pFile; 
    RSA *rsa = RSA_new(); 
    unsigned char *out;

    encode_str = malloc(sizeof(unsigned char) * 4096);
    memset(encode_str, 0, sizeof(unsigned char) * 4096);

    out = malloc(sizeof(unsigned char) * 4096);
    memset(out, 0, sizeof(unsigned char) * 4096);

    pFile = fopen("public.pem", "rb"); 
    if(pFile == NULL) {
        printf("%s(%d) Open file fail\n", __func__, __LINE__);
	exit(0);
    }

    printf("%s(%d)\n", __func__, __LINE__);

    rsa = PEM_read_RSA_PUBKEY(pFile, &rsa, NULL, NULL);
    if (rsa == NULL){
	printf("%s(%d)Public Key not valid \n", __func__, __LINE__);
	ERR_print_errors_fp(stdout);
	exit(0);
    }

    printf("%s(%d) str(%d) %s\n", __func__, __LINE__, str_len, str);

    base64_decode(str , str_len, encode_str, (unsigned long *)&len);
    
    printf("%s(%d) base64_decode(%d): %s\n", __func__, __LINE__, len, encode_str);

    for(int x = 0;x < len;x++){
	printf("0x%02x ", encode_str[x]);
    }
    printf("\n");
/*
    res = RSA_public_decrypt(len, encode_str, out, rsa, RSA_PKCS1_PADDING);
    if(res < 0){
	printf("%s(%d)RSA_public_decrypt not valid \n", __func__, __LINE__);
	ERR_print_errors_fp(stdout);
	exit(0);
    }

    printf("%s(%d)[%zd] %s \n", __func__, __LINE__, strlen(out), out);
*/
}

int encode_oaep_rsa_sha256(EVP_PKEY *rkey, char *str, unsigned char *result, int *res_len){
    int len = MAX_STRING;
    EVP_PKEY_CTX *pctx;
    int flags = CMS_BINARY | CMS_PARTIAL | CMS_KEY_PARAM;
    unsigned char *out;
   
    if(rkey == NULL || str == NULL || strlen(str) <= 0){
    	_ERROR_MSG("Input is invaild.");    
	return 0;
    }

    if(result == NULL || res_len == NULL){
    	_ERROR_MSG("Output is invaild.");    
	return 0;
    }

    out = malloc(sizeof(unsigned char) * MAX_STRING);
    if(out == NULL){
	_ERROR_MSG("Create output buffer fail.");
	return 0;
    }

    memset(out, 0, sizeof(unsigned char) * 4096);
    
    _DEBUG_MSG("String[%zd] : %s", strlen(str), str);    

    pctx = EVP_PKEY_CTX_new(rkey, NULL);
    if(pctx == NULL){
    	_ERROR_MSG("EVP_PKEY_CTX_new fail.");    
	ERR_print_errors_fp(stdout);
	return 0;
    }

    if (EVP_PKEY_encrypt_init(pctx) <= 0) {
    	_ERROR_MSG("EVP_PKEY_encrypt_init fail.");    
	ERR_print_errors_fp(stdout);
	return 0;
    }

    EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_OAEP_PADDING);
    EVP_PKEY_CTX_set_rsa_oaep_md(pctx, EVP_sha256());
    EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256());

    if (EVP_PKEY_encrypt(pctx, out, (size_t *)&len, str, strlen(str)) <= 0){
    	_ERROR_MSG("EVP_PKEY_encrypt fail.");    
	ERR_print_errors_fp(stdout);
	return 0;
    }

    if(len <= 0){
    	_ERROR_MSG("Encrypted string length is 0.");    
	return 0;
    }

#ifdef DEBUG
    _DEBUG_MSG("Encode len [%d]", len);
    for(int x = 0;x < len;x++){
	printf("0x%02x ", out[x]);
    }
    printf("\n");
#endif

    base64_encode(out ,len, result, (unsigned long *)res_len);

    if(res_len <= 0){
    	_ERROR_MSG("Base64 encode fail.");    
	return 0;
    }

    free(out);
    return 1;
}

void main(void){
    int len;
    EVP_PKEY *rkey;
    unsigned char result[4096] = {0};

    OpenSSL_add_all_ciphers(); 
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    if((rkey = generatePriEVPKEY()) == NULL){
	_ERROR_MSG("generatePriEVPKEY fail.");
        return;
    }

    if(!encode_oaep_rsa_sha256(rkey , STRING, (unsigned char *)&result, (int *)&len)){
	_ERROR_MSG("Encode fail.");
	return;
    }
    _DEBUG_MSG("Base64 encoded String[%d] : %s", len, result);

    //decode_oaep_rsa_sha256((unsigned char *)&result, len);

  
}

