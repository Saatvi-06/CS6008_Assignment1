#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

using namespace std;

// RFC 3526 Group 14 (2048-bit MODP)
const char* P_HEX = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
                    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
                    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
                    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
                    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
                    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
                    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
                    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
                    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
                    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
                    "15728E5A8AACAA68FFFFFFFFFFFFFFFF";
const char* G_HEX = "02";

string sha256_hash(const string& input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input.c_str(), input.length());
    SHA256_Final(hash, &sha256);
    stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

class DHKeyExchange {
private:
    BIGNUM *p, *g, *priv_key, *pub_key;
    BN_CTX *ctx;
public:
    DHKeyExchange() {
        ctx = BN_CTX_new();
        p = BN_new();
        g = BN_new();
        priv_key = BN_new();
        pub_key = BN_new();

        BN_hex2bn(&p, P_HEX);
        BN_hex2bn(&g, G_HEX);

        // Generate 256-bit random private key
        BN_rand(priv_key, 256, -1, 0);

        // pub_key = g^priv_key mod p
        BN_mod_exp(pub_key, g, priv_key, p, ctx);
    }

    ~DHKeyExchange() {
        BN_free(p); BN_free(g); BN_free(priv_key); BN_free(pub_key);
        BN_CTX_free(ctx);
    }

    string get_public_key_hex() {
        char *hex = BN_bn2hex(pub_key);
        string ret(hex);
        OPENSSL_free(hex);
        return ret;
    }

    string compute_shared_secret(const string& peer_pub_hex) {
        BIGNUM *peer_pub = BN_new();
        BN_hex2bn(&peer_pub, peer_pub_hex.c_str());

        BIGNUM *shared_secret = BN_new();
        // shared_secret = peer_pub^priv_key mod p
        BN_mod_exp(shared_secret, peer_pub, priv_key, p, ctx);

        char *hex = BN_bn2hex(shared_secret);
        string secret_hex(hex);

        BN_free(peer_pub);
        BN_free(shared_secret);
        OPENSSL_free(hex);
        
        // Return 256-bit hash of the raw shared secret to be used as AES key
        return sha256_hash(secret_hex);
    }
};

string encrypt_aes_gcm(const string& plaintext, const string& hex_key) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key[32];
    for(int i = 0; i < 32; i++) {
        sscanf(hex_key.substr(i*2, 2).c_str(), "%2hhx", &key[i]);
    }
    
    unsigned char iv[12];
    RAND_bytes(iv, sizeof(iv));

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);

    unsigned char outbuf[4096];
    int outlen;
    EVP_EncryptUpdate(ctx, outbuf, &outlen, (const unsigned char*)plaintext.c_str(), plaintext.length());
    
    int finallen;
    EVP_EncryptFinal_ex(ctx, outbuf + outlen, &finallen);
    
    unsigned char tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);

    string result;
    for(int i = 0; i < 12; i++) {
        char hex[3]; sprintf(hex, "%02x", iv[i]); result += hex;
    }
    for(int i = 0; i < 16; i++) {
        char hex[3]; sprintf(hex, "%02x", tag[i]); result += hex;
    }
    for(int i = 0; i < outlen + finallen; i++) {
        char hex[3]; sprintf(hex, "%02x", outbuf[i]); result += hex;
    }
    return result; // IV (24 hex) + TAG (32 hex) + CIPHERTEXT
}

string decrypt_aes_gcm(const string& ciphertext_hex, const string& hex_key) {
    if(ciphertext_hex.length() < 56) return ""; // Minimum length for IV + Tag

    unsigned char key[32];
    for(int i = 0; i < 32; i++) {
        sscanf(hex_key.substr(i*2, 2).c_str(), "%2hhx", &key[i]);
    }
    
    unsigned char iv[12];
    for(int i = 0; i < 12; i++) {
        sscanf(ciphertext_hex.substr(i*2, 2).c_str(), "%2hhx", &iv[i]);
    }
    
    unsigned char tag[16];
    for(int i = 0; i < 16; i++) {
        sscanf(ciphertext_hex.substr(24 + i*2, 2).c_str(), "%2hhx", &tag[i]);
    }

    string actual_cipher_hex = ciphertext_hex.substr(56);
    int cipher_len = actual_cipher_hex.length() / 2;
    vector<unsigned char> cipher(cipher_len);
    for(int i = 0; i < cipher_len; i++) {
        sscanf(actual_cipher_hex.substr(i*2, 2).c_str(), "%2hhx", &cipher[i]);
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv);
    
    unsigned char outbuf[4096];
    int outlen;
    EVP_DecryptUpdate(ctx, outbuf, &outlen, cipher.data(), cipher_len);
    
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag);
    
    int ret = EVP_DecryptFinal_ex(ctx, outbuf + outlen, &outlen);
    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        return string((char*)outbuf, cipher_len);
    }
    return ""; // Decryption or Authentication failed
}

#endif

