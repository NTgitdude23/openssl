/*
 * Based on selftls.c (Let OpenSSL talk to itself / code CC0 by Hanno Böck).
 *
 * make openssl talk to itself.
 * optionally save the dialog packets to a dir.
 * optionally replace a single message, read from a file.
 * 
 * The file has a synthetic header:
 *     packetNumber - 1byte, which packet number to replace.
 *
 * Expects server-*.pem and *ca-cert.pem files to exist in current directory
 *   with private keys and certs in all server-*.pem files.
 */

#ifdef WIN32
#include "stdafx.h"
#include <windows.h>
#include "wingetopt.h"

#define ssize_t SSIZE_T

#define strdup _strdup
#define mkdir(fn,mode)  (CreateDirectoryA((fn), NULL) ? 0 : -1)
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/conf.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/dh.h>
#include <openssl/engine.h>
#include <openssl/srp.h>

#include "ssl/ssl_locl.h" // we need to peek into SSL to pull out kex info

struct opts {
    unsigned char step;             // 0: packet number to fuzz
    unsigned char clMeth, srvMeth;  // 1,2: proto/method to use
    unsigned char srvCert;          // 3: which cert type to load
    unsigned char ciphers;          // 4: which ciphers to support
    unsigned char curve;            // 5: which ecdh curves to support
    unsigned char reneg;            // 6: server renegotiates

    char _unused[9];                // 7-15: for the future
};

void err() {
    ERR_print_errors_fp(stderr);
    printf("exiting\n");
    exit(1);
}

int wantIO(SSL *s, int r) {
    return ((SSL_get_error(s, r) == SSL_ERROR_WANT_WRITE) ||
            (SSL_get_error(s, r) == SSL_ERROR_WANT_READ));
}

ssize_t xReadFile(char *fn, unsigned char *buf, size_t maxsz)
{
    FILE *fp;
    ssize_t r;

    fp = fopen(fn, "rb");
    if(!fp) {
        perror(fn);
        exit(1);
    }
    r = fread(buf, 1, maxsz, fp);
    fclose(fp);
    return r;
}

void xWritePack(char *dirname, char *pref, int packNum, unsigned char *buf, size_t sz, struct opts *opts)
{
    struct opts svOpts = *opts;
    char fn[256];
    FILE *fp;

    sprintf(fn, "%s/%s_packet_%02d.bin", dirname, pref, packNum); // yah, dont make dirname big
    fp = fopen(fn, "wb");
    if(!fp) {
        perror(fn);
        exit(1);
    }
    svOpts.step = packNum;
    fwrite(&svOpts, 1, sizeof svOpts, fp);
    fwrite(buf, 1, sz, fp);
    fclose(fp);
}

const SSL_METHOD *getMeth(int x)
{
    switch(x) {
    case 1: return SSLv3_method();
    case 2: return TLSv1_method();
    case 3: return TLSv1_1_method();
    case 4: return TLSv1_2_method();
    case 5: return DTLS_method();
    case 6: return DTLSv1_method();
    case 7: return DTLSv1_2_method();
    default: return SSLv23_method(); // pick best
    }
}

void getEngine(char *engine)
{
    ENGINE *e;

    if(!(e = ENGINE_by_id(engine))
    || !ENGINE_set_default(e, ENGINE_METHOD_ALL))
        err();
    printf("loaded %s engine\n", engine);
    ENGINE_free(e);
}

void setCert(SSL_CTX *ctx, int x)
{
    BIO *bio;
    DH *dh;
    char *fn, *cafn;

    cafn = NULL;
    switch(x) {
    case 1: fn = "server-dsa.pem"; break;
    case 2: fn = "server-ecdsa.pem"; break;
    case 3: fn = "server-gost.pem"; break;
    case 4: 
        fn = "/home/tom/openssl/engined/test/ftls/server-rsa_dh.pem"; 
        cafn = "/home/tom/openssl/engined/test/ftls/rsaca-cert.pem";
        break;
    case 5: 
        fn = "server-dsa_dh.pem"; 
        cafn = "dsaca-cert.pem";
        break;
    case 6: 
        fn = "server-rsa_ecdh.pem"; 
        cafn = "rsaca-cert.pem";
        break;
    case 7: 
        fn = "server-ecdsa_ecdh.pem"; 
        cafn = "ecdsaca-cert.pem";
        break;
    case 8: fn = NULL; break;
    default: fn = "server-rsa.pem"; break;
    }

    dh = NULL;
    if(fn) {
        if(cafn)
            if(!SSL_CTX_load_verify_locations(ctx, cafn, NULL)) err();

        if (!SSL_CTX_use_certificate_file(ctx, fn, SSL_FILETYPE_PEM)) err();
        if (!SSL_CTX_use_PrivateKey_file(ctx, fn, SSL_FILETYPE_PEM)) err();
        printf("loaded cert %s\n", fn);

        /* see if we need to load default DH params */
        if ((bio = BIO_new_file(fn, "r")) == NULL) err();
        dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
        BIO_free(bio);
    } else {
        printf("no certificate\n");
    }

    if(dh) {
        printf("using DH params from file\n");
        DH_free(dh);
    } else {
        printf("using default DH params\n");
        SSL_CTX_set_dh_auto(ctx, 1);
    }
}

void setCurve(SSL_CTX *ctx, int opt)
{
    EC_KEY *ecdh;
    char *name;
    int nid;

    name = NULL;
    switch(opt) {
    case 1: /* auto */          break;
    case 2: name = "secp160k1"; break;
    case 3: name = "secp160r1"; break;
    case 4: name = "sect571k1"; break;
    case 5: name = "sect571r1"; break;
    default: break; /* don't set a curve */
    }
    if(name) {
        if((nid = OBJ_sn2nid(name)) == NID_undef) {
            printf("cant load curve %s\n", name);
            err();
        }
        if(!(ecdh = EC_KEY_new_by_curve_name(nid))) err();
        if(!SSL_CTX_set_tmp_ecdh(ctx, ecdh)) err();
        EC_KEY_free(ecdh);
        printf("set tmp ecdh to %s\n", name);
    }
}

void setCipherList(SSL_CTX *c1, SSL_CTX *c2, int opt, int *usePsk, int *useSrp)
{
    char *descr = NULL;

    switch(opt) {
    /* kex types */
    case 1: descr = "kRSA"; break;
    case 2: descr = "kDHr"; break;
    case 3: descr = "kDHd"; break;
    case 4: descr = "kDHE"; break;
    case 5: descr = "kEDH"; break; // XXX duplicate!
    case 6: descr = "kECDHr"; break;
    case 7: descr = "kECDHe"; break;
    case 8: descr = "kECDHE"; break;
    case 9: descr = "kPSK"; break;
    case 10: descr = "kGOST"; break;
    case 11: descr = "kSRP"; break;
    case 12: descr = "kRSAPSK"; break;
    case 13: descr = "kECDHEPSK"; break;
    case 14: descr = "kDHEPSK"; break;
    case 15: descr = "ALL"; break;

    /* ciphers */
    case 32: descr = "DES"; break;
    case 33: descr = "3DES"; break;
    case 34: descr = "RC4"; break;
    case 35: descr = "RC2"; break;
    case 36: descr = "IDEA"; break;
    case 37: descr = "NULL"; break;
    case 38: descr = "AES128"; break;
    case 39: descr = "AES256"; break;
    case 40: descr = "CAMELLIA128"; break;
    case 41: descr = "CAMELLIA256"; break;
    case 42: descr = "eGOST2814789CNT"; break;
    case 43: descr = "SEED"; break;
    case 44: descr = "AES128-GCM-SHA256"; break;
    case 45: descr = "AES256-GCM-SHA384"; break;
    case 46: descr = "AES128-CCM"; break;
    case 47: descr = "AES256-CCM"; break;

    /* auth types not already covered */
    case 64: descr = "aECDSA"; break;
    case 65: descr = "aGOST"; break;
    case 66: descr = "aSRP"; break;

    default:
        break; // accept the defaults
    }
    *usePsk = (descr && (strstr(descr, "PSK") != 0));
    *useSrp = (descr && (strstr(descr, "SRP") != 0));

    if(descr) {
        printf("cipher %s psk %d srp %d\n", descr, *usePsk, *useSrp);
        if(SSL_CTX_set_cipher_list(c1, descr) == 0
        || SSL_CTX_set_cipher_list(c2, descr) == 0)
            err(); 
        printf("selected ciphers %s\n", descr);
    }
}

unsigned int cbClPsk(SSL *s, const char *hint, char *id, unsigned int maxIdLen, unsigned char *psk, unsigned int maxPskLen)
{
    printf("client PSK hint: %s\n", hint);
    if(maxIdLen >= 5 && maxPskLen >= 8) {
        strcpy(id, "myId");
        strcpy((char *)psk, "ABCD123");
        return 8;
    }
    return 0;
}

unsigned int cbSrvPsk(SSL *s, const char *id, unsigned char *psk, unsigned int maxPskLen)
{
    printf("server PSK id: %s\n", id);
    if(maxPskLen >= 8) {
        strcpy((char*)psk, "ABCD123");
        return 8;
    }
    return 0;
}

char *cbClSRPPW(SSL *s, void *arg)
{
    return strdup("user");
}

int cbSrvSRPUser(SSL* s, int *ad, void *arg)
{
    SRP_user_pwd *user;
    SRP_VBASE *vb;
    char *login = SSL_get_srp_username(s);

    printf("setting SRP params for %s\n", login);
    if(!(vb = SRP_VBASE_new(NULL))
    || SRP_VBASE_init(vb, "srppw") != 0)
        err();
    user = SRP_VBASE_get1_by_user(vb, login);
    if(!user)
        return SSL3_AL_FATAL;
    if(SSL_set_srp_server_param(s, user->N, user->g, user->s, user->v, user->info) < 0)
        err();
    SRP_VBASE_free(vb);
    return 0;
}

/* build server and client handles */
void
init(struct opts *opts, SSL **retClient, SSL **retServer, SSL_CTX **retClientCtx, SSL_CTX ** retServerCtx)
{
    SSL_CTX *sctx, *cctx;
    SSL *client, *server;
    int usePSK, useSRP;

    if (!(sctx = SSL_CTX_new(getMeth(opts->srvMeth)))) err();
    if(!(cctx = SSL_CTX_new(getMeth(opts->clMeth)))) err();

    // XXX disable or allow compression.. client and server
    // XXX enable zlib, md2, rc5, sctp, jpake?
    //    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION)

    /* set security level to zero to test the widest range of ciphers */
    SSL_CTX_set_security_level(sctx, 0);
    SSL_CTX_set_security_level(cctx, 0);

    setCipherList(sctx, cctx, opts->ciphers, &usePSK, &useSRP);

    if(useSRP) {
        if(!SSL_CTX_set_srp_username(cctx, "user")
        || !SSL_CTX_set_srp_client_pwd_callback(cctx, cbClSRPPW)
        || !SSL_CTX_set_srp_username_callback(sctx, cbSrvSRPUser))
            err();
    }

    setCurve(sctx, opts->curve);
    setCurve(cctx, opts->curve);

    if(opts->srvCert == 3) /* XXX should we consider loading engine at other times too? */
        getEngine("gost");
    setCert(sctx, opts->srvCert);
    if (!(server = SSL_new(sctx))) err();
    if(!(client = SSL_new(cctx))) err();

    if(usePSK) {
        SSL_use_psk_identity_hint(server, "EnterPW");
        SSL_set_psk_server_callback(server, cbSrvPsk);
        SSL_set_psk_client_callback(client, cbClPsk);
    }

    *retClient = client;
    *retServer = server;
    *retClientCtx = cctx;
    *retServerCtx = sctx;
}


unsigned char buf[4096], fbuf[4096];
char *saveDir;
char *savePref;
unsigned char *fuzzed;
int flen;

/* pump messages through BIOs until no IO is left */
void pump(struct opts *opts, SSL *server, SSL *client, BIO *sinbio, BIO *soutbio, BIO *cinbio, BIO *coutbio, int *cp, int clientFirst)
{
    int r;
    int c = *cp;

    do {
        /* read from client, write to server */
        if(clientFirst) {
            r = SSL_read(client, buf, sizeof buf);
            if (r == -1 && !wantIO(client, r)) err();
            if(r > 0)
                printf("%d: client read %d: %.*s\n", c, r, r, buf);
            else
                printf("%d: client state: %s / %s\n", c, SSL_state_string(client), SSL_state_string_long(client));
    
            r = BIO_read(coutbio, buf, sizeof buf);
            if (r == -1)  // no more data, done
                break;
            c++;
            if(saveDir)
                xWritePack(saveDir, savePref, c, buf, r, opts);
            if (c == opts->step) {
                printf("replacing packet %d\n", c);
                memcpy(buf, fuzzed, flen);
                r = flen;
            }
            BIO_write(sinbio, buf, r);
        }
        clientFirst = 1;

        /* read from server, write to client */
        r = SSL_read(server, buf, sizeof buf);
        if (r == -1 && !wantIO(server, r)) err();
        if(r > 0)
            printf("%d: client read %d: %.*s\n", c, r, r, buf);
        else 
            printf("%d: server state: %s / %s\n", c, SSL_state_string(server), SSL_state_string_long(server));

        r = BIO_read(soutbio, buf, sizeof buf);
        if (r == -1) // no more data, done
            break;
        c++;
        if(saveDir)
            xWritePack(saveDir, savePref, c, buf, r, opts);
        if (c == opts->step) {
            printf("replacing packet %d\n", c);
            memcpy(buf, fuzzed, flen);
            r = flen;
        }
        BIO_write(cinbio, buf, r);
    } while (c < 20);
    *cp = c;
}

static void usage(char *prog)
{
    printf("usage:  %s [-d] [-c clMeth] [-s srvMeth] [-C srvCert]\n"
           "\t\t[-e ecdheCurve] [-k kexAndCipher] [-r reneg]\n"
           "\t\t[-o saveDir] [-p savePrefix] [inFile]\n", prog);
    exit(1);
}

int main(int argc, char **argv) {
    struct opts opts;
    char *inFile;
    SSL *server, *client;
    SSL_CTX *serverCtx, *clientCtx;
    BIO *sinbio, *soutbio, *cinbio, *coutbio;
    struct stat st;
    int c, ch, doData;

#ifdef WIN32
    /* Fuzzer doesn't set working directory */
    SetCurrentDirectory(TEXT("C:\\ftls"));
#endif

    /* parse options */
    memset(&opts, 0, sizeof opts);
    inFile = 0;
    saveDir = 0;
    savePref = "";
    doData = 0;
    while((ch = getopt(argc, argv, "c:C:de:hk:o:p:r:s:")) != -1) {
    switch(ch) {
    case 'c':
        opts.clMeth = atoi(optarg);
        break;
    case 'C':
        opts.srvCert = atoi(optarg);
        break;
    case 'd':
        doData = 1;
        break;
    case 'e' :
        opts.curve = atoi(optarg);
        break;
    case 'k':
        opts.ciphers = atoi(optarg);
        break;
    case 'o':
        saveDir = optarg;
        break;
    case 'p':
        savePref = optarg;
        break;
    case 'r':
        opts.reneg = atoi(optarg);
        break;
    case 's':
        opts.srvMeth = atoi(optarg);
        break;
    case '?':
    case 'h':
        usage(argv[0]);
        break;
    }
    }
    argc -= optind;
    argv += optind;

    if(argc > 0) {
        inFile = argv[0];
        argc --;
        argv ++;
    }
    if(argc != 0)
        usage(argv[0]);

    /* read input file and override options */
    fuzzed = fbuf;
    flen = 0;
    if(inFile) {
        flen = xReadFile(inFile, fbuf, sizeof fbuf);
        if(flen < sizeof opts) {
            printf("insufficient options header\n");
            exit(1);
        }
        memcpy(&opts, fbuf, sizeof opts);
        fuzzed = fbuf + sizeof opts;
        flen -= sizeof opts;
    }

    /* if saving, make the directory */
    if(saveDir && stat(saveDir, &st) == -1) {
        if(mkdir(saveDir, 0755) == -1) {
            perror(saveDir);
            exit(1);
        }
    }

    /* say what we're about to do */
    if(inFile)
        printf("input from %s, replacing %d\n", inFile, opts.step);
    if(saveDir)
        printf("saving to %s/%s\n", saveDir, savePref);
    printf("server method %d\n", opts.srvMeth);
    printf("client method %d\n", opts.clMeth);
    printf("cert type %d\n", opts.srvCert);
    printf("ciphers %d\n", opts.ciphers);

    /* initialize */
    BIO *bio_err = BIO_new_fp(stderr,
			BIO_NOCLOSE | BIO_FP_TEXT);
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_load_builtin_modules();
    ENGINE_load_builtin_engines();

    /* Add the ossltest engine */
    ENGINE *e = ENGINE_by_id("dynamic");
    if(e == NULL) {
      printf("Could not load dynamic engine\n");
      ERR_print_errors(bio_err);
      return -1;
    } else {
      if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", "../../engines/ossltest.so", 0)) {
	printf("Could not set .so path\n");
	ERR_print_errors(bio_err);
	ENGINE_free(e);
	BIO_free(bio_err);
	return -2;
      }
      if(!ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)) {
	printf("Could not load ossltest library\n");
	ERR_print_errors(bio_err);
	ENGINE_free(e);
	BIO_free(bio_err);
	return -3;
      }
      ENGINE_ctrl(e, ENGINE_CTRL_SET_LOGSTREAM, 0, bio_err, 0);
      if (!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
	printf("Could not set ossltest as default engine\n");
	ERR_print_errors(bio_err);
	ENGINE_free(e);
	BIO_free(bio_err);
	return -4;
      }
    }
    ENGINE_free(e);//Is this correct? It causes ASAN to report MORE memleaks than not having it.
    printf("loaded ossltest engine\n");
    
    init(&opts, &client, &server, &clientCtx, &serverCtx);

    sinbio = BIO_new(BIO_s_mem());
    soutbio = BIO_new(BIO_s_mem());
    SSL_set_bio(server, sinbio, soutbio);
    SSL_set_accept_state(server);

    cinbio = BIO_new(BIO_s_mem());
    coutbio = BIO_new(BIO_s_mem());
    SSL_set_bio(client, cinbio, coutbio);
    SSL_set_connect_state(client);

    /* perform handshake on both sides and quit */
    c = 0;
    pump(&opts, server, client, sinbio, soutbio, cinbio, coutbio, &c, 1);

    if(doData) {
        /* now send a little data */
        SSL_write(server, "abcd", 4);
        SSL_write(client, "XYZ!", 4);
        pump(&opts, server, client, sinbio, soutbio, cinbio, coutbio, &c, 1);

        /* try another kex */
        printf("reneg %d\n", opts.reneg);
        if(opts.reneg) {
            SSL_renegotiate(server);
            /* I don't like that this reverses the normal order of files/packets */
            pump(&opts, server, client, sinbio, soutbio, cinbio, coutbio, &c, 0);
        } else {
            SSL_renegotiate(client);
            pump(&opts, server, client, sinbio, soutbio, cinbio, coutbio, &c, 1);
        }
    }

    /* show the options we exercised */
    printf("keyex %x/%x, ", client->s3->tmp.new_cipher->algorithm_mkey, server->s3->tmp.new_cipher->algorithm_mkey);
    printf("auth %x/%x, ", client->s3->tmp.new_cipher->algorithm_auth, server->s3->tmp.new_cipher->algorithm_auth);
    printf("enc %x/%x, ", client->s3->tmp.new_cipher->algorithm_enc, server->s3->tmp.new_cipher->algorithm_enc);
    printf("mac %x/%x, ", client->s3->tmp.new_cipher->algorithm_mac, server->s3->tmp.new_cipher->algorithm_mac);
    printf("tls %x/%x - %x/%x, ", client->s3->tmp.new_cipher->min_tls, server->s3->tmp.new_cipher->min_tls, client->s3->tmp.new_cipher->max_tls, server->s3->tmp.new_cipher->max_tls);
    printf("dtls %x/%x - %x/%x\n", client->s3->tmp.new_cipher->min_dtls, server->s3->tmp.new_cipher->min_dtls, client->s3->tmp.new_cipher->max_dtls, server->s3->tmp.new_cipher->max_dtls);

    SSL_CTX_free(clientCtx);
    SSL_CTX_free(serverCtx);
    SSL_free(client);
    SSL_free(server);

    BIO_free(bio_err);
    
    return 0;
}
