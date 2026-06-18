/*
 * test_cve_patches.c
 *
 * Verifies that the CVE-2019-16224..16228 patches reject crafted/corrupt
 * data.mdb files instead of crashing.  Each test creates a valid database,
 * corrupts specific bytes to reproduce the attack vector, then asserts that
 * the patched library returns a clean error code rather than segfaulting.
 *
 * Ported from ArcticDB cpp/arcticdb/storage/test/test_lmdb_cve.cpp.
 *
 * Internal mdb.c layout constants used for corruption:
 *
 *   Meta page (page 0 and 1), MDB_meta starts at offset +16:
 *     +40..+43  mm_dbs[FREE_DBI].md_pad  = mm_psize  (uint32)
 *     +44..+45  mm_dbs[FREE_DBI].md_flags             (uint16)
 *     +92..+93  mm_dbs[MAIN_DBI].md_flags             (uint16)
 *
 *   Any page:
 *     +10..+11  mp_flags  (uint16)
 *     +16..+17  mp_ptrs[0] — byte offset of first node within page (uint16)
 *
 *   MDB_node (at page_base + mp_ptrs[i]):
 *     +0..+1  mn_lo    low 16 bits of data size
 *     +2..+3  mn_hi    high 16 bits                  (CVE-2019-16226)
 *     +4..+5  mn_flags (F_DUPDATA=0x04)              (CVE-2019-16227)
 *     +6..+7  mn_ksize
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <lmdb.h>

/* ---- page layout constants (from mdb.c internals) ---- */
#define PSIZE_OFFSET      40
#define FREE_FLAGS_OFFSET 44
#define MAIN_FLAGS_OFFSET 92
#define MP_FLAGS_OFFSET   10
#define MP_PTRS0_OFFSET   16
#define P_LEAF       0x02u
#define P_DIRTY      0x10u
#define F_DUPDATA    0x04u

/* ---- simple test harness ---- */
static int n_pass = 0, n_fail = 0;

#define EXPECT(cond, msg) \
    do { if (cond) { n_pass++; printf("PASS: %s\n", (msg)); } \
         else { n_fail++; fprintf(stderr, "FAIL: %s\n", (msg)); } } while (0)

#define ABORT_IF(cond, msg) \
    do { if (cond) { fprintf(stderr, "ABORT: %s\n", (msg)); exit(1); } } while (0)

/* ---- binary I/O helpers ---- */

static void patch_u16(const char *path, long off, uint16_t v)
{
    FILE *f = fopen(path, "r+b");
    ABORT_IF(!f, "fopen patch_u16");
    fseek(f, off, SEEK_SET);
    fwrite(&v, 2, 1, f);
    fclose(f);
}

static void patch_u32(const char *path, long off, uint32_t v)
{
    FILE *f = fopen(path, "r+b");
    ABORT_IF(!f, "fopen patch_u32");
    fseek(f, off, SEEK_SET);
    fwrite(&v, 4, 1, f);
    fclose(f);
}

static uint32_t read_u32(const char *path, long off)
{
    uint32_t v = 0;
    FILE *f = fopen(path, "rb");
    ABORT_IF(!f, "fopen read_u32");
    fseek(f, off, SEEK_SET);
    fread(&v, 4, 1, f);
    fclose(f);
    return v;
}

/* Slurp entire file; caller must free() the returned buffer. */
static uint8_t *slurp(const char *path, long *out_size)
{
    FILE *f = fopen(path, "rb");
    ABORT_IF(!f, "fopen slurp");
    fseek(f, 0, SEEK_END);
    *out_size = ftell(f);
    uint8_t *buf = malloc(*out_size);
    ABORT_IF(!buf, "malloc slurp");
    fseek(f, 0, SEEK_SET);
    fread(buf, 1, *out_size, f);
    fclose(f);
    return buf;
}

static void spew(const char *path, const uint8_t *buf, long size)
{
    FILE *f = fopen(path, "wb");
    ABORT_IF(!f, "fopen spew");
    fwrite(buf, 1, size, f);
    fclose(f);
}

/* ---- database helpers ---- */

/* Create a valid DB with n_keys short entries; returns page size or 0. */
static uint32_t create_db(const char *dir, int n_keys)
{
    MDB_env *env = NULL;
    MDB_txn *txn = NULL;
    MDB_dbi  dbi;
    char db_path[512];
    snprintf(db_path, sizeof(db_path), "%s/data.mdb", dir);

    if (mdb_env_create(&env) != MDB_SUCCESS) return 0;
    mdb_env_set_mapsize(env, 4ULL << 20);
    if (mdb_env_open(env, dir, 0, 0644) != MDB_SUCCESS)
        { mdb_env_close(env); return 0; }
    mdb_txn_begin(env, NULL, 0, &txn);
    mdb_dbi_open(txn, NULL, MDB_CREATE, &dbi);
    for (int i = 0; i < n_keys; i++) {
        char key[16]; snprintf(key, sizeof(key), "key%d", i);
        char val[] = "xxx";
        MDB_val k = {strlen(key), key}, v = {3, val};
        mdb_put(txn, dbi, &k, &v, 0);
    }
    mdb_txn_commit(txn);
    mdb_env_close(env);
    return read_u32(db_path, PSIZE_OFFSET);
}

/* Return file offset of the first clean leaf page, or -1. */
static long first_leaf_offset(const char *path, uint32_t psize)
{
    long fsize;
    uint8_t *data = slurp(path, &fsize);
    long result = -1;
    for (long off = 2 * (long)psize; off + (long)psize <= fsize; off += psize) {
        uint16_t flags = 0;
        memcpy(&flags, data + off + MP_FLAGS_OFFSET, 2);
        if ((flags & P_LEAF) && !(flags & P_DIRTY)) { result = off; break; }
    }
    free(data);
    return result;
}

/* Create a temp directory under /tmp; buf must be >= 64 bytes. */
static void make_tmpdir(char *buf, size_t len, const char *tag)
{
    snprintf(buf, len, "/tmp/lmdb_cve_%s_XXXXXX", tag);
    ABORT_IF(!mkdtemp(buf), "mkdtemp");
}

static void rm_tmpdir(const char *dir)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    (void)system(cmd);
}

/* ---- CVE-2019-16224 -------------------------------------------------------
 * Heap buffer overflow via invalid md_flags combination.
 * Setting MDB_DUPFIXED (or MDB_INTEGERDUP) without MDB_DUPSORT on FREE_DBI
 * or MAIN_DBI causes mdb_node_add to use md_pad (page size) as a memcpy
 * length, producing a heap overflow on commit.
 * Patch: BAD_DB_FLAGS() check in mdb_txn_renew0 — mdb_txn_begin returns
 * MDB_INVALID before any writes can happen.
 * ----------------------------------------------------------------------- */

static void test_cve_16224_free_dbi(void)
{
    char dir[64], db[128];
    make_tmpdir(dir, sizeof(dir), "16224a");
    snprintf(db, sizeof(db), "%s/data.mdb", dir);

    uint32_t psize = create_db(dir, 50);
    ABORT_IF(!psize, "create_db 16224a");

    /* Corrupt both meta pages: FREE_DBI gets DUPFIXED without DUPSORT */
    for (uint32_t m = 0; m < 2; m++)
        patch_u16(db, (long)(m * psize) + FREE_FLAGS_OFFSET,
                  (uint16_t)(MDB_INTEGERKEY | MDB_DUPFIXED));

    MDB_env *env = NULL;
    MDB_txn *txn = NULL;
    mdb_env_create(&env);
    mdb_env_set_mapsize(env, 4ULL << 20);
    int open_rc = mdb_env_open(env, dir, 0, 0644);
    int txn_rc  = -1;
    if (open_rc == MDB_SUCCESS)
        txn_rc = mdb_txn_begin(env, NULL, 0, &txn);
    if (txn) mdb_txn_abort(txn);
    mdb_env_close(env);
    rm_tmpdir(dir);

    EXPECT(open_rc == MDB_SUCCESS && txn_rc == MDB_INVALID,
           "CVE-2019-16224: FREE_DBI DUPFIXED without DUPSORT -> "
           "mdb_txn_begin returns MDB_INVALID");
}

static void test_cve_16224_main_dbi(void)
{
    char dir[64], db[128];
    make_tmpdir(dir, sizeof(dir), "16224b");
    snprintf(db, sizeof(db), "%s/data.mdb", dir);

    uint32_t psize = create_db(dir, 10);
    ABORT_IF(!psize, "create_db 16224b");

    for (uint32_t m = 0; m < 2; m++)
        patch_u16(db, (long)(m * psize) + MAIN_FLAGS_OFFSET,
                  (uint16_t)MDB_INTEGERDUP);

    MDB_env *env = NULL;
    MDB_txn *txn = NULL;
    mdb_env_create(&env);
    mdb_env_set_mapsize(env, 4ULL << 20);
    mdb_env_open(env, dir, 0, 0644);
    int rc = mdb_txn_begin(env, NULL, 0, &txn);
    if (txn) mdb_txn_abort(txn);
    mdb_env_close(env);
    rm_tmpdir(dir);

    EXPECT(rc == MDB_INVALID,
           "CVE-2019-16224: MAIN_DBI INTEGERDUP without DUPSORT -> "
           "mdb_txn_begin returns MDB_INVALID");
}

/* ---- CVE-2019-16228 -------------------------------------------------------
 * Divide-by-zero in mdb_env_open2: me_maxpg = me_mapsize / me_psize when
 * mm_psize is zero or nonsensical.
 * Patch: validate mm_psize in mdb_env_open2 — mdb_env_open returns MDB_INVALID.
 * ----------------------------------------------------------------------- */

static void test_cve_16228_zero_psize(void)
{
    char dir[64], db[128];
    make_tmpdir(dir, sizeof(dir), "16228z");
    snprintf(db, sizeof(db), "%s/data.mdb", dir);

    uint32_t psize = create_db(dir, 1);
    ABORT_IF(!psize, "create_db 16228z");

    patch_u32(db, PSIZE_OFFSET, 0);
    patch_u32(db, (long)psize + PSIZE_OFFSET, 0);

    MDB_env *env = NULL;
    mdb_env_create(&env);
    int rc = mdb_env_open(env, dir, 0, 0644);
    mdb_env_close(env);
    rm_tmpdir(dir);

    EXPECT(rc == MDB_INVALID,
           "CVE-2019-16228: mm_psize=0 -> mdb_env_open returns MDB_INVALID");
}

static void test_cve_16228_nonpow2_psize(void)
{
    char dir[64], db[128];
    make_tmpdir(dir, sizeof(dir), "16228n");
    snprintf(db, sizeof(db), "%s/data.mdb", dir);

    uint32_t psize = create_db(dir, 1);
    ABORT_IF(!psize, "create_db 16228n");

    patch_u32(db, PSIZE_OFFSET, 4000);
    patch_u32(db, (long)psize + PSIZE_OFFSET, 4000);

    MDB_env *env = NULL;
    mdb_env_create(&env);
    int rc = mdb_env_open(env, dir, 0, 0644);
    mdb_env_close(env);
    rm_tmpdir(dir);

    EXPECT(rc == MDB_INVALID,
           "CVE-2019-16228: mm_psize=4000 (not power-of-two) -> "
           "mdb_env_open returns MDB_INVALID");
}

/* ---- CVE-2019-16225 -------------------------------------------------------
 * Invalid write via P_DIRTY on a read-only mmap'd page.
 * mdb_page_touch() skips copy-on-write when P_DIRTY is already set, leaving
 * the cursor pointing at the read-only mmap; the next write crashes.
 * Patch: guard in mdb_page_get rejects P_DIRTY pages in non-WRITEMAP mode
 * with MDB_CORRUPTED.
 * ----------------------------------------------------------------------- */

static void test_cve_16225(void)
{
    char dir[64], db[128];
    make_tmpdir(dir, sizeof(dir), "16225");
    snprintf(db, sizeof(db), "%s/data.mdb", dir);

    uint32_t psize = create_db(dir, 3);
    ABORT_IF(!psize, "create_db 16225");

    long fsize;
    uint8_t *data = slurp(db, &fsize);
    int patched = 0;
    for (long off = 2 * (long)psize; off + (long)psize <= fsize; off += psize) {
        uint16_t flags = 0;
        memcpy(&flags, data + off + MP_FLAGS_OFFSET, 2);
        if ((flags & P_LEAF) && !(flags & P_DIRTY)) {
            flags |= P_DIRTY;
            memcpy(data + off + MP_FLAGS_OFFSET, &flags, 2);
            patched++;
        }
    }
    ABORT_IF(!patched, "no leaf page found to corrupt (CVE-16225)");
    spew(db, data, fsize);
    free(data);

    MDB_env *env = NULL;
    MDB_txn *txn = NULL;
    MDB_dbi dbi;
    mdb_env_create(&env);
    mdb_env_set_mapsize(env, 4ULL << 20);
    mdb_env_open(env, dir, 0, 0644);
    mdb_txn_begin(env, NULL, 0, &txn);
    mdb_dbi_open(txn, NULL, 0, &dbi);

    char ks[] = "key0";
    MDB_val k = {4, ks};
    int del_rc = mdb_del(txn, dbi, &k, NULL);

    char ks2[] = "key2", vs2[] = "xxx";
    MDB_val k2 = {4, ks2}, v2 = {3, vs2};
    int put_rc = mdb_put(txn, dbi, &k2, &v2, 0);

    mdb_txn_abort(txn);
    mdb_env_close(env);
    rm_tmpdir(dir);

    EXPECT(del_rc == MDB_CORRUPTED || put_rc == MDB_CORRUPTED,
           "CVE-2019-16225: P_DIRTY on disk page -> del or put returns MDB_CORRUPTED");
}

/* ---- CVE-2019-16226 -------------------------------------------------------
 * Out-of-bounds memmove in mdb_node_del via corrupt mn_hi.
 * NODEDSZ() = mn_lo | (mn_hi << 16). Setting mn_hi=0x0100 yields a size
 * larger than the page, causing memmove to write beyond the page buffer.
 * Patch: size validation in mdb_node_del sets MDB_TXN_ERROR; commit returns
 * MDB_BAD_TXN.
 * ----------------------------------------------------------------------- */

static void test_cve_16226(void)
{
    char dir[64], db[128];
    make_tmpdir(dir, sizeof(dir), "16226");
    snprintf(db, sizeof(db), "%s/data.mdb", dir);

    uint32_t psize = create_db(dir, 3);
    ABORT_IF(!psize, "create_db 16226");

    long leaf_off = first_leaf_offset(db, psize);
    ABORT_IF(leaf_off < 0, "no leaf page found (CVE-16226)");

    long fsize;
    uint8_t *data = slurp(db, &fsize);

    uint16_t ptr0 = 0;
    memcpy(&ptr0, data + leaf_off + MP_PTRS0_OFFSET, 2);
    ABORT_IF(!ptr0 || ptr0 >= psize, "ptr0 out of range");

    /* mn_hi is at MDB_node+2; set to 0x0100 -> NODEDSZ >> psize */
    uint16_t corrupt_hi = 0x0100;
    memcpy(data + leaf_off + ptr0 + 2, &corrupt_hi, 2);
    spew(db, data, fsize);
    free(data);

    MDB_env *env = NULL;
    MDB_txn *txn = NULL;
    MDB_dbi dbi;
    mdb_env_create(&env);
    mdb_env_set_mapsize(env, 4ULL << 20);
    mdb_env_open(env, dir, 0, 0644);
    mdb_txn_begin(env, NULL, 0, &txn);
    mdb_dbi_open(txn, NULL, 0, &dbi);

    char ks[] = "key0";
    MDB_val k = {4, ks};
    mdb_del(txn, dbi, &k, NULL);

    char ks2[] = "key2", vs2[] = "xxx";
    MDB_val k2 = {4, ks2}, v2 = {3, vs2};
    mdb_put(txn, dbi, &k2, &v2, 0);

    int commit_rc = mdb_txn_commit(txn);
    mdb_env_close(env);
    rm_tmpdir(dir);

    EXPECT(commit_rc != MDB_SUCCESS,
           "CVE-2019-16226: corrupt mn_hi -> mdb_txn_commit must fail");
}

/* ---- CVE-2019-16227 -------------------------------------------------------
 * NULL-pointer write via F_DUPDATA on a non-DUPSORT database.
 * mdb_xcursor_init1 is called with mc->mc_xcursor==NULL (xcursors are only
 * allocated for DUPSORT databases) and immediately dereferences it for memcpy.
 * Patch: NULL guard before every mdb_xcursor_init1 call that follows an
 * F_DUPDATA check; mdb_cursor_get(MDB_FIRST) returns MDB_CORRUPTED.
 * ----------------------------------------------------------------------- */

static void test_cve_16227(void)
{
    char dir[64], db[128];
    make_tmpdir(dir, sizeof(dir), "16227");
    snprintf(db, sizeof(db), "%s/data.mdb", dir);

    uint32_t psize = create_db(dir, 3);
    ABORT_IF(!psize, "create_db 16227");

    long leaf_off = first_leaf_offset(db, psize);
    ABORT_IF(leaf_off < 0, "no leaf page found (CVE-16227)");

    long fsize;
    uint8_t *data = slurp(db, &fsize);

    uint16_t ptr0 = 0;
    memcpy(&ptr0, data + leaf_off + MP_PTRS0_OFFSET, 2);
    ABORT_IF(!ptr0 || ptr0 >= psize, "ptr0 out of range");

    /* mn_flags is at MDB_node+4; set F_DUPDATA on a non-DUPSORT node */
    uint16_t mn_flags = 0;
    memcpy(&mn_flags, data + leaf_off + ptr0 + 4, 2);
    mn_flags |= F_DUPDATA;
    memcpy(data + leaf_off + ptr0 + 4, &mn_flags, 2);
    spew(db, data, fsize);
    free(data);

    MDB_env *env = NULL;
    MDB_txn *txn = NULL;
    MDB_dbi dbi;
    MDB_cursor *cursor = NULL;
    mdb_env_create(&env);
    mdb_env_set_mapsize(env, 4ULL << 20);
    mdb_env_open(env, dir, 0, 0644);
    mdb_txn_begin(env, NULL, 0, &txn);
    mdb_dbi_open(txn, NULL, 0, &dbi);
    mdb_cursor_open(txn, dbi, &cursor);

    MDB_val k = {0, NULL}, v = {0, NULL};
    int rc = mdb_cursor_get(cursor, &k, &v, MDB_FIRST);
    mdb_cursor_close(cursor);
    mdb_txn_abort(txn);
    mdb_env_close(env);
    rm_tmpdir(dir);

    EXPECT(rc == MDB_CORRUPTED,
           "CVE-2019-16227: F_DUPDATA on non-DUPSORT node -> "
           "mdb_cursor_get(MDB_FIRST) returns MDB_CORRUPTED");
}

/* ---- main ---- */

int main(void)
{
    printf("Testing CVE-2019-16224..16228 patches\n");
    printf("=====================================\n");
    test_cve_16224_free_dbi();
    test_cve_16224_main_dbi();
    test_cve_16228_zero_psize();
    test_cve_16228_nonpow2_psize();
    test_cve_16225();
    test_cve_16226();
    test_cve_16227();
    printf("=====================================\n");
    printf("Results: %d passed, %d failed\n", n_pass, n_fail);
    return n_fail > 0 ? 1 : 0;
}
