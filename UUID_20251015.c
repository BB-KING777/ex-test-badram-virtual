#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/sysinfo.h>
#include <dirent.h>
#include <pthread.h>
#include <signal.h>
#include <setjmp.h>

// ============================================================================
// 定数定義
// ============================================================================
#define PAGE_SIZE 0x1000
#define MB (1024UL * 1024)
#define GB (1024UL * 1024 * 1024)
#define PHYSICAL_ADDR_THRESHOLD 0x200000000UL
#define PHYSICAL_ADDR_MAXIMAM 0x400000000UL

// UUID関連の定数 (修正: 有効な16進数に変更)
#define UUID_MAGIC 0xBAD0000000000001ULL

// pagemap bit flags
#define PM_PRESENT (1ULL << 63)
#define PM_PFN_MASK ((1ULL << 55) - 1)

// ============================================================================
// グローバル変数
// ============================================================================
volatile size_t g_alias_processed = 0;
volatile size_t g_alias_total = 0;

// ============================================================================
// 構造体定義
// ============================================================================

// メモリブロック
typedef struct {
    void *addr;
    size_t size;
} MemBlock;

// ページUUID構造体
typedef struct {
    uint64_t magic;        // マジックナンバー (識別用)
    uint64_t virt_addr;    // 仮想アドレス
    uint64_t checksum;     // チェックサム
    uint64_t reserved;     // 予約フィールド (64バイト境界調整)
} PageUUID;

// ページ情報
typedef struct {
    uint64_t phys;
    void *virt;
} PageInfo;

// スレッドデータ (UUID版)
typedef struct {
    size_t *valid_indices;  // 有効なインデックスの配列
    size_t start_index;     // valid_indices内の開始位置
    size_t end_index;       // valid_indices内の終了位置
    size_t valid_count;     // 有効なインデックスの総数
} AliasThreadDataV2;

// ============================================================================
// グローバル変数
// ============================================================================
MemBlock *mem_blocks = NULL;
size_t block_count = 0;
size_t block_capacity = 0;

pthread_mutex_t g_alias_mutex = PTHREAD_MUTEX_INITIALIZER;
int g_pairs_found = 0;

// シグナルハンドリング用
static sigjmp_buf segv_jmp_buf;
static volatile sig_atomic_t segv_occurred = 0;

void segv_handler(int sig) {
    segv_occurred = 1;
    siglongjmp(segv_jmp_buf, 1);
}

// ============================================================================
// アドレス検証関数
// ============================================================================

// ユーザ空間の有効なアドレス範囲かチェック
int is_valid_user_address(void *addr) {
    uintptr_t addr_val = (uintptr_t)addr;
    
    if (addr == NULL) {
        return 0;
    }
    
    // Linux x86_64 user space: 0x1000 ~ 0x7fffffffffff
    if (addr_val < 0x1000 || addr_val >= 0x800000000000ULL) {
        return 0;
    }
    
    return 1;
}

// アドレスがアクセス可能か (read/writeでSegFaultしないか) チェック
int is_address_accessible(void *addr, size_t size) {
    struct sigaction sa, old_sa;
    int result = 1;
    
    // シグナルハンドラをセットアップ
    sa.sa_handler = segv_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    if (sigaction(SIGSEGV, &sa, &old_sa) == -1) {
        return 0;
    }
    
    segv_occurred = 0;
    
    // 読み書きを試行
    if (sigsetjmp(segv_jmp_buf, 1) == 0) {
        volatile uint8_t *ptr = (volatile uint8_t *)addr;
        
        // 開始位置での読み取りテスト
        volatile uint8_t dummy = ptr[0];
        
        // 開始位置での書き込みテスト
        uint8_t original = ptr[0];
        ptr[0] = 0xAA;
        ptr[0] = original;
        
        // 終端位置でのテスト
        dummy = ptr[size - 1];
        
        (void)dummy;
    } else {
        result = 0;
    }
    
    // 元のハンドラに戻す
    sigaction(SIGSEGV, &old_sa, NULL);
    
    return result && !segv_occurred;
}

// 包括的なアドレス検証
typedef enum {
    ADDR_VALID = 0,
    ADDR_NULL,
    ADDR_OUT_OF_RANGE,
    ADDR_NOT_ACCESSIBLE
} AddressValidation;

const char* addr_validation_string(AddressValidation result) {
    switch (result) {
        case ADDR_VALID: return "Valid";
        case ADDR_NULL: return "NULL pointer";
        case ADDR_OUT_OF_RANGE: return "Out of user address range";
        case ADDR_NOT_ACCESSIBLE: return "Not accessible (would segfault)";
        default: return "Unknown error";
    }
}

AddressValidation validate_address(void *addr, size_t size) {
    // 1. NULLチェック
    if (addr == NULL) {
        return ADDR_NULL;
    }
    
    // 2. 範囲チェック
    if (!is_valid_user_address(addr)) {
        return ADDR_OUT_OF_RANGE;
    }
    
    // 3. アクセス可能性チェック (最も重要)
    if (!is_address_accessible(addr, size)) {
        return ADDR_NOT_ACCESSIBLE;
    }
    
    return ADDR_VALID;
}

// ============================================================================
// UUID関連関数
// ============================================================================

/**
 * generate_page_uuid - ページ用のUUIDを生成
 * @virt_addr: 仮想アドレス
 * 
 * 戻り値: 生成されたUUID
 */
PageUUID generate_page_uuid(void *virt_addr) {
    PageUUID uuid;
    
    // マジックナンバー
    uuid.magic = UUID_MAGIC;
    
    // 仮想アドレス
    uuid.virt_addr = (uint64_t)virt_addr;
    
    // チェックサム (XORベースの簡単なハッシュ)
    uuid.checksum = uuid.magic ^ uuid.virt_addr;
    
    // 予約フィールド
    uuid.reserved = 0;
    
    return uuid;
}

/**
 * verify_page_uuid - UUIDの妥当性を検証
 * @uuid: 検証するUUID
 * @expected_virt: 期待される仮想アドレス (NULLの場合はチェックしない)
 * 
 * 戻り値: 1=有効, 0=無効
 */
int verify_page_uuid(const PageUUID *uuid, void *expected_virt) {
    // NULLチェック
    if (uuid == NULL) {
        return 0;
    }
    
    // マジックナンバー検証
    if (uuid->magic != UUID_MAGIC) {
        return 0;
    }
    
    // チェックサム検証
    uint64_t expected_checksum = uuid->magic ^ uuid->virt_addr;
    if (uuid->checksum != expected_checksum) {
        return 0;
    }
    
    // 仮想アドレス一致確認 (オプション)
    if (expected_virt != NULL) {
        if (uuid->virt_addr != (uint64_t)expected_virt) {
            return 0;
        }
    }
    
    return 1;
}

/**
 * print_page_uuid - UUIDの内容を表示 (デバッグ用)
 * @uuid: 表示するUUID
 * @prefix: 表示の前に出力する文字列
 */
void print_page_uuid(const PageUUID *uuid, const char *prefix) {
    if (uuid == NULL) {
        printf("%sUUID: NULL\n", prefix ? prefix : "");
        return;
    }
    
    printf("%sUUID:\n", prefix ? prefix : "");
    printf("%s  magic:     0x%016lx %s\n", prefix ? prefix : "", 
           uuid->magic, uuid->magic == UUID_MAGIC ? "OK" : "NG");
    printf("%s  virt_addr: 0x%016lx\n", prefix ? prefix : "", uuid->virt_addr);
    printf("%s  checksum:  0x%016lx %s\n", prefix ? prefix : "", 
           uuid->checksum, 
           uuid->checksum == (uuid->magic ^ uuid->virt_addr) ? "OK" : "NG");
}

// ============================================================================
// ユーティリティ関数
// ============================================================================

int ask_user(const char *question) {
    char response;
    printf("\n%s (Y/N): ", question);
    scanf(" %c", &response);
    while (getchar() != '\n');
    return (toupper(response) == 'Y');
}

size_t get_available_memory_mb() {
    struct sysinfo info;
    if (sysinfo(&info) != 0) {
        perror("sysinfo failed");
        return 0;
    }
    size_t available = info.freeram + info.bufferram;
    return (available * info.mem_unit) / MB;
}

uint64_t get_physical_address(void *virtual_addr) {
    int pagemap_fd = open("/proc/self/pagemap", O_RDONLY);
    if (pagemap_fd < 0) return 0;
    
    uint64_t offset = ((uint64_t)virtual_addr / PAGE_SIZE) * sizeof(uint64_t);
    if (lseek(pagemap_fd, offset, SEEK_SET) < 0) {
        close(pagemap_fd);
        return 0;
    }
    
    uint64_t page_info;
    if (read(pagemap_fd, &page_info, sizeof(uint64_t)) != sizeof(uint64_t)) {
        close(pagemap_fd);
        return 0;
    }
    
    close(pagemap_fd);
    
    if (!(page_info & (1ULL << 63))) return 0;
    
    uint64_t pfn = page_info & ((1ULL << 55) - 1);
    return pfn * PAGE_SIZE;
}

void add_mem_block(void *addr, size_t size) {
    if (block_count >= block_capacity) {
        block_capacity = block_capacity == 0 ? 100000 : block_capacity * 2;
        mem_blocks = realloc(mem_blocks, block_capacity * sizeof(MemBlock));
        if (!mem_blocks) {
            perror("realloc failed");
            exit(1);
        }
    }
    mem_blocks[block_count].addr = addr;
    mem_blocks[block_count].size = size;
    block_count++;
}

// ============================================================================
// Stage 1: メモリ確保
// ============================================================================

void stage1_allocate_memory() {
    printf("\n=== Stage 1: Allocate Memory ===\n");
    printf("PID: %d\n", getpid());
    
    size_t available_mb = get_available_memory_mb();
    printf("Available memory: %zu MB (%.2f GB)\n",
           available_mb, (double)available_mb / 1024);
    
    size_t max_safe_mb = available_mb * 95 / 100;
    if (max_safe_mb > 10 * 1024) {
        max_safe_mb = 10 * 1024;
    }
    
    size_t max_pages = (max_safe_mb * MB) / PAGE_SIZE;
    
    printf("Will allocate: %zu pages (%zu MB, %.2f GB)\n",
           max_pages, (max_pages * PAGE_SIZE) / MB, (double)(max_pages * PAGE_SIZE) / GB);
    
    if (!ask_user("Start allocation?")) {
        return;
    }
    
    printf("\nAllocating memory...\n");
    
    size_t total_allocated = 0;
    
    for (size_t i = 0; i < max_pages; i++) {
        void *addr = malloc(PAGE_SIZE);
        
        if (addr == NULL) {
            break;
        }
        
        add_mem_block(addr, PAGE_SIZE);
        total_allocated += PAGE_SIZE;
        
        if ((i + 1) % 10000 == 0) {
            printf("  %zu pages (%zu MB)\n", i + 1, total_allocated / MB);
        }
    }

    printf("\nAllocated: %zu pages (%zu MB, %.2f GB)\n",
           block_count, total_allocated / MB, (double)total_allocated / GB);

    if (ask_user("Check high physical addresses (>= 8GB)?")) {
        printf("\nChecking physical addresses...\n");

        int high_addr_count = 0;
        int display_count = 0;
        
        for (size_t i = 0; i < block_count; i++) {
            void *virt_addr = mem_blocks[i].addr;
            uint64_t phys_addr = get_physical_address(virt_addr);
            
            if (phys_addr >= PHYSICAL_ADDR_THRESHOLD && 
                phys_addr < PHYSICAL_ADDR_MAXIMAM) {
                high_addr_count++;
                if (display_count < 10) {
                    printf("  Page %zu: virtual %p -> physical 0x%lx\n",
                           i, virt_addr, phys_addr);
                    display_count++;
                }
            }
            
            if ((i + 1) % 50000 == 0) {
                printf("  Checked %zu / %zu pages\n", i + 1, block_count);
            }
        }
        
        if (high_addr_count > 10) {
            printf("  ... and %d more\n", high_addr_count - 10);
        }
        
        printf("\nTotal high addresses: %d\n", high_addr_count);
    }
}

// ============================================================================
// Stage 2: UUID書き込み
// ============================================================================

void stage2_write_pages_uuid() {
    printf("\n=== Stage 2: Write UUID to Pages ===\n");
    
    if (block_count == 0) {
        printf("No allocated memory.\n");
        return;
    }

    printf("Will write UUID to: %zu pages (about %zu MB)\n",
           block_count, block_count * PAGE_SIZE / MB);

    if (!ask_user("Write UUID to each page?")) {
        printf("Skipping Stage 2\n");
        return;
    }

    // ========================================
    // 事前検証
    // ========================================
    printf("\nValidating all addresses before writing...\n");
    
    typedef struct {
        size_t index;
        AddressValidation error;
        void *addr;
    } ValidationError;
    
    ValidationError *errors = malloc(sizeof(ValidationError) * block_count);
    if (!errors) {
        perror("Failed to allocate error array");
        return;
    }
    
    size_t error_count = 0;
    size_t null_count = 0;
    size_t range_count = 0;
    size_t access_count = 0;
    
    for (size_t i = 0; i < block_count; i++) {
        AddressValidation result = validate_address(mem_blocks[i].addr, PAGE_SIZE);
        
        if (result != ADDR_VALID) {
            errors[error_count].index = i;
            errors[error_count].error = result;
            errors[error_count].addr = mem_blocks[i].addr;
            error_count++;
            
            switch (result) {
                case ADDR_NULL: null_count++; break;
                case ADDR_OUT_OF_RANGE: range_count++; break;
                case ADDR_NOT_ACCESSIBLE: access_count++; break;
                default: break;
            }
        }
        
        if ((i + 1) % 100000 == 0) {
            printf("  Validated %zu / %zu (errors: %zu)\n", 
                   i + 1, block_count, error_count);
        }
    }
    
    // ========================================
    // 検証結果の表示
    // ========================================
    printf("\nValidation complete:\n");
    printf("  Total pages: %zu\n", block_count);
    printf("  Valid pages: %zu (%.2f%%)\n", 
           block_count - error_count, 
           100.0 * (block_count - error_count) / block_count);
    printf("  Invalid pages: %zu (%.2f%%)\n", 
           error_count, 
           100.0 * error_count / block_count);
    
    if (error_count > 0) {
        printf("\nError breakdown:\n");
        printf("  NULL pointers: %zu\n", null_count);
        printf("  Out of range: %zu\n", range_count);
        printf("  Not accessible: %zu\n", access_count);
        
        // 最初の10個のエラーを表示
        printf("\nFirst errors (up to 10):\n");
        size_t display_limit = (error_count < 10) ? error_count : 10;
        
        for (size_t i = 0; i < display_limit; i++) {
            printf("  [%zu] Index %zu: %s (addr=%p)\n",
                   i + 1,
                   errors[i].index,
                   addr_validation_string(errors[i].error),
                   errors[i].addr);
        }
        
        if (error_count > 10) {
            printf("  ... and %zu more errors\n", error_count - 10);
        }
        
        // BadRAM検出
        if (null_count > 0 || access_count > 0) {
            printf("\n*** BadRAM DETECTED (Pre-write validation) ***\n");
            printf("Memory corruption detected in mem_blocks array.\n");
        }
        
        if (!ask_user("Continue with valid addresses only?")) {
            free(errors);
            return;
        }
    } else {
        printf("\nAll addresses are valid\n");
    }

    // ========================================
    // UUID書き込み (検証付き)
    // ========================================
    printf("\nWriting UUID to each page...\n");
    
    size_t written = 0;
    size_t skipped = 0;
    size_t write_errors = 0;
    size_t uuid_verify_errors = 0;
    
    for (size_t i = 0; i < block_count; i++) {
        // 書き込み前に再検証 (事前検証後に破損した可能性を考慮)
        AddressValidation validation = validate_address(mem_blocks[i].addr, PAGE_SIZE);
        
        if (validation != ADDR_VALID) {
            skipped++;
            continue;
        }
        
        // UUID生成
        PageUUID uuid = generate_page_uuid(mem_blocks[i].addr);
        
        // シグナルハンドラ保護
        struct sigaction sa, old_sa;
        sa.sa_handler = segv_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGSEGV, &sa, &old_sa);
        
        segv_occurred = 0;
        
        if (sigsetjmp(segv_jmp_buf, 1) == 0) {
            // UUID書き込み
            PageUUID *page_uuid = (PageUUID *)(mem_blocks[i].addr);
            *page_uuid = uuid;
            
            // 検証: 読み戻して確認
            PageUUID read_back = *page_uuid;
            
            if (!verify_page_uuid(&read_back, mem_blocks[i].addr)) {
                uuid_verify_errors++;
                if (uuid_verify_errors <= 10) {
                    printf("  WARNING: UUID verification failed at index %zu (addr=%p)\n",
                           i, mem_blocks[i].addr);
                    printf("    Written: magic=0x%lx, virt=0x%lx, checksum=0x%lx\n",
                           uuid.magic, uuid.virt_addr, uuid.checksum);
                    printf("    Read:    magic=0x%lx, virt=0x%lx, checksum=0x%lx\n",
                           read_back.magic, read_back.virt_addr, read_back.checksum);
                }
            }
            
            written++;
        } else {
            // 書き込み中に予期しないSegFault
            write_errors++;
            skipped++;
            if (write_errors <= 10) {
                printf("  ERROR: Segfault during write at index %zu (addr=%p)\n",
                       i, mem_blocks[i].addr);
            }
        }
        
        sigaction(SIGSEGV, &old_sa, NULL);
        
        if (written % 100000 == 0 && written > 0) {
            printf("  %zu / %zu pages written (skipped %zu)\n",
                   written, block_count, skipped);
        }
    }

    if (write_errors > 10) {
        printf("  ... and %zu more write errors\n", write_errors - 10);
    }
    
    if (uuid_verify_errors > 10) {
        printf("  ... and %zu more UUID verification errors\n", 
               uuid_verify_errors - 10);
    }

    printf("\n=== Write Summary ===\n");
    printf("  Successfully written: %zu\n", written);
    printf("  Skipped (invalid): %zu\n", skipped);
    printf("  Write errors: %zu\n", write_errors);
    printf("  UUID verification errors: %zu\n", uuid_verify_errors);
    
    if (write_errors > 0 || uuid_verify_errors > 0) {
        printf("\n*** WARNING: Errors detected during UUID write ***\n");
        printf("Some pages did not retain written UUIDs correctly.\n");
        printf("This indicates memory aliasing or corruption.\n");
    }
    
    free(errors);
}

// ============================================================================
// Stage 3: UUID版エイリアスワーカー
// ============================================================================

/**
 * alias_worker_uuid - UUIDを使ったエイリアス検出ワーカー
 * @arg: AliasThreadDataV2 構造体へのポインタ
 * 
 * 戻り値: NULL
 */
void *alias_worker_uuid(void *arg) {
    AliasThreadDataV2 *data = (AliasThreadDataV2 *)arg;
    
    // 外側ループ: 基準ページ i を選択
    for (size_t idx_i = data->start_index; idx_i < data->end_index; idx_i++) {
        size_t i = data->valid_indices[idx_i];
        
        void *addr_i = mem_blocks[i].addr;
        
        // 基本チェック
        if (addr_i == NULL) {
            __sync_fetch_and_add(&g_alias_processed, 1);
            continue;
        }
        
        uintptr_t addr_val = (uintptr_t)addr_i;
        if (addr_val < 0x1000 || addr_val >= 0x800000000000ULL) {
            __sync_fetch_and_add(&g_alias_processed, 1);
            continue;
        }
        
        // シグナルハンドラ設定
        struct sigaction sa, old_sa;
        sa.sa_handler = segv_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        
        if (sigaction(SIGSEGV, &sa, &old_sa) == -1) {
            __sync_fetch_and_add(&g_alias_processed, 1);
            continue;
        }
        
        segv_occurred = 0;
        
        if (sigsetjmp(segv_jmp_buf, 1) == 0) {
            PageUUID *uuid_i = (PageUUID *)addr_i;
            PageUUID uuid_i_copy = *uuid_i;
            
            // ページ i のUUID検証
            if (!verify_page_uuid(&uuid_i_copy, addr_i)) {
                __sync_fetch_and_add(&g_alias_processed, 1);
                sigaction(SIGSEGV, &old_sa, NULL);
                continue;
            }
            
            uint64_t expected_virt_i = uuid_i_copy.virt_addr;
            
            // 内側ループ: 他の全ページと比較
            for (size_t idx_j = idx_i + 1; idx_j < data->valid_count; idx_j++) {
                size_t j = data->valid_indices[idx_j];
                
                void *addr_j = mem_blocks[j].addr;
                
                if (addr_j == NULL) continue;
                
                uintptr_t addr_val_j = (uintptr_t)addr_j;
                if (addr_val_j < 0x1000 || addr_val_j >= 0x800000000000ULL) {
                    continue;
                }
                
                PageUUID *uuid_j = (PageUUID *)addr_j;
                
                segv_occurred = 0;
                if (sigsetjmp(segv_jmp_buf, 1) == 0) {
                    PageUUID uuid_j_copy = *uuid_j;
                    
                    // ページ j のUUID検証
                    if (!verify_page_uuid(&uuid_j_copy, NULL)) {
                        continue;
                    }
                    
                    uint64_t virt_in_uuid_j = uuid_j_copy.virt_addr;
                    
                    // ========================================
                    // 重要: UUID-based エイリアス検出
                    // ========================================
                    // もし uuid_j の仮想アドレスが addr_i なら、
                    // addr_j は addr_i とエイリアス!
                    
                    if (virt_in_uuid_j == (uint64_t)addr_i) {
                        pthread_mutex_lock(&g_alias_mutex);
                        g_pairs_found++;
                        printf("\n=== ALIAS DETECTED via UUID ===\n");
                        printf("  Page i (index %zu):\n", i);
                        printf("    Virtual address: %p\n", addr_i);
                        printf("    Physical address: 0x%lx\n", 
                               get_physical_address(addr_i));
                        printf("    UUID virt_addr: 0x%lx\n", expected_virt_i);
                        printf("\n");
                        printf("  Page j (index %zu):\n", j);
                        printf("    Virtual address: %p\n", addr_j);
                        printf("    Physical address: 0x%lx\n", 
                               get_physical_address(addr_j));
                        printf("    UUID virt_addr: 0x%lx\n", virt_in_uuid_j);
                        printf("\n");
                        printf("  Detection: UUID in page j points to page i's address\n");
                        printf("  This means page j is an alias of page i\n");
                        printf("================================\n");
                        pthread_mutex_unlock(&g_alias_mutex);
                    }
                    
                } else {
                    // SegFault発生
                }
            }
        }
        
        sigaction(SIGSEGV, &old_sa, NULL);
        __sync_fetch_and_add(&g_alias_processed, 1);
    }
    
    return NULL;
}

// ============================================================================
// Stage 3: UUIDを使った効率的なエイリアス検出
// ============================================================================

void stage3_check_aliases_uuid() {
    printf("\n=== Stage 3: Check Aliases with UUID ===\n");
    
    if (block_count < 2) {
        printf("Not enough memory.\n");
        return;
    }

    if (!ask_user("Start UUID-based alias scan?")) {
        return;
    }

    // ========================================
    // 事前検証 & UUID検証
    // ========================================
    printf("\n--- Pre-scan Validation ---\n");
    printf("Validating addresses and UUIDs...\n");
    
    size_t *valid_indices = malloc(block_count * sizeof(size_t));
    if (!valid_indices) {
        perror("Failed to allocate valid_indices");
        return;
    }
    
    size_t valid_count = 0;
    size_t null_count = 0;
    size_t range_count = 0;
    size_t access_count = 0;
    size_t invalid_uuid_count = 0;
    
    for (size_t i = 0; i < block_count; i++) {
        void *addr = mem_blocks[i].addr;
        
        // NULLチェック
        if (addr == NULL) {
            null_count++;
            continue;
        }
        
        // 範囲チェック
        uintptr_t addr_val = (uintptr_t)addr;
        if (addr_val < 0x1000 || addr_val >= 0x800000000000ULL) {
            range_count++;
            continue;
        }
        
        // シグナルハンドラ設定
        struct sigaction sa, old_sa;
        sa.sa_handler = segv_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGSEGV, &sa, &old_sa);
        
        segv_occurred = 0;
        int accessible = 1;
        int uuid_valid = 0;
        
        if (sigsetjmp(segv_jmp_buf, 1) == 0) {
            // UUIDを読み取り
            PageUUID *uuid = (PageUUID *)addr;
            PageUUID uuid_copy = *uuid;
            
            // UUID検証
            if (verify_page_uuid(&uuid_copy, addr)) {
                uuid_valid = 1;
            } else {
                invalid_uuid_count++;
                accessible = 0;
            }
        } else {
            accessible = 0;
            access_count++;
        }
        
        sigaction(SIGSEGV, &old_sa, NULL);
        
        // アクセス可能かつUUIDが有効な場合のみ有効リストに追加
        if (accessible && uuid_valid) {
            valid_indices[valid_count] = i;
            valid_count++;
        }
        
        if ((i + 1) % 100000 == 0) {
            printf("  Validated %zu / %zu (valid: %zu)\n", 
                   i + 1, block_count, valid_count);
        }
    }
    
    printf("\n--- Validation Results ---\n");
    printf("  Total pages: %zu\n", block_count);
    printf("  Valid pages (with UUID): %zu (%.2f%%)\n", 
           valid_count, 100.0 * valid_count / block_count);
    printf("  Invalid pages: %zu\n", block_count - valid_count);
    printf("    NULL pointers: %zu\n", null_count);
    printf("    Out of range: %zu\n", range_count);
    printf("    Not accessible: %zu\n", access_count);
    printf("    Invalid UUID: %zu\n", invalid_uuid_count);
    
    if (null_count > 0 || access_count > 0 || invalid_uuid_count > 0) {
        printf("\n*** BadRAM DETECTED (Pre-scan) ***\n");
        if (invalid_uuid_count > 0) {
            printf("UUIDs corrupted: %zu pages\n", invalid_uuid_count);
            printf("This strongly indicates memory aliasing.\n");
        }
    }
    
    if (valid_count < 2) {
        printf("\nNot enough valid pages for alias scan.\n");
        free(valid_indices);
        return;
    }
    
    printf("\nProceeding with alias scan using %zu valid pages...\n", valid_count);

    // ========================================
    // マルチスレッドでUUID版エイリアススキャン
    // ========================================
    int num_threads = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_threads <= 0) num_threads = 4;
    if (num_threads > 16) num_threads = 16;

    printf("Scanning with %d threads...\n", num_threads);

    pthread_t threads[num_threads];
    AliasThreadDataV2 thread_data[num_threads];
    size_t indices_per_thread = valid_count / num_threads;

    g_pairs_found = 0;
    g_alias_processed = 0;
    g_alias_total = valid_count;

    for (int i = 0; i < num_threads; i++) {
        thread_data[i].valid_indices = valid_indices;
        thread_data[i].valid_count = valid_count;
        thread_data[i].start_index = i * indices_per_thread;
        if (i == num_threads - 1) {
            thread_data[i].end_index = valid_count;
        } else {
            thread_data[i].end_index = (i + 1) * indices_per_thread;
        }
        pthread_create(&threads[i], NULL, alias_worker_uuid, &thread_data[i]);
    }

    // プログレスバー
    printf("\nScanning for aliases...\n");
    while (g_alias_processed < g_alias_total) {
        int percent = (g_alias_processed * 100) / g_alias_total;
        int bar_width = 50;
        int filled = (bar_width * g_alias_processed) / g_alias_total;
        
        printf("\r[");
        for (int i = 0; i < bar_width; i++) {
            if (i < filled) {
                printf("=");
            } else if (i == filled) {
                printf(">");
            } else {
                printf(" ");
            }
        }
        printf("] %3d%% | %zu/%zu pages | Found: %d aliases",
               percent, (size_t)g_alias_processed, (size_t)g_alias_total, g_pairs_found);
        fflush(stdout);
        usleep(100000);  // 100ms
    }
    
    // 最終更新
    printf("\r[");
    for (int i = 0; i < 50; i++) printf("=");
    printf("] 100%% | %zu/%zu pages | Found: %d aliases\n",
           (size_t)g_alias_total, (size_t)g_alias_total, g_pairs_found);

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    free(valid_indices);

    printf("\n=== Result ===\n");
    if (g_pairs_found == 0) {
        printf("No aliases found\n");
    } else {
        printf("%d alias pair(s) found\n", g_pairs_found);
        printf("*** BadRAM CONFIRMED ***\n");
    }
}

// ============================================================================
// メイン関数
// ============================================================================

int main() {
    printf("========================================\n");
    printf("  BadRAM Detection Tool with UUID\n");
    printf("  UUID-based Efficient Alias Detection\n");
    printf("========================================\n\n");
    
    printf("Features:\n");
    printf("  - UUID-based page identification\n");
    printf("  - Efficient O(n^2) alias detection with single read\n");
    printf("  - Copy-on-Write resistant\n");
    printf("  - Comprehensive validation and error reporting\n\n");
    
    // Stage 1: メモリ確保
    stage1_allocate_memory();
    
    // Stage 2: UUID書き込み
    if (block_count > 0 && ask_user("Proceed to Stage 2 (UUID write)?")) {
        stage2_write_pages_uuid();
    }
    
    // Stage 3: UUID版エイリアス検出
    if (block_count > 0 && ask_user("Proceed to Stage 3 (UUID-based alias detection)?")) {
        stage3_check_aliases_uuid();
    }
    
    // クリーンアップ
    printf("\n=== Cleanup ===\n");
    for (size_t i = 0; i < block_count; i++) {
        if (validate_address(mem_blocks[i].addr, PAGE_SIZE) == ADDR_VALID) {
            free(mem_blocks[i].addr);
        }
    }
    free(mem_blocks);
    
    printf("Done.\n");
    return 0;
}