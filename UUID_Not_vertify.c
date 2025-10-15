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
// 定数定義 (Constants)
// ============================================================================
#define PAGE_SIZE 0x1000
#define MB (1024UL * 1024)
#define GB (1024UL * 1024 * 1024)
#define PHYSICAL_ADDR_THRESHOLD 0x200000000UL
#define PHYSICAL_ADDR_MAXIMAM 0x400000000UL

// UUID関連の定数 (UUID Constants)
#define UUID_MAGIC 0xBAD0000000000001ULL

// pagemap bit flags
#define PM_PRESENT (1ULL << 63)
#define PM_PFN_MASK ((1ULL << 55) - 1)

// ============================================================================
// グローバル変数 (Global Variables)
// ============================================================================
volatile size_t g_alias_processed = 0;
volatile size_t g_alias_total = 0;

// ============================================================================
// 構造体定義 (Struct Definitions)
// ============================================================================

// メモリブロック (Memory Block)
typedef struct {
    void *addr;
    size_t size;
} MemBlock;

// ページUUID構造体 (Page UUID Struct)
typedef struct {
    uint64_t magic;      // マジックナンバー (識別用) (Magic number for identification)
    uint64_t virt_addr;  // 仮想アドレス (Virtual address)
    uint64_t checksum;   // チェックサム (Checksum)
    uint64_t reserved;   // 予約フィールド (64バイト境界調整) (Reserved for 64-byte alignment)
} PageUUID;

// スレッドデータ (UUID版) (Thread Data for UUID version)
typedef struct {
    size_t *valid_indices; // 有効なインデックスの配列 (Array of valid indices)
    size_t start_index;    // valid_indices内の開始位置 (Start index within valid_indices)
    size_t end_index;      // valid_indices内の終了位置 (End index within valid_indices)
    size_t valid_count;    // 有効なインデックスの総数 (Total count of valid indices)
} AliasThreadDataV2;

// ============================================================================
// グローバル変数 (Global Variables)
// ============================================================================
MemBlock *mem_blocks = NULL;
size_t block_count = 0;
size_t block_capacity = 0;

pthread_mutex_t g_alias_mutex = PTHREAD_MUTEX_INITIALIZER;
int g_pairs_found = 0;

// シグナルハンドリング用 (For Signal Handling)
static sigjmp_buf segv_jmp_buf;
static volatile sig_atomic_t segv_occurred = 0;

void segv_handler(int sig) {
    segv_occurred = 1;
    siglongjmp(segv_jmp_buf, 1);
}

// ============================================================================
// UUID関連関数 (UUID Functions)
// ============================================================================

/**
 * generate_page_uuid - ページ用のUUIDを生成
 * @virt_addr: 仮想アドレス
 *
 * 戻り値: 生成されたUUID
 */
PageUUID generate_page_uuid(void *virt_addr) {
    PageUUID uuid;
    uuid.magic = UUID_MAGIC;
    uuid.virt_addr = (uint64_t)virt_addr;
    uuid.checksum = uuid.magic ^ uuid.virt_addr;
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
    if (uuid == NULL) {
        return 0;
    }
    if (uuid->magic != UUID_MAGIC) {
        return 0;
    }
    uint64_t expected_checksum = uuid->magic ^ uuid->virt_addr;
    if (uuid->checksum != expected_checksum) {
        return 0;
    }
    if (expected_virt != NULL) {
        if (uuid->virt_addr != (uint64_t)expected_virt) {
            return 0;
        }
    }
    return 1;
}

// ============================================================================
// ユーティリティ関数 (Utility Functions)
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

    if (!(page_info & PM_PRESENT)) return 0;

    uint64_t pfn = page_info & PM_PFN_MASK;
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
// Stage 1: メモリ確保 (Memory Allocation)
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
// Stage 2: UUID書き込み (Write UUID)
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
    
    printf("\nWriting UUID to each page...\n");

    size_t written = 0;
    size_t write_errors = 0;
    size_t uuid_verify_errors = 0;

    for (size_t i = 0; i < block_count; i++) {
        // UUID生成 
        PageUUID uuid = generate_page_uuid(mem_blocks[i].addr);

        // シグナルハンドラ保護 
        /*
        struct sigaction sa, old_sa;
        sa.sa_handler = segv_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGSEGV, &sa, &old_sa);

        segv_occurred = 0;

        if (sigsetjmp(segv_jmp_buf, 1) == 0) {
        */
            // UUID書き込み
            PageUUID *page_uuid = (PageUUID *)(mem_blocks[i].addr);
            *page_uuid = uuid;

            // 検証: 読み戻して確認 
            PageUUID read_back = *page_uuid;

            if (!verify_page_uuid(&read_back, mem_blocks[i].addr)) {
                uuid_verify_errors++;
            }
            written++;
        /*
        } else {
            // 書き込み中に予期しないSegFault (Unexpected SegFault during write)
            write_errors++;
        }

        sigaction(SIGSEGV, &old_sa, NULL);
        */

        if (written % 100000 == 0 && written > 0) {
            printf("  %zu / %zu pages written (write_errors %zu)\n",
                   written, block_count, write_errors);
        }
    }

    printf("\n=== Write Summary ===\n");
    printf("  Successfully written: %zu\n", written);
    printf("  Write errors (segfaults): %zu\n", write_errors);
    printf("  UUID verification errors: %zu\n", uuid_verify_errors);
    
    if (write_errors > 0 || uuid_verify_errors > 0) {
        printf("\n*** WARNING: Errors detected during UUID write ***\n");
    }
}


// ============================================================================
// Stage 3: UUID版エイリアスワーカー (Alias Worker for UUID)
// ============================================================================
void *alias_worker_uuid(void *arg) {
    AliasThreadDataV2 *data = (AliasThreadDataV2 *)arg;

    // 外側ループ: 基準ページ i を選択 (Outer loop: select base page i)
    for (size_t idx_i = data->start_index; idx_i < data->end_index; idx_i++) {
        size_t i = data->valid_indices[idx_i];
        void *addr_i = mem_blocks[i].addr;

        // 検証はスキップ (Validation is skipped)

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

            if (!verify_page_uuid(&uuid_i_copy, addr_i)) {
                // UUIDが不正ならスキップ (Skip if UUID is invalid)
            } else {
                 uint64_t expected_virt_i = uuid_i_copy.virt_addr;
                // 内側ループ: 他の全ページと比較 (Inner loop: compare with all other pages)
                for (size_t idx_j = idx_i + 1; idx_j < data->valid_count; idx_j++) {
                    size_t j = data->valid_indices[idx_j];
                    void *addr_j = mem_blocks[j].addr;
                    PageUUID *uuid_j = (PageUUID *)addr_j;
                    
                    segv_occurred = 0;
                    if (sigsetjmp(segv_jmp_buf, 1) == 0) {
                        PageUUID uuid_j_copy = *uuid_j;
                        if (verify_page_uuid(&uuid_j_copy, NULL)) {
                            uint64_t virt_in_uuid_j = uuid_j_copy.virt_addr;

                            if (virt_in_uuid_j == (uint64_t)addr_i) {
                                pthread_mutex_lock(&g_alias_mutex);
                                g_pairs_found++;
                                printf("\n=== ALIAS DETECTED via UUID ===\n");
                                printf("  Page i (index %zu): addr=%p, phys=0x%lx\n", i, addr_i, get_physical_address(addr_i));
                                printf("  Page j (index %zu): addr=%p, phys=0x%lx\n", j, addr_j, get_physical_address(addr_j));
                                printf("  Detection: UUID in page j (0x%lx) points to page i's address\n", virt_in_uuid_j);
                                printf("================================\n");
                                pthread_mutex_unlock(&g_alias_mutex);
                            }
                        }
                    }
                }
            }
        }
        
        sigaction(SIGSEGV, &old_sa, NULL);
        __sync_fetch_and_add(&g_alias_processed, 1);
    }
    return NULL;
}


// ============================================================================
// Stage 3: UUIDを使った効率的なエイリアス検出 (Efficient Alias Detection with UUID)
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

    printf("\n--- Pre-scan ---\n");
    printf("Collecting all allocated pages for scanning (no validation)...\n");

    size_t *valid_indices = malloc(block_count * sizeof(size_t));
    if (!valid_indices) {
        perror("Failed to allocate valid_indices");
        return;
    }
    
    // すべてのページをスキャン対象とする (Target all pages for scanning)
    for (size_t i = 0; i < block_count; i++) {
        valid_indices[i] = i;
    }
    size_t valid_count = block_count;

    printf("\nProceeding with alias scan using %zu pages...\n", valid_count);

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

    // プログレスバー (Progress bar)
    printf("\nScanning for aliases...\n");
    while (g_alias_processed < g_alias_total) {
        int percent = (g_alias_processed * 100) / g_alias_total;
        int bar_width = 50;
        int filled = (bar_width * g_alias_processed) / g_alias_total;

        printf("\r[");
        for (int i = 0; i < bar_width; i++) {
            if (i < filled) printf("=");
            else if (i == filled) printf(">");
            else printf(" ");
        }
        printf("] %3d%% | %zu/%zu pages | Found: %d aliases",
               percent, (size_t)g_alias_processed, (size_t)g_alias_total, g_pairs_found);
        fflush(stdout);
        usleep(100000);
    }

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
// メイン関数 (Main Function)
// ============================================================================

int main() {
    printf("========================================\n");
    printf("  BadRAM Detection Tool with UUID\n");
    printf("  (Validation Skipped Version)\n");
    printf("========================================\n\n");

    // Stage 1: メモリ確保 (Memory Allocation)
    stage1_allocate_memory();

    // Stage 2: UUID書き込み (Write UUID)
    if (block_count > 0 && ask_user("Proceed to Stage 2 (UUID write)?")) {
        stage2_write_pages_uuid();
    }

    // Stage 3: UUID版エイリアス検出 (UUID-based Alias Detection)
    if (block_count > 0 && ask_user("Proceed to Stage 3 (UUID-based alias detection)?")) {
        stage3_check_aliases_uuid();
    }

    // クリーンアップ (Cleanup)
    printf("\n=== Cleanup ===\n");
    for (size_t i = 0; i < block_count; i++) {
        // 検証せずに解放 (Free without validation)
        free(mem_blocks[i].addr);
    }
    free(mem_blocks);

    printf("Done.\n");
    return 0;
}
