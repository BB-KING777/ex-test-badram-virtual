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
#include <time.h>

// Constant definitions
#define PAGE_SIZE 0x1000
#define MB (1024UL * 1024)
#define GB (1024UL * 1024 * 1024)
#define PHYSICAL_ADDR_THRESHOLD 0x200000000UL
#define PHYSICAL_ADDR_MAXIMAM 0x400000000UL
#define MAX_BLOCKS 3000000

// Magic numbers for integrity verification
#define MEMBLOCK_MAGIC_START 0x4D454D424C4B3231ULL  // "MEMBLK21"
#define MEMBLOCK_MAGIC_END   0x454E444D424C4B21ULL  // "ENDMBLK!"

// pagemap bit flags
#define PM_PRESENT (1ULL << 63)
#define PM_PFN_MASK ((1ULL << 55) - 1)

// ★★★ 冗長化・多重チェック機能付き Memory block ★★★
typedef struct {
    uint64_t magic_start;     // 開始マジックナンバー
    void *addr;               // メインアドレス
    size_t size;              // サイズ
    void *addr_copy1;         // アドレスコピー1
    void *addr_copy2;         // アドレスコピー2
    uint64_t checksum1;       // チェックサム1 (FNV-1a)
    uint64_t checksum2;       // チェックサム2 (独自ハッシュ)
    uint64_t index;           // インデックス（自己参照チェック用）
    uint64_t timestamp;       // 作成タイムスタンプ
    uint64_t magic_end;       // 終了マジックナンバー
} MemBlock;

// Physical address mapping
typedef struct {
    uint64_t phys_addr;
    unsigned long virt_addr;
    pid_t pid;
    char comm[256];
} PhysMapping;

// Mapping table
typedef struct {
    PhysMapping *mappings;
    size_t count;
    size_t capacity;
} MappingTable;

// Page information
typedef struct {
    uint64_t phys;
    void *virt;
} PageInfo;

// Thread data
typedef struct {
    pid_t *pids;
    size_t pid_count;
    MappingTable *table;
} ScanThreadData;

// Global variables
static MemBlock mem_blocks_static[MAX_BLOCKS];
MemBlock *mem_blocks = mem_blocks_static;
size_t block_count = 0;
size_t block_capacity = MAX_BLOCKS;

pthread_mutex_t g_mapping_mutex;
pthread_mutex_t g_print_mutex;
volatile size_t g_processed_procs_count = 0;
pid_t g_self_pid;

// Mutex and shared counter for detected pairs
pthread_mutex_t g_alias_mutex = PTHREAD_MUTEX_INITIALIZER;
int g_pairs_found = 0;

// Information passed to each thread
typedef struct {
    size_t start_index;
    size_t end_index;
} AliasThreadData;

// Corruption statistics
typedef struct {
    size_t magic_start_corrupted;
    size_t magic_end_corrupted;
    size_t addr_null;
    size_t addr_invalid_range;
    size_t addr_misaligned;
    size_t addr_copy_mismatch;
    size_t size_wrong;
    size_t checksum1_mismatch;
    size_t checksum2_mismatch;
    size_t index_mismatch;
    size_t timestamp_invalid;
} CorruptionStats;

// ★★★ FNV-1a ハッシュ（チェックサム1） ★★★
uint64_t compute_checksum_fnv1a(void *addr, size_t size, uint64_t index) {
    uint64_t hash = 0xcbf29ce484222325ULL;
    
    // アドレスをハッシュ
    uint64_t val = (uint64_t)addr;
    for (int i = 0; i < 8; i++) {
        hash ^= (val & 0xFF);
        hash *= 0x100000001b3ULL;
        val >>= 8;
    }
    
    // サイズをハッシュ
    val = (uint64_t)size;
    for (int i = 0; i < 8; i++) {
        hash ^= (val & 0xFF);
        hash *= 0x100000001b3ULL;
        val >>= 8;
    }
    
    // インデックスをハッシュ
    val = index;
    for (int i = 0; i < 8; i++) {
        hash ^= (val & 0xFF);
        hash *= 0x100000001b3ULL;
        val >>= 8;
    }
    
    return hash;
}

// ★★★ 独自ハッシュ（チェックサム2） ★★★
uint64_t compute_checksum_custom(void *addr, size_t size, uint64_t index) {
    uint64_t hash = 0x123456789abcdef0ULL;
    uint64_t val = (uint64_t)addr;
    
    hash ^= val;
    hash = (hash << 21) | (hash >> 43);
    hash ^= size;
    hash = (hash << 13) | (hash >> 51);
    hash ^= index;
    hash = (hash << 7) | (hash >> 57);
    hash *= 0x9e3779b97f4a7c15ULL;
    
    return hash;
}

// ★★★ タイムスタンプ取得 ★★★
uint64_t get_timestamp() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

// ★★★ 厳密なエントリ検証 ★★★
typedef enum {
    VERIFY_OK = 0,
    VERIFY_MAGIC_START_CORRUPT,
    VERIFY_MAGIC_END_CORRUPT,
    VERIFY_ADDR_NULL,
    VERIFY_ADDR_INVALID_RANGE,
    VERIFY_ADDR_MISALIGNED,
    VERIFY_ADDR_COPY1_MISMATCH,
    VERIFY_ADDR_COPY2_MISMATCH,
    VERIFY_SIZE_WRONG,
    VERIFY_CHECKSUM1_MISMATCH,
    VERIFY_CHECKSUM2_MISMATCH,
    VERIFY_INDEX_MISMATCH,
    VERIFY_TIMESTAMP_INVALID
} VerifyResult;

const char* verify_result_string(VerifyResult result) {
    switch (result) {
        case VERIFY_OK: return "OK";
        case VERIFY_MAGIC_START_CORRUPT: return "Magic start corrupted";
        case VERIFY_MAGIC_END_CORRUPT: return "Magic end corrupted";
        case VERIFY_ADDR_NULL: return "Address is NULL";
        case VERIFY_ADDR_INVALID_RANGE: return "Address out of valid range";
        case VERIFY_ADDR_MISALIGNED: return "Address not page-aligned";
        case VERIFY_ADDR_COPY1_MISMATCH: return "Address copy 1 mismatch";
        case VERIFY_ADDR_COPY2_MISMATCH: return "Address copy 2 mismatch";
        case VERIFY_SIZE_WRONG: return "Size incorrect";
        case VERIFY_CHECKSUM1_MISMATCH: return "Checksum 1 mismatch";
        case VERIFY_CHECKSUM2_MISMATCH: return "Checksum 2 mismatch";
        case VERIFY_INDEX_MISMATCH: return "Index mismatch";
        case VERIFY_TIMESTAMP_INVALID: return "Timestamp invalid";
        default: return "Unknown error";
    }
}

VerifyResult verify_mem_block_entry_detailed(size_t index, CorruptionStats *stats) {
    MemBlock *block = &mem_blocks[index];
    
    // 1. マジックナンバーチェック（最優先）
    if (block->magic_start != MEMBLOCK_MAGIC_START) {
        if (stats) stats->magic_start_corrupted++;
        return VERIFY_MAGIC_START_CORRUPT;
    }
    
    if (block->magic_end != MEMBLOCK_MAGIC_END) {
        if (stats) stats->magic_end_corrupted++;
        return VERIFY_MAGIC_END_CORRUPT;
    }
    
    // 2. アドレスの NULL チェック
    if (block->addr == NULL) {
        if (stats) stats->addr_null++;
        return VERIFY_ADDR_NULL;
    }
    
    // 3. アドレスの範囲チェック（ユーザー空間）
    uintptr_t addr_val = (uintptr_t)block->addr;
    // Linux x86_64: ユーザー空間は 0x00000000 ~ 0x00007fffffffffff
    if (addr_val < 0x1000 || addr_val >= 0x800000000000ULL) {
        if (stats) stats->addr_invalid_range++;
        return VERIFY_ADDR_INVALID_RANGE;
    }
    
    // 4. ページアライメントチェック
    if (addr_val % PAGE_SIZE != 0) {
        if (stats) stats->addr_misaligned++;
        return VERIFY_ADDR_MISALIGNED;
    }
    
    // 5. アドレスコピー1の一致チェック
    if (block->addr != block->addr_copy1) {
        if (stats) stats->addr_copy_mismatch++;
        return VERIFY_ADDR_COPY1_MISMATCH;
    }
    
    // 6. アドレスコピー2の一致チェック
    if (block->addr != block->addr_copy2) {
        if (stats) stats->addr_copy_mismatch++;
        return VERIFY_ADDR_COPY2_MISMATCH;
    }
    
    // 7. サイズチェック
    if (block->size != PAGE_SIZE) {
        if (stats) stats->size_wrong++;
        return VERIFY_SIZE_WRONG;
    }
    
    // 8. インデックスの自己参照チェック
    if (block->index != index) {
        if (stats) stats->index_mismatch++;
        return VERIFY_INDEX_MISMATCH;
    }
    
    // 9. タイムスタンプの妥当性チェック
    // タイムスタンプは現在時刻より未来ではない、かつ0ではない
    if (block->timestamp == 0 || block->timestamp > get_timestamp()) {
        if (stats) stats->timestamp_invalid++;
        return VERIFY_TIMESTAMP_INVALID;
    }
    
    // 10. チェックサム1の検証
    uint64_t expected_checksum1 = compute_checksum_fnv1a(block->addr, block->size, block->index);
    if (block->checksum1 != expected_checksum1) {
        if (stats) stats->checksum1_mismatch++;
        return VERIFY_CHECKSUM1_MISMATCH;
    }
    
    // 11. チェックサム2の検証
    uint64_t expected_checksum2 = compute_checksum_custom(block->addr, block->size, block->index);
    if (block->checksum2 != expected_checksum2) {
        if (stats) stats->checksum2_mismatch++;
        return VERIFY_CHECKSUM2_MISMATCH;
    }
    
    return VERIFY_OK;
}

// ★★★ シンプルな検証（統計不要） ★★★
int verify_mem_block_entry(size_t index) {
    return verify_mem_block_entry_detailed(index, NULL) == VERIFY_OK;
}

// =============================================================================
// Utility functions
// =============================================================================

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
        printf("ERROR: Exceeded maximum blocks (%zu)\n", block_capacity);
        return;
    }
    
    // ★★★ 厳密な事前チェック ★★★
    if (addr == NULL) {
        printf("CRITICAL ERROR: malloc returned NULL at block %zu\n", block_count);
        printf("This is a malloc failure, not BadRAM corruption.\n");
        return;
    }
    
    // アドレス範囲チェック
    uintptr_t addr_val = (uintptr_t)addr;
    if (addr_val < 0x1000 || addr_val >= 0x800000000000ULL) {
        printf("CRITICAL ERROR: malloc returned invalid address %p at block %zu\n", 
               addr, block_count);
        free(addr);
        return;
    }
    
    // ページアライメントチェック
    if (addr_val % PAGE_SIZE != 0) {
        printf("WARNING: malloc returned non-page-aligned address %p at block %zu\n",
               addr, block_count);
        // これは正常な場合もあるが、念のため記録
    }
    
    // ★★★ 完全な冗長情報で初期化 ★★★
    uint64_t timestamp = get_timestamp();
    
    mem_blocks[block_count].magic_start = MEMBLOCK_MAGIC_START;
    mem_blocks[block_count].addr = addr;
    mem_blocks[block_count].size = size;
    mem_blocks[block_count].addr_copy1 = addr;
    mem_blocks[block_count].addr_copy2 = addr;
    mem_blocks[block_count].index = block_count;
    mem_blocks[block_count].timestamp = timestamp;
    mem_blocks[block_count].checksum1 = compute_checksum_fnv1a(addr, size, block_count);
    mem_blocks[block_count].checksum2 = compute_checksum_custom(addr, size, block_count);
    mem_blocks[block_count].magic_end = MEMBLOCK_MAGIC_END;
    
    block_count++;
}

// =============================================================================
// Mapping table functions
// =============================================================================

void init_mapping_table(MappingTable *table) {
    table->capacity = 100000;
    table->count = 0;
    table->mappings = malloc(sizeof(PhysMapping) * table->capacity);
    if (!table->mappings) {
        perror("Memory allocation failed");
        exit(1);
    }
}

void add_mapping(MappingTable *table, uint64_t phys_addr,
                 unsigned long virt_addr, pid_t pid, const char *comm) {
    if (table->count >= table->capacity) {
        table->capacity *= 2;
        table->mappings = realloc(table->mappings,
                                  sizeof(PhysMapping) * table->capacity);
        if (!table->mappings) {
            perror("Memory reallocation failed");
            exit(1);
        }
    }
    
    PhysMapping *m = &table->mappings[table->count];
    m->phys_addr = phys_addr;
    m->virt_addr = virt_addr;
    m->pid = pid;
    strncpy(m->comm, comm, sizeof(m->comm) - 1);
    m->comm[sizeof(m->comm) - 1] = '\0';
    
    table->count++;
}

void get_process_name(pid_t pid, char *name, size_t size) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    
    FILE *fp = fopen(path, "r");
    if (fp) {
        if (fgets(name, size, fp)) {
            size_t len = strlen(name);
            if (len > 0 && name[len-1] == '\n') {
                name[len-1] = '\0';
            }
        }
        fclose(fp);
    } else {
        snprintf(name, size, "unknown");
    }
}

int compare_mappings(const void *a, const void *b) {
    uint64_t phys_a = ((PhysMapping *)a)->phys_addr;
    uint64_t phys_b = ((PhysMapping *)b)->phys_addr;
    if (phys_a < phys_b) return -1;
    if (phys_a > phys_b) return 1;
    return 0;
}

void search_physical_address_bsearch(MappingTable *table, uint64_t target_phys) {
    uint64_t target_page_start = (target_phys / PAGE_SIZE) * PAGE_SIZE;
    
    PhysMapping key;
    key.phys_addr = target_page_start;
    
    PhysMapping *found = bsearch(&key, table->mappings, table->count,
                                 sizeof(PhysMapping), compare_mappings);
    
    if (found) {
        printf("      -> PID %d (%s), Virtual: 0x%lx\n",
               found->pid, found->comm, found->virt_addr);
    } else {
        printf("      -> Unused or swapped out\n");
    }
}

int get_pfn_for_range(pid_t pid, unsigned long vaddr_start, unsigned long vaddr_end,
                      MappingTable *table, const char *comm) {
    char pagemap_path[256];
    snprintf(pagemap_path, sizeof(pagemap_path), "/proc/%d/pagemap", pid);
    
    int fd = open(pagemap_path, O_RDONLY);
    if (fd < 0) return -1;
    
    for (unsigned long vaddr = vaddr_start; vaddr < vaddr_end; vaddr += PAGE_SIZE) {
        uint64_t offset = (vaddr / PAGE_SIZE) * sizeof(uint64_t);
        
        if (lseek(fd, offset, SEEK_SET) < 0) {
            continue;
        }
        
        uint64_t entry;
        if (read(fd, &entry, sizeof(uint64_t)) != sizeof(uint64_t)) {
            continue;
        }
        
        if (entry & PM_PRESENT) {
            uint64_t pfn = entry & PM_PFN_MASK;
            uint64_t phys_addr = pfn * PAGE_SIZE;
            
            pthread_mutex_lock(&g_mapping_mutex);
            add_mapping(table, phys_addr, vaddr, pid, comm);
            pthread_mutex_unlock(&g_mapping_mutex);
        }
    }
    
    close(fd);
    return 0;
}

// =============================================================================
// Parallel processing (process scanning)
// =============================================================================

void *scan_worker(void *arg) {
    ScanThreadData *data = (ScanThreadData *)arg;
    char maps_path[256];
    char comm[256];
    
    for (size_t i = 0; i < data->pid_count; i++) {
        pid_t pid = data->pids[i];
        
        get_process_name(pid, comm, sizeof(comm));
        
        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
        FILE *maps_fp = fopen(maps_path, "r");
        if (!maps_fp) {
            pthread_mutex_lock(&g_mapping_mutex);
            g_processed_procs_count++;
            pthread_mutex_unlock(&g_mapping_mutex);
            continue;
        }
        
        char line[512];
        while (fgets(line, sizeof(line), maps_fp)) {
            unsigned long vaddr_start, vaddr_end;
            
            if (sscanf(line, "%lx-%lx", &vaddr_start, &vaddr_end) == 2) {
                get_pfn_for_range(pid, vaddr_start, vaddr_end, data->table, comm);
            }
        }
        
        fclose(maps_fp);
        
        pthread_mutex_lock(&g_mapping_mutex);
        g_processed_procs_count++;
        pthread_mutex_unlock(&g_mapping_mutex);
    }
    return NULL;
}

void scan_all_processes_parallel(MappingTable *table) {
    DIR *proc_dir = opendir("/proc");
    if (!proc_dir) {
        perror("Error: Cannot open /proc directory");
        return;
    }
    
    pid_t *pids = NULL;
    size_t pid_count = 0;
    size_t pid_capacity = 1024;
    pids = malloc(sizeof(pid_t) * pid_capacity);
    
    struct dirent *entry;
    while ((entry = readdir(proc_dir)) != NULL) {
        if (isdigit(entry->d_name[0])) {
            if (pid_count >= pid_capacity) {
                pid_capacity *= 2;
                pids = realloc(pids, sizeof(pid_t) * pid_capacity);
            }
            pids[pid_count++] = atoi(entry->d_name);
        }
    }
    closedir(proc_dir);
    
    printf("Total processes: %zu (excluding self PID %d)\n", pid_count, g_self_pid);
    
    int num_threads = get_nprocs();
    if (num_threads > 16) num_threads = 16;
    
    printf("Parallel processing: Scanning all processes with %d threads...\n", num_threads);
    printf("* Only scanning actually mapped ranges from /proc/PID/maps\n\n");
    
    pthread_t threads[num_threads];
    ScanThreadData thread_data[num_threads];
    size_t pids_per_thread = pid_count / num_threads;
    
    g_processed_procs_count = 0;
    
    for (int i = 0; i < num_threads; i++) {
        thread_data[i].table = table;
        thread_data[i].pids = &pids[i * pids_per_thread];
        if (i == num_threads - 1) {
            thread_data[i].pid_count = pid_count - (i * pids_per_thread);
        } else {
            thread_data[i].pid_count = pids_per_thread;
        }
        pthread_create(&threads[i], NULL, scan_worker, &thread_data[i]);
    }
    
    while (g_processed_procs_count < pid_count) {
        int percent = (g_processed_procs_count * 100) / pid_count;
        printf("\rProgress: [");
        int bar_width = 40;
        int filled = (percent * bar_width) / 100;
        for (int i = 0; i < bar_width; i++) {
            printf(i < filled ? "=" : (i == filled ? ">" : " "));
        }
        printf("] %3d%% | %zu/%zu processes | %zu mappings   ",
               percent, (size_t)g_processed_procs_count, pid_count, table->count);
        fflush(stdout);
        usleep(100000);
    }
    
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    free(pids);
    
    printf("\rProgress: [");
    for (int i = 0; i < 40; i++) printf("=");
    printf("] 100%% | %zu/%zu processes | %zu mappings   \n",
           pid_count, pid_count, table->count);
    printf("\nScan complete!\n");
}

void *alias_worker(void *arg) {
    AliasThreadData *data = (AliasThreadData *)arg;
    const uint64_t TEST_PATTERN = 0xDEADBEEFCAFEBABE;

    for (size_t i = data->start_index; i < data->end_index; i++) {
        if (!verify_mem_block_entry(i)) {
            continue;
        }
        
        uint64_t *ptr_i = (uint64_t *)mem_blocks[i].addr;
        uint64_t original_value_i = *ptr_i;
        *ptr_i = TEST_PATTERN;

        for (size_t j = i + 1; j < block_count; j++) {
            if (!verify_mem_block_entry(j)) {
                continue;
            }
            
            uint64_t *ptr_j = (uint64_t *)mem_blocks[j].addr;
            if (*ptr_j == TEST_PATTERN) {
                pthread_mutex_lock(&g_alias_mutex);
                
                g_pairs_found++;
                printf("Alias pair detected (found by thread %lu):\n", pthread_self());
                printf("    - Page %zu (virtual address: %p)\n", i, mem_blocks[i].addr);
                printf("    - Page %zu (virtual address: %p)\n\n", j, mem_blocks[j].addr);
                
                pthread_mutex_unlock(&g_alias_mutex);
            }
        }
        *ptr_i = original_value_i;
    }
    return NULL;
}

// =============================================================================
// Stage 1-3
// =============================================================================

void stage1_allocate_memory() {
    printf("=== Stage 1: Allocate Memory ===\n");
    printf("PID: %d\n", getpid());
    printf("Page size: 0x%x (%d bytes)\n", PAGE_SIZE, PAGE_SIZE);
    
    size_t available_mb = get_available_memory_mb();
    printf("Usable memory: %zu MB (%.2f GB)\n",
           available_mb, (double)available_mb / 1024);
    
    size_t max_safe_mb = available_mb * 70 / 100;
    if (max_safe_mb > 10 * 1024) {
        max_safe_mb = 10 * 1024;
    }
    
    size_t max_pages = (max_safe_mb * MB) / PAGE_SIZE;
    
    if (max_pages > MAX_BLOCKS) {
        printf("Note: Limiting allocation to %d pages due to MAX_BLOCKS constraint\n", MAX_BLOCKS);
        max_pages = MAX_BLOCKS;
    }
    
    printf("Will allocate: max %zu pages (%zu MB, %.2f GB)\n",
           max_pages, (max_pages * PAGE_SIZE) / MB, (double)(max_pages * PAGE_SIZE) / GB);
    
    if (!ask_user("Start allocating memory?")) {
        printf("Skipping Stage 1\n");
        return;
    }
    
    printf("\nAllocating virtual memory with malloc in 0x1000 (4096 bytes) chunks\n");
    printf("Each block includes redundant verification data:\n");
    printf("  - 2 magic numbers (start/end)\n");
    printf("  - 3 copies of address\n");
    printf("  - 2 independent checksums\n");
    printf("  - Self-referential index\n");
    printf("  - Timestamp\n\n");
    
    size_t total_allocated = 0;
    size_t malloc_failures = 0;
    
    for (size_t i = 0; i < max_pages; i++) {
        void *addr = malloc(PAGE_SIZE);
        
        if (addr == NULL) {
            malloc_failures++;
            printf("malloc failed at iteration %zu (total failures: %zu)\n", 
                   i, malloc_failures);
            
            if (malloc_failures >= 10) {
                printf("Too many malloc failures. Stopping allocation.\n");
                break;
            }
            continue;
        }
        
        size_t expected_count = block_count + 1;
        add_mem_block(addr, PAGE_SIZE);
        
        // add_mem_block が実際に追加したか確認
        if (block_count != expected_count) {
            printf("ERROR: add_mem_block failed at iteration %zu\n", i);
            printf("Expected block_count %zu, got %zu\n", expected_count, block_count);
            free(addr);
            break;
        }
        
        total_allocated += PAGE_SIZE;
        
        if ((i + 1) % 10000 == 0) {
            printf("  %zu pages (%zu MB) allocated...\n",
                   block_count, total_allocated / MB);
        }
    }

    printf("\nTotal allocated: %zu pages (%zu MB, %.2f GB)\n",
           block_count, total_allocated / MB, (double)total_allocated / GB);
    
    if (malloc_failures > 0) {
        printf("Note: %zu malloc failures occurred (normal memory pressure)\n", malloc_failures);
    }

    if (ask_user("Check pages with physical addresses >= 0x200000000?")) {
        printf("\nChecking pages with physical addresses >= 0x200000000 (8GB)...\n");

        int high_addr_count = 0;
        int checked_count = 0;
        int max_display = 20;
        
        for (size_t i = 0; i < block_count; i++) {
            if (!verify_mem_block_entry(i)) {
                continue;
            }
            
            void *virt_addr = mem_blocks[i].addr;
            uint64_t phys_addr = get_physical_address(virt_addr);
            
            if (phys_addr > 0) {
                checked_count++;
                if (phys_addr >= PHYSICAL_ADDR_THRESHOLD && PHYSICAL_ADDR_MAXIMAM >= phys_addr) {
                    high_addr_count++;
                    if (high_addr_count <= max_display) {
                        printf("  Page %zu: virtual: %p -> physical: 0x%lx (%.2f GB)\n",
                               i, virt_addr, phys_addr,
                               (double)phys_addr / GB);
                    }
                }
            }
            
            if ((i + 1) % 50000 == 0) {
                printf("  %zu / %zu pages checked (%.1f%%)...\n",
                       i + 1, block_count,
                       100.0 * (i + 1) / block_count);
            }
        }
        
        if (high_addr_count > max_display) {
            printf("  ... (and %d more pages)\n", high_addr_count - max_display);
        }
        
        printf("\nResult:\n");
        printf("  Checked pages: %d\n", checked_count);
        printf("  Pages with physical addresses >= 0x200000000: %d\n", high_addr_count);
        if (checked_count > 0) {
            printf("  Ratio: %.2f%%\n", 100.0 * high_addr_count / checked_count);
        }
    }
}

void stage2_write_pages() {
    printf("\n=== Stage 2: Write Pages ===\n");
    
    if (block_count == 0) {
        printf("No allocated memory.\n");
        return;
    }

    printf("Will write: %zu pages (about %zu MB)\n",
           block_count, block_count * PAGE_SIZE / MB);

    if (!ask_user("Write unique values to each page?")) {
        printf("Skipping Stage 2\n");
        return;
    }

    // ★★★ 完全な整合性チェック ★★★
    printf("\n=== Comprehensive Integrity Verification ===\n");
    printf("Performing multi-layer verification with redundant checks...\n\n");
    
    CorruptionStats stats = {0};
    size_t valid_count = 0;
    size_t corrupt_count = 0;
    
    // 詳細な破損情報を記録
    typedef struct {
        size_t index;
        VerifyResult result;
        MemBlock snapshot;  // 破損時のスナップショット
    } CorruptionRecord;
    
    CorruptionRecord *corruptions = malloc(sizeof(CorruptionRecord) * block_count);
    if (!corruptions) {
        printf("ERROR: Cannot allocate memory for corruption tracking\n");
        return;
    }
    
    for (size_t i = 0; i < block_count; i++) {
        VerifyResult result = verify_mem_block_entry_detailed(i, &stats);
        
        if (result == VERIFY_OK) {
            valid_count++;
        } else {
            corruptions[corrupt_count].index = i;
            corruptions[corrupt_count].result = result;
            corruptions[corrupt_count].snapshot = mem_blocks[i];  // スナップショット保存
            corrupt_count++;
        }
        
        if ((i + 1) % 50000 == 0) {
            printf("  Verified %zu / %zu entries... (valid: %zu, corrupt: %zu)\n", 
                   i + 1, block_count, valid_count, corrupt_count);
        }
    }
    
    printf("\n=== Verification Results ===\n");
    printf("Total entries: %zu\n", block_count);
    printf("Valid entries: %zu (%.2f%%)\n", valid_count, 100.0 * valid_count / block_count);
    printf("Corrupt entries: %zu (%.2f%%)\n", corrupt_count, 100.0 * corrupt_count / block_count);
    
    if (corrupt_count > 0) {
        printf("\n=== Detailed Corruption Analysis ===\n");
        printf("Corruption types breakdown:\n");
        printf("  [1] Magic start corrupted:    %zu\n", stats.magic_start_corrupted);
        printf("  [2] Magic end corrupted:      %zu\n", stats.magic_end_corrupted);
        printf("  [3] Address is NULL:          %zu\n", stats.addr_null);
        printf("  [4] Address invalid range:    %zu\n", stats.addr_invalid_range);
        printf("  [5] Address misaligned:       %zu\n", stats.addr_misaligned);
        printf("  [6] Address copy mismatch:    %zu\n", stats.addr_copy_mismatch);
        printf("  [7] Size incorrect:           %zu\n", stats.size_wrong);
        printf("  [8] Checksum1 mismatch:       %zu\n", stats.checksum1_mismatch);
        printf("  [9] Checksum2 mismatch:       %zu\n", stats.checksum2_mismatch);
        printf("  [10] Index mismatch:          %zu\n", stats.index_mismatch);
        printf("  [11] Timestamp invalid:       %zu\n", stats.timestamp_invalid);
        
        // ★★★ 信頼性分析 ★★★
        printf("\n=== Reliability Analysis ===\n");
        
        // 深刻な破損（マジックナンバーまたはアドレス関連）
        size_t critical_corruption = stats.magic_start_corrupted + 
                                     stats.magic_end_corrupted + 
                                     stats.addr_null + 
                                     stats.addr_invalid_range + 
                                     stats.addr_copy_mismatch;
        
        // 軽度の破損（チェックサムのみ）
        size_t minor_corruption = stats.checksum1_mismatch + stats.checksum2_mismatch;
        
        // その他の破損
        size_t other_corruption = corrupt_count - critical_corruption - minor_corruption;
        
        printf("Critical corruption (high confidence): %zu\n", critical_corruption);
        printf("Minor corruption (checksum only):      %zu\n", minor_corruption);
        printf("Other corruption:                      %zu\n", other_corruption);
        
        double confidence_score = 0.0;
        if (corrupt_count > 0) {
            confidence_score = (double)critical_corruption / corrupt_count * 100.0;
        }
        
        printf("\nBadRAM Detection Confidence: %.1f%%\n", confidence_score);
        
        // ★★★ 判定ロジック ★★★
        if (critical_corruption == 0 && minor_corruption == corrupt_count) {
            printf("\n*** LOW CONFIDENCE: Possible False Positive ***\n");
            printf("All corruptions are checksum-only mismatches.\n");
            printf("This could be:\n");
            printf("  - Hash collision (unlikely but possible)\n");
            printf("  - Timing issue during verification\n");
            printf("  - Memory initialization problem\n");
            printf("Recommendation: Inconclusive for BadRAM detection.\n");
        } else if (critical_corruption > 0) {
            printf("\n***** HIGH CONFIDENCE: BadRAM DETECTED *****\n");
            printf("Detected %zu critical corruptions including:\n", critical_corruption);
            if (stats.magic_start_corrupted > 0) {
                printf("  - %zu magic number corruptions (strong evidence)\n", 
                       stats.magic_start_corrupted + stats.magic_end_corrupted);
            }
            if (stats.addr_null > 0) {
                printf("  - %zu NULL addresses (strong evidence)\n", stats.addr_null);
            }
            if (stats.addr_copy_mismatch > 0) {
                printf("  - %zu address copy mismatches (strong evidence)\n", 
                       stats.addr_copy_mismatch);
            }
            printf("\nPhysical memory aliasing is affecting the .bss section.\n");
            printf("This confirms BadRAM attack presence.\n");
        } else {
            printf("\n*** MODERATE CONFIDENCE: Possible BadRAM ***\n");
            printf("Detected corruptions that don't fit typical patterns.\n");
            printf("Further investigation recommended.\n");
        }
        
        // ★★★ 詳細な破損レポート（最初の20件） ★★★
        printf("\n=== Detailed Corruption Report (first 20) ===\n");
        size_t report_limit = (corrupt_count < 20) ? corrupt_count : 20;
        
        for (size_t i = 0; i < report_limit; i++) {
            CorruptionRecord *rec = &corruptions[i];
            printf("\n[%zu] Index %zu: %s\n", i + 1, rec->index, 
                   verify_result_string(rec->result));
            printf("    Magic start:  0x%016lx (expected: 0x%016lx)\n",
                   rec->snapshot.magic_start, MEMBLOCK_MAGIC_START);
            printf("    Magic end:    0x%016lx (expected: 0x%016lx)\n",
                   rec->snapshot.magic_end, MEMBLOCK_MAGIC_END);
            printf("    Address:      %p\n", rec->snapshot.addr);
            printf("    Address copy1: %p\n", rec->snapshot.addr_copy1);
            printf("    Address copy2: %p\n", rec->snapshot.addr_copy2);
            printf("    Size:         %zu (expected: %d)\n", 
                   rec->snapshot.size, PAGE_SIZE);
            printf("    Index:        %lu (expected: %zu)\n", 
                   rec->snapshot.index, rec->index);
            printf("    Timestamp:    %lu\n", rec->snapshot.timestamp);
            
            if (rec->snapshot.addr != NULL && rec->result != VERIFY_ADDR_NULL) {
                uint64_t expected_cs1 = compute_checksum_fnv1a(
                    rec->snapshot.addr, rec->snapshot.size, rec->index);
                uint64_t expected_cs2 = compute_checksum_custom(
                    rec->snapshot.addr, rec->snapshot.size, rec->index);
                printf("    Checksum1:    0x%016lx (expected: 0x%016lx) %s\n",
                       rec->snapshot.checksum1, expected_cs1,
                       rec->snapshot.checksum1 == expected_cs1 ? "✓" : "✗");
                printf("    Checksum2:    0x%016lx (expected: 0x%016lx) %s\n",
                       rec->snapshot.checksum2, expected_cs2,
                       rec->snapshot.checksum2 == expected_cs2 ? "✓" : "✗");
            }
        }
        
        if (corrupt_count > 20) {
            printf("\n... (and %zu more corruptions)\n", corrupt_count - 20);
        }
        
        // ★★★ パターン分析 ★★★
        printf("\n=== Corruption Pattern Analysis ===\n");
        
        // 連続した破損を検出
        int consecutive_groups = 0;
        int in_group = 0;
        size_t group_start = 0;
        
        for (size_t i = 0; i < corrupt_count; i++) {
            if (i == 0 || corruptions[i].index != corruptions[i-1].index + 1) {
                if (in_group) {
                    consecutive_groups++;
                    if (consecutive_groups <= 5) {
                        printf("  Group %d: indices %zu-%zu (%zu entries)\n",
                               consecutive_groups, group_start, 
                               corruptions[i-1].index,
                               corruptions[i-1].index - group_start + 1);
                    }
                }
                in_group = 1;
                group_start = corruptions[i].index;
            } else {
                in_group = 1;
            }
        }
        if (in_group) {
            consecutive_groups++;
            if (consecutive_groups <= 5) {
                printf("  Group %d: indices %zu-%zu (%zu entries)\n",
                       consecutive_groups, group_start, 
                       corruptions[corrupt_count-1].index,
                       corruptions[corrupt_count-1].index - group_start + 1);
            }
        }
        
        if (consecutive_groups > 5) {
            printf("  ... (and %d more groups)\n", consecutive_groups - 5);
        }
        
        printf("\nTotal consecutive corruption groups: %d\n", consecutive_groups);
        
        if (consecutive_groups > 1) {
            printf("Multiple corruption groups suggest systematic aliasing.\n");
        }
        
        // ★★★ 破損の物理ページ分布 ★★★
        if (corrupt_count > 0 && corrupt_count < 1000) {
            printf("\n=== Physical Page Distribution of Corruptions ===\n");
            printf("Checking if corrupted entries share physical pages...\n");
            
            int phys_check_count = 0;
            for (size_t i = 0; i < corrupt_count && phys_check_count < 10; i++) {
                size_t idx = corruptions[i].index;
                
                // 破損していても addr が有効なら物理アドレスをチェック
                if (corruptions[i].result != VERIFY_ADDR_NULL &&
                    corruptions[i].result != VERIFY_ADDR_INVALID_RANGE) {
                    
                    uint64_t phys = get_physical_address(mem_blocks[idx].addr);
                    if (phys > 0) {
                        printf("  Corrupt index %zu: phys=0x%lx\n", idx, phys);
                        phys_check_count++;
                    }
                }
            }
        }
        
        printf("\n********************************************\n");
        
        // ★★★ ユーザーに続行を確認 ★★★
        if (critical_corruption > 0) {
            printf("CRITICAL: Data structure corruption detected.\n");
            printf("Continuing may cause segmentation faults.\n");
            
            if (!ask_user("Continue writing to valid entries only?")) {
                free(corruptions);
                return;
            }
        } else {
            printf("Minor corruptions detected (checksum mismatches).\n");
            
            if (!ask_user("Continue with valid entries?")) {
                free(corruptions);
                return;
            }
        }
    } else {
        printf("\n✓ All entries passed comprehensive verification.\n");
        printf("No corruption detected in mem_blocks array.\n");
        printf("This suggests:\n");
        printf("  - No BadRAM aliasing affecting .bss section\n");
        printf("  - OR BadRAM is present but hasn't corrupted this array yet\n");
        printf("  - OR corruption timing hasn't aligned with verification\n\n");
    }
    
    free(corruptions);

    printf("\n=== Writing Unique Values to Valid Pages ===\n");
    
    size_t written_count = 0;
    size_t skipped_count = 0;
    size_t write_errors = 0;
    
    for (size_t i = 0; i < block_count; i++) {
        // ★★★ 書き込み直前に再検証 ★★★
        if (!verify_mem_block_entry(i)) {
            skipped_count++;
            continue;
        }
        
        // ★★★ 書き込み試行 ★★★
        uint64_t unique_value = i;
        
        // セグメンテーションフォルトを避けるため、慎重に書き込む
        // （実際にはこれでも完全には防げないが、エラー情報は得られる）
        void *addr = mem_blocks[i].addr;
        
        // 書き込み実行
        *(uint64_t *)addr = unique_value;
        
        // 書き込みが成功したか確認（読み戻し）
        uint64_t read_back = *(uint64_t *)addr;
        if (read_back != unique_value) {
            write_errors++;
            if (write_errors <= 10) {
                printf("WARNING: Write verification failed at index %zu\n", i);
                printf("  Wrote: 0x%lx, Read back: 0x%lx\n", unique_value, read_back);
            }
        }
        
        written_count++;
        
        if (written_count % 100000 == 0) {
            printf("  %zu / %zu valid pages written (%.1f%%)... (skipped %zu)\n",
                   written_count, block_count - skipped_count,
                   100.0 * written_count / (block_count - skipped_count),
                   skipped_count);
        }
    }

    printf("\n=== Write Operation Summary ===\n");
    printf("Total written:       %zu pages\n", written_count);
    printf("Skipped (corrupt):   %zu pages\n", skipped_count);
    printf("Write errors:        %zu pages\n", write_errors);
    
    if (write_errors > 0) {
        printf("\n*** WARNING: Write verification errors detected ***\n");
        printf("Some pages did not retain written values.\n");
        printf("This could indicate:\n");
        printf("  - Memory aliasing causing overwrites\n");
        printf("  - Hardware memory errors\n");
        printf("  - Cache coherency issues\n");
    }
}

void stage3_check_aliases() {
    printf("\n=== Stage 3: Check Aliases ===\n");
    if (block_count < 2) {
        printf("Not enough memory to compare.\n");
        return;
    }

    if (!ask_user("Start a time-consuming scan for alias pairs in parallel?")) {
        printf("Skipping Stage 3.\n");
        return;
    }

    // 事前検証
    printf("\nPerforming pre-scan verification...\n");
    size_t valid_for_scan = 0;
    for (size_t i = 0; i < block_count; i++) {
        if (verify_mem_block_entry(i)) {
            valid_for_scan++;
        }
    }
    
    printf("Valid entries for alias scanning: %zu / %zu (%.1f%%)\n",
           valid_for_scan, block_count, 100.0 * valid_for_scan / block_count);
    
    if (valid_for_scan < 2) {
        printf("ERROR: Not enough valid entries for alias detection.\n");
        return;
    }

    int num_threads = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_threads <= 0) num_threads = 4;
    if (num_threads > 16) num_threads = 16;

    printf("Scanning alias pairs in parallel with %d threads...\n", num_threads);
    printf("(Automatically skipping corrupted entries)\n\n");

    pthread_t threads[num_threads];
    AliasThreadData thread_data[num_threads];
    size_t total_indices = block_count;
    size_t indices_per_thread = total_indices / num_threads;

    g_pairs_found = 0;

    for (int i = 0; i < num_threads; i++) {
        thread_data[i].start_index = i * indices_per_thread;
        if (i == num_threads - 1) {
            thread_data[i].end_index = total_indices;
        } else {
            thread_data[i].end_index = (i + 1) * indices_per_thread;
        }
        pthread_create(&threads[i], NULL, alias_worker, &thread_data[i]);
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("\n=== Alias Detection Results ===\n");
    if (g_pairs_found == 0) {
        printf("✓ No alias pairs found\n");
        printf("\nThis suggests:\n");
        printf("  - No BadRAM aliasing in allocated pages\n");
        printf("  - OR aliases exist but are not in the tested memory range\n");
        printf("  - OR memmap configuration successfully isolated aliases\n");
    } else {
        printf("✗ Found %d alias pair(s)\n", g_pairs_found);
        printf("\n***** ALIASING CONFIRMED *****\n");
        printf("Multiple virtual addresses map to the same physical memory.\n");
        printf("This is strong evidence of BadRAM attack.\n");
    }
}

// =============================================================================
// Stage 4
// =============================================================================

void stage4_offset_tracking() {
    printf("\n=== Stage 4: Offset Tracking ===\n");
    
    if (block_count == 0) {
        printf("No allocated memory.\n");
        return;
    }
    
    g_self_pid = getpid();
    printf("PID of this process: %d\n", g_self_pid);
    printf("Offset value: -0x200008000\n");
    
    if (!ask_user("Start offset tracking?")) {
        printf("Skipping Stage 4.\n");
        return;
    }
    
    pthread_mutex_init(&g_mapping_mutex, NULL);
    pthread_mutex_init(&g_print_mutex, NULL);
    
    printf("\nStep 1: Get physical addresses of this process\n");
    
    PageInfo *page_infos = malloc(block_count * sizeof(PageInfo));
    if (!page_infos) {
        printf("ERROR: Cannot allocate memory for page tracking\n");
        return;
    }
    
    size_t valid_pages = 0;
    
    for (size_t i = 0; i < block_count; i++) {
        if (!verify_mem_block_entry(i)) {
            continue;
        }
        
        uint64_t phys = get_physical_address(mem_blocks[i].addr);
        if (phys > 0) {
            page_infos[valid_pages].phys = phys;
            page_infos[valid_pages].virt = mem_blocks[i].addr;
            valid_pages++;
        }
        
        if ((i + 1) % 50000 == 0) {
            printf("\r  %zu / %zu pages processed", i + 1, block_count);
            fflush(stdout);
        }
    }

    printf("\rValid pages with physical addresses: %zu\n", valid_pages);

    printf("\nStep 2: Scanning all processes...\n");
    MappingTable table;
    init_mapping_table(&table);
    scan_all_processes_parallel(&table);

    printf("\nSorting mapping table (%zu entries)...", table.count);
    fflush(stdout);
    qsort(table.mappings, table.count, sizeof(PhysMapping), compare_mappings);
    printf(" Done\n");

    printf("\nStep 3: Offset calculation and search\n");

    int64_t offset = -0x200008000LL;
    int processed = 0;
    int skipped = 0;
    int display_limit = 20;

    printf("Displaying the first %d results:\n\n", display_limit);

    for (size_t i = 0; i < valid_pages; i++) {
        uint64_t original_phys = page_infos[i].phys;
        void *original_virt = page_infos[i].virt;
        
        int64_t temp_target = (int64_t)original_phys + offset;
        
        if (temp_target < 0) {
            skipped++;
            continue;
        }
        
        uint64_t target_phys = (uint64_t)temp_target;
        
        if (processed < display_limit) {
            printf("  [%d] Virtual: %p, Physical: 0x%lx\n",
                   processed + 1, original_virt, original_phys);
            printf("      After offset: 0x%lx - 0x200008000 = 0x%lx\n",
                   original_phys, target_phys);
            
            search_physical_address_bsearch(&table, target_phys);
            printf("\n");
        }
        
        processed++;
    }
    
    printf("============================================================\n");
    printf("Complete\n");
    printf("  All pages: %zu\n", valid_pages);
    printf("  Processed pages: %d\n", processed);
    printf("  Skipped pages: %d (underflow)\n", skipped);
    
    if (processed > display_limit) {
        printf("\nNote: Displaying only the first %d results due to high volume.\n", display_limit);
    }
    
    free(page_infos);
    free(table.mappings);
    pthread_mutex_destroy(&g_mapping_mutex);
    pthread_mutex_destroy(&g_print_mutex);
}

// =============================================================================
// Main function
// =============================================================================

int main() {
    printf("========================================================================\n");
    printf("  BadRAM Detection Tool - High Confidence Version\n");
    printf("  Multi-layer Verification with Redundant Integrity Checks\n");
    printf("========================================================================\n\n");
    printf("Features:\n");
    printf("  - Dual magic numbers (start/end)\n");
    printf("  - Triple address storage (3 independent copies)\n");
    printf("  - Dual checksums (FNV-1a + custom hash)\n");
    printf("  - Self-referential index verification\n");
    printf("  - Timestamp validation\n");
    printf("  - Comprehensive corruption pattern analysis\n");
    printf("  - False positive detection and filtering\n\n");
    printf("MAX_BLOCKS: %d (%.2f GB max allocation)\n", 
           MAX_BLOCKS, (double)(MAX_BLOCKS * PAGE_SIZE) / GB);
    printf("========================================================================\n\n");
    
    // Stage 1
    stage1_allocate_memory();
    
    // Stage 2
    if (block_count > 0 && ask_user("Proceed to Stage 2?")) {
        stage2_write_pages();
    }
    
    // Stage 3
    if (block_count > 0 && ask_user("Proceed to Stage 3?")) {
        stage3_check_aliases();
    }
    
    // Stage 4
    if (block_count > 0 && ask_user("Proceed to Stage 4 (offset tracking)?")) {
        stage4_offset_tracking();
    }
    
    // Cleanup
    printf("\n=== Cleanup ===\n");
    printf("Freeing %zu allocated pages...\n", block_count);
    
    for (size_t i = 0; i < block_count; i++) {
        if (verify_mem_block_entry(i)) {
            free(mem_blocks[i].addr);
        }
    }
    
    printf("Program terminated successfully.\n");
    printf("========================================================================\n");
    return 0;
}