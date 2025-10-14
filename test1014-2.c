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

// Constant definitions
#define PAGE_SIZE 0x1000
#define MB (1024UL * 1024)
#define GB (1024UL * 1024 * 1024)
#define PHYSICAL_ADDR_THRESHOLD 0x200000000UL
#define PHYSICAL_ADDR_MAXIMAM 0x400000000UL

// pagemap bit flags
#define PM_PRESENT (1ULL << 63)
#define PM_PFN_MASK ((1ULL << 55) - 1)

// Memory block
typedef struct {
    void *addr;
    size_t size;
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

typedef struct {
    size_t start_index;
    size_t end_index;
} AliasThreadData;

typedef struct {
    size_t *valid_indices;  // 有効なインデックスの配列
    size_t start_index;     // valid_indices内の開始位置
    size_t end_index;       // valid_indices内の終了位置
    size_t valid_count;     // 有効なインデックスの総数
} AliasThreadDataV2;

// Global variables
MemBlock *mem_blocks = NULL;
size_t block_count = 0;
size_t block_capacity = 0;

pthread_mutex_t g_mapping_mutex;
pthread_mutex_t g_print_mutex;
volatile size_t g_processed_procs_count = 0;
pid_t g_self_pid;

pthread_mutex_t g_alias_mutex = PTHREAD_MUTEX_INITIALIZER;
int g_pairs_found = 0;

// Signal handling for safe memory access testing
static sigjmp_buf segv_jmp_buf;
static volatile sig_atomic_t segv_occurred = 0;

void segv_handler(int sig) {
    segv_occurred = 1;
    siglongjmp(segv_jmp_buf, 1);
}

// =============================================================================
// Address validation functions
// =============================================================================

// Check if address is in valid user space range
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

// Check if address is accessible (can read/write without segfault)
int is_address_accessible(void *addr, size_t size) {
    struct sigaction sa, old_sa;
    int result = 1;
    
    // Setup signal handler
    sa.sa_handler = segv_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    
    if (sigaction(SIGSEGV, &sa, &old_sa) == -1) {
        return 0;
    }
    
    segv_occurred = 0;
    
    // Try to read and write
    if (sigsetjmp(segv_jmp_buf, 1) == 0) {
        volatile uint8_t *ptr = (volatile uint8_t *)addr;
        
        // Test read at start
        volatile uint8_t dummy = ptr[0];
        
        // Test write at start
        uint8_t original = ptr[0];
        ptr[0] = 0xAA;
        ptr[0] = original;
        
        // Test at end of range
        dummy = ptr[size - 1];
        
        (void)dummy;
    } else {
        result = 0;
    }
    
    // Restore original handler
    sigaction(SIGSEGV, &old_sa, NULL);
    
    return result && !segv_occurred;
}

// Comprehensive address validation
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
    // 1. NULL check
    if (addr == NULL) {
        return ADDR_NULL;
    }
    
    // 2. Range check
    if (!is_valid_user_address(addr)) {
        return ADDR_OUT_OF_RANGE;
    }
    
    // 3. Accessibility check (most important)
    if (!is_address_accessible(addr, size)) {
        return ADDR_NOT_ACCESSIBLE;
    }
    
    return ADDR_VALID;
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
// Parallel processing
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
    
    printf("Total processes: %zu\n", pid_count);
    
    int num_threads = get_nprocs();
    if (num_threads > 16) num_threads = 16;
    
    printf("Scanning with %d threads...\n", num_threads);
    
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
        printf("\rProgress: %3d%% | %zu/%zu processes",
               percent, (size_t)g_processed_procs_count, pid_count);
        fflush(stdout);
        usleep(100000);
    }
    
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    free(pids);
    printf("\rProgress: 100%% | %zu/%zu processes\n", pid_count, pid_count);
}


void *alias_worker_v2(void *arg) {
    AliasThreadDataV2 *data = (AliasThreadDataV2 *)arg;
    const uint64_t TEST_PATTERN = 0xDEADBEEFCAFEBABE;

    // valid_indicesを使って有効なページのみスキャン
    for (size_t idx_i = data->start_index; idx_i < data->end_index; idx_i++) {
        size_t i = data->valid_indices[idx_i];  // 実際のインデックス
        
        void *addr_i = mem_blocks[i].addr;
        
        // ダブルチェック（念のため）
        if (addr_i == NULL) continue;
        
        uintptr_t addr_val = (uintptr_t)addr_i;
        if (addr_val < 0x1000 || addr_val >= 0x800000000000ULL) {
            continue;
        }
        
        // シグナルハンドラ設定
        struct sigaction sa, old_sa;
        sa.sa_handler = segv_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        
        if (sigaction(SIGSEGV, &sa, &old_sa) == -1) {
            continue;
        }
        
        segv_occurred = 0;
        
        if (sigsetjmp(segv_jmp_buf, 1) == 0) {
            volatile uint64_t *ptr_i = (volatile uint64_t *)addr_i;
            uint64_t original_value_i = *ptr_i;
            *ptr_i = TEST_PATTERN;
            
            // 内側のループも有効なインデックスのみ
            for (size_t idx_j = idx_i + 1; idx_j < data->valid_count; idx_j++) {
                size_t j = data->valid_indices[idx_j];
                
                void *addr_j = mem_blocks[j].addr;
                
                // ダブルチェック
                if (addr_j == NULL) continue;
                
                uintptr_t addr_val_j = (uintptr_t)addr_j;
                if (addr_val_j < 0x1000 || addr_val_j >= 0x800000000000ULL) {
                    continue;
                }
                
                volatile uint64_t *ptr_j = (volatile uint64_t *)addr_j;
                
                // 読み取り時もSegFault保護
                segv_occurred = 0;
                if (sigsetjmp(segv_jmp_buf, 1) == 0) {
                    if (*ptr_j == TEST_PATTERN) {
                        pthread_mutex_lock(&g_alias_mutex);
                        g_pairs_found++;
                        printf("Alias detected: Page %zu (%p) <-> Page %zu (%p)\n",
                               i, addr_i, j, addr_j);
                        pthread_mutex_unlock(&g_alias_mutex);
                    }
                } else {
                    // 読み取り時にSegFault（スキップ）
                }
            }
            
            // 元の値を復元
            *ptr_i = original_value_i;
        } else {
            // 外側のループでSegFault（スキップ）
        }
        
        sigaction(SIGSEGV, &old_sa, NULL);
    }
    return NULL;
}

/*
void *alias_worker(void *arg) {
    AliasThreadData *data = (AliasThreadData *)arg;
    const uint64_t TEST_PATTERN = 0xDEADBEEFCAFEBABE;

    for (size_t i = data->start_index; i < data->end_index && i < block_count; i++) {
        // 範囲チェック
        if (i >= block_count) {
            break;
        }
        
        // インデックスiの検証
        AddressValidation val_i = validate_address(mem_blocks[i].addr, PAGE_SIZE);
        if (val_i != ADDR_VALID) {
            continue;
        }
        
        // より安全なポインタアクセス
        volatile uint64_t *ptr_i = NULL;
        struct sigaction sa, old_sa;
        sa.sa_handler = segv_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        
        if (sigaction(SIGSEGV, &sa, &old_sa) == -1) {
            continue;
        }
        
        segv_occurred = 0;
        
        if (sigsetjmp(segv_jmp_buf, 1) == 0) {
            ptr_i = (volatile uint64_t *)mem_blocks[i].addr;
            uint64_t original_value_i = *ptr_i;
            *ptr_i = TEST_PATTERN;
            
            // 内側のループも保護
            for (size_t j = i + 1; j < block_count; j++) {
                if (j >= block_count) break;
                
                AddressValidation val_j = validate_address(mem_blocks[j].addr, PAGE_SIZE);
                if (val_j != ADDR_VALID) {
                    continue;
                }
                
                volatile uint64_t *ptr_j = (volatile uint64_t *)mem_blocks[j].addr;
                
                // セグフォルト保護付きで読み取り
                segv_occurred = 0;
                if (sigsetjmp(segv_jmp_buf, 1) == 0) {
                    if (*ptr_j == TEST_PATTERN) {
                        pthread_mutex_lock(&g_alias_mutex);
                        g_pairs_found++;
                        printf("Alias detected: Page %zu (%p) <-> Page %zu (%p)\n",
                               i, mem_blocks[i].addr, j, mem_blocks[j].addr);
                        pthread_mutex_unlock(&g_alias_mutex);
                    }
                } else {
                    // セグフォルト発生、スキップ
                }
            }
            
            // 元の値を復元
            *ptr_i = original_value_i;
        } else {
            // セグフォルト発生
        }
        
        sigaction(SIGSEGV, &old_sa, NULL);
    }
    return NULL;
}*/

// =============================================================================
// Stage 1
// =============================================================================

void stage1_allocate_memory() {
    printf("\n=== Stage 1: Allocate Memory ===\n");
    printf("PID: %d\n", getpid());
    
    size_t available_mb = get_available_memory_mb();
    printf("Available memory: %zu MB (%.2f GB)\n",
           available_mb, (double)available_mb / 1024);
    
    size_t max_safe_mb = available_mb * 70 / 100;
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

// =============================================================================
// Stage 2: Write Pages with validation
// =============================================================================

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

    // ========================================
    // Pre-write validation
    // ========================================
    printf("\nValidating all addresses before writing...\n");
    
    typedef struct {
        size_t index;
        AddressValidation error;
        void *addr;
    } ValidationError;
    
    ValidationError *errors = malloc(sizeof(ValidationError) * block_count);
    size_t error_count = 0;
    
    size_t null_count = 0;
    size_t range_count = 0;
    size_t access_count = 0;
    
    for (size_t i = 0; i < block_count; i++) {
        AddressValidation result = validate_address(mem_blocks[i].addr, PAGE_SIZE);
        
        if (result != ADDR_VALID) {
            // Record error details
            if (error_count < block_count) {
                errors[error_count].index = i;
                errors[error_count].error = result;
                errors[error_count].addr = mem_blocks[i].addr;
                error_count++;
            }
            
            // Count by type
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
    // Display validation results
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
        
        // Display first 10 errors
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
        
        // BadRAM detection
        if (null_count > 0 || access_count > 0) {
            printf("\n*** BadRAM DETECTED ***\n");
            printf("Memory corruption detected in mem_blocks array.\n");
            printf("This indicates physical memory aliasing.\n");
        }
        
        if (!ask_user("Continue with valid addresses only?")) {
            free(errors);
            return;
        }
    } else {
        printf("\n✓ All addresses are valid\n");
    }

    // ========================================
    // Write with validation
    // ========================================
    printf("\nWriting unique values to each page...\n");
    
    size_t written = 0;
    size_t skipped = 0;
    size_t write_errors = 0;
    
    for (size_t i = 0; i < block_count; i++) {
        // Re-validate before writing (in case corruption happened during validation)
        AddressValidation validation = validate_address(mem_blocks[i].addr, PAGE_SIZE);
        
        if (validation != ADDR_VALID) {
            skipped++;
            continue;
        }
        
        // Write unique value
        uint64_t unique_value = i;
        
        // Use signal handler to catch any unexpected segfaults
        struct sigaction sa, old_sa;
        sa.sa_handler = segv_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGSEGV, &sa, &old_sa);
        
        segv_occurred = 0;
        
        if (sigsetjmp(segv_jmp_buf, 1) == 0) {
            *(uint64_t *)(mem_blocks[i].addr) = unique_value;
            
            // Verify write
            uint64_t read_back = *(uint64_t *)(mem_blocks[i].addr);
            if (read_back != unique_value) {
                write_errors++;
                if (write_errors <= 10) {
                    printf("  WARNING: Write verification failed at index %zu\n", i);
                    printf("    Wrote: 0x%lx, Read: 0x%lx\n", unique_value, read_back);
                }
            }
            
            written++;
        } else {
            // Unexpected segfault during write
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

    printf("\n=== Write Summary ===\n");
    printf("  Successfully written: %zu\n", written);
    printf("  Skipped (invalid): %zu\n", skipped);
    printf("  Write errors: %zu\n", write_errors);
    
    if (write_errors > 0) {
        printf("\n*** WARNING: Write verification errors detected ***\n");
        printf("Some pages did not retain written values.\n");
        printf("This may indicate memory aliasing or corruption.\n");
    }
    
    free(errors);
}

// =============================================================================
// Stage 3
// =============================================================================

void stage3_check_aliases() {
    printf("\n=== Stage 3: Check Aliases ===\n");
    
    if (block_count < 2) {
        printf("Not enough memory.\n");
        return;
    }

    if (!ask_user("Start alias scan?")) {
        return;
    }

    // ========================================
    // 新規追加: 事前検証フェーズ
    // ========================================
    printf("\n--- Pre-scan Validation ---\n");
    printf("Validating all addresses before alias scan...\n");
    
    // 有効なインデックスのリストを作成
    size_t *valid_indices = malloc(block_count * sizeof(size_t));
    if (!valid_indices) {
        perror("Failed to allocate valid_indices");
        return;
    }
    
    size_t valid_count = 0;
    size_t null_count = 0;
    size_t range_count = 0;
    size_t access_count = 0;
    
    for (size_t i = 0; i < block_count; i++) {
        void *addr = mem_blocks[i].addr;
        
        // 1. NULLチェック
        if (addr == NULL) {
            null_count++;
            continue;
        }
        
        // 2. 範囲チェック
        uintptr_t addr_val = (uintptr_t)addr;
        if (addr_val < 0x1000 || addr_val >= 0x800000000000ULL) {
            range_count++;
            continue;
        }
        
        // 3. アクセス可能性チェック（軽量版）
        struct sigaction sa, old_sa;
        sa.sa_handler = segv_handler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGSEGV, &sa, &old_sa);
        
        segv_occurred = 0;
        int accessible = 1;
        
        if (sigsetjmp(segv_jmp_buf, 1) == 0) {
            // 読み書きテスト
            volatile uint8_t *ptr = (volatile uint8_t *)addr;
            volatile uint8_t dummy = ptr[0];
            uint8_t original = ptr[0];
            ptr[0] = 0x55;
            ptr[0] = original;
            (void)dummy;
        } else {
            accessible = 0;
            access_count++;
        }
        
        sigaction(SIGSEGV, &old_sa, NULL);
        
        // アクセス可能なら有効リストに追加
        if (accessible) {
            valid_indices[valid_count] = i;
            valid_count++;
        }
        
        // 進捗表示
        if ((i + 1) % 100000 == 0) {
            printf("  Validated %zu / %zu (valid: %zu)\n", i + 1, block_count, valid_count);
        }
    }
    
    printf("\n--- Validation Results ---\n");
    printf("  Total pages: %zu\n", block_count);
    printf("  Valid pages: %zu (%.2f%%)\n", 
           valid_count, 100.0 * valid_count / block_count);
    printf("  Invalid pages: %zu\n", block_count - valid_count);
    printf("    NULL pointers: %zu\n", null_count);
    printf("    Out of range: %zu\n", range_count);
    printf("    Not accessible: %zu\n", access_count);
    
    if (null_count > 0 || access_count > 0) {
        printf("\n*** BadRAM DETECTED (Pre-scan) ***\n");
        printf("Memory corruption detected in mem_blocks array.\n");
        printf("This indicates physical memory aliasing.\n");
    }
    
    if (valid_count < 2) {
        printf("\nNot enough valid pages for alias scan.\n");
        free(valid_indices);
        return;
    }
    
    printf("\nProceeding with alias scan using %zu valid pages...\n", valid_count);

    // ========================================
    // マルチスレッドでエイリアススキャン
    // ========================================
    int num_threads = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_threads <= 0) num_threads = 4;
    if (num_threads > 16) num_threads = 16;

    printf("Scanning with %d threads...\n", num_threads);

    // スレッドデータ構造を修正版に変更
    typedef struct {
        size_t *valid_indices;  // 有効なインデックスの配列
        size_t start_index;     // valid_indices内の開始位置
        size_t end_index;       // valid_indices内の終了位置
        size_t valid_count;     // 有効なインデックスの総数
    } AliasThreadDataV2;

    pthread_t threads[num_threads];
    AliasThreadDataV2 thread_data[num_threads];
    size_t indices_per_thread = valid_count / num_threads;

    g_pairs_found = 0;

    for (int i = 0; i < num_threads; i++) {
        thread_data[i].valid_indices = valid_indices;
        thread_data[i].valid_count = valid_count;
        thread_data[i].start_index = i * indices_per_thread;
        if (i == num_threads - 1) {
            thread_data[i].end_index = valid_count;
        } else {
            thread_data[i].end_index = (i + 1) * indices_per_thread;
        }
        pthread_create(&threads[i], NULL, alias_worker_v2, &thread_data[i]);
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    free(valid_indices);

    printf("\nResult: ");
    if (g_pairs_found == 0) {
        printf("No aliases found\n");
    } else {
        printf("%d alias pair(s) found\n", g_pairs_found);
        printf("*** BadRAM CONFIRMED ***\n");
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
    printf("PID: %d\n", g_self_pid);
    
    if (!ask_user("Start offset tracking?")) {
        return;
    }
    
    pthread_mutex_init(&g_mapping_mutex, NULL);
    pthread_mutex_init(&g_print_mutex, NULL);
    
    printf("\nGetting physical addresses...\n");
    
    PageInfo *page_infos = malloc(block_count * sizeof(PageInfo));
    if (!page_infos) {
        return;
    }
    
    size_t valid_pages = 0;
    
    for (size_t i = 0; i < block_count; i++) {
        // Validate address before accessing
        if (validate_address(mem_blocks[i].addr, PAGE_SIZE) != ADDR_VALID) {
            continue;
        }
        
        uint64_t phys = get_physical_address(mem_blocks[i].addr);
        if (phys > 0) {
            page_infos[valid_pages].phys = phys;
            page_infos[valid_pages].virt = mem_blocks[i].addr;
            valid_pages++;
        }
        
        if ((i + 1) % 50000 == 0) {
            printf("  %zu / %zu processed\n", i + 1, block_count);
        }
    }

    printf("Valid pages: %zu\n", valid_pages);

    printf("\nScanning processes...\n");
    MappingTable table;
    init_mapping_table(&table);
    scan_all_processes_parallel(&table);

    printf("\nSorting mappings...\n");
    qsort(table.mappings, table.count, sizeof(PhysMapping), compare_mappings);

    printf("\nSearching with offset -0x200008000...\n");

    int64_t offset = -0x200008000LL;
    int processed = 0;

    for (size_t i = 0; i < valid_pages && processed < 20; i++) {
        uint64_t original_phys = page_infos[i].phys;
        void *original_virt = page_infos[i].virt;
        
        int64_t temp_target = (int64_t)original_phys + offset;
        if (temp_target < 0) {
            continue;
        }
        
        uint64_t target_phys = (uint64_t)temp_target;
        
        printf("  [%d] Virtual: %p, Physical: 0x%lx\n",
               processed + 1, original_virt, original_phys);
        printf("      Target: 0x%lx\n", target_phys);
        
        search_physical_address_bsearch(&table, target_phys);
        printf("\n");
        
        processed++;
    }
    
    printf("Displayed first %d results\n", processed);
    
    free(page_infos);
    free(table.mappings);
    pthread_mutex_destroy(&g_mapping_mutex);
    pthread_mutex_destroy(&g_print_mutex);
}

// =============================================================================
// Main
// =============================================================================

int main() {
    printf("========================================\n");
    printf("  BadRAM Detection Tool\n");
    printf("  With Address Validation\n");
    printf("========================================\n\n");
    
    printf("Features:\n");
    printf("  - Pre-write address validation\n");
    printf("  - Safe memory access testing\n");
    printf("  - SIGSEGV protection\n");
    printf("  - Detailed corruption analysis\n\n");
    
    stage1_allocate_memory();
    
    if (block_count > 0 && ask_user("Proceed to Stage 2?")) {
        stage2_write_pages();
    }
    
    if (block_count > 0 && ask_user("Proceed to Stage 3?")) {
        stage3_check_aliases();
    }
    
    if (block_count > 0 && ask_user("Proceed to Stage 4?")) {
        stage4_offset_tracking();
    }
    
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