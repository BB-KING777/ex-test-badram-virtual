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

// Constant definitions
#define PAGE_SIZE 0x1000
#define MB (1024UL * 1024)
#define GB (1024UL * 1024 * 1024)
#define PHYSICAL_ADDR_THRESHOLD 0x200000000UL
#define PHYSICAL_ADDR_MAXIMAM 0x400000000UL
#define MAX_BLOCKS 3000000

// Magic number for corruption detection
#define MEMBLOCK_MAGIC 0x4D454D424C4B3231ULL  // "MEMBLK21"

// pagemap bit flags
#define PM_PRESENT (1ULL << 63)
#define PM_PFN_MASK ((1ULL << 55) - 1)

// Memory block with corruption detection
typedef struct {
    uint64_t magic;       // Magic number
    void *addr;           // Main address
    void *addr_backup;    // Backup address
    size_t size;          // Size
    uint64_t index;       // Self-reference index
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

// Global variables
static MemBlock mem_blocks_static[MAX_BLOCKS];
MemBlock *mem_blocks = mem_blocks_static;
size_t block_count = 0;
size_t block_capacity = MAX_BLOCKS;

pthread_mutex_t g_mapping_mutex;
pthread_mutex_t g_print_mutex;
volatile size_t g_processed_procs_count = 0;
pid_t g_self_pid;

pthread_mutex_t g_alias_mutex = PTHREAD_MUTEX_INITIALIZER;
int g_pairs_found = 0;

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

// Simple verification: checks magic, null, and backup consistency
int verify_mem_block(size_t index) {
    MemBlock *block = &mem_blocks[index];
    
    // Magic number check
    if (block->magic != MEMBLOCK_MAGIC) {
        return 0;
    }
    
    // NULL check
    if (block->addr == NULL) {
        return 0;
    }
    
    // Backup consistency check
    if (block->addr != block->addr_backup) {
        return 0;
    }
    
    // Index self-reference check
    if (block->index != index) {
        return 0;
    }
    
    // Size check
    if (block->size != PAGE_SIZE) {
        return 0;
    }
    
    return 1;
}

void add_mem_block(void *addr, size_t size) {
    if (block_count >= block_capacity) {
        return;
    }
    
    if (addr == NULL) {
        return;
    }
    
    mem_blocks[block_count].magic = MEMBLOCK_MAGIC;
    mem_blocks[block_count].addr = addr;
    mem_blocks[block_count].addr_backup = addr;
    mem_blocks[block_count].size = size;
    mem_blocks[block_count].index = block_count;
    
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

void *alias_worker(void *arg) {
    AliasThreadData *data = (AliasThreadData *)arg;
    const uint64_t TEST_PATTERN = 0xDEADBEEFCAFEBABE;

    for (size_t i = data->start_index; i < data->end_index; i++) {
        if (!verify_mem_block(i)) {
            continue;
        }
        
        uint64_t *ptr_i = (uint64_t *)mem_blocks[i].addr;
        uint64_t original_value_i = *ptr_i;
        *ptr_i = TEST_PATTERN;

        for (size_t j = i + 1; j < block_count; j++) {
            if (!verify_mem_block(j)) {
                continue;
            }
            
            uint64_t *ptr_j = (uint64_t *)mem_blocks[j].addr;
            if (*ptr_j == TEST_PATTERN) {
                pthread_mutex_lock(&g_alias_mutex);
                
                g_pairs_found++;
                printf("Alias detected: Page %zu (%p) <-> Page %zu (%p)\n",
                       i, mem_blocks[i].addr, j, mem_blocks[j].addr);
                
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
    
    if (max_pages > MAX_BLOCKS) {
        max_pages = MAX_BLOCKS;
    }
    
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
            if (!verify_mem_block(i)) {
                continue;
            }
            
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

void stage2_write_pages() {
    printf("\n=== Stage 2: Write Pages ===\n");
    
    if (block_count == 0) {
        printf("No allocated memory.\n");
        return;
    }

    printf("Will write: %zu pages (%zu MB)\n",
           block_count, block_count * PAGE_SIZE / MB);

    if (!ask_user("Start writing?")) {
        return;
    }

    // Verify integrity first
    printf("\nVerifying integrity...\n");
    
    size_t corrupted = 0;
    int warning_count = 0;
    
    for (size_t i = 0; i < block_count; i++) {
        if (!verify_mem_block(i)) {
            corrupted++;
            if (warning_count < 10) {
                MemBlock *block = &mem_blocks[i];
                printf("  WARNING: Corruption at index %zu\n", i);
                printf("    magic: 0x%lx (expected 0x%lx)\n", 
                       block->magic, MEMBLOCK_MAGIC);
                printf("    addr: %p, backup: %p\n", 
                       block->addr, block->addr_backup);
                warning_count++;
            }
        }
        
        if ((i + 1) % 50000 == 0) {
            printf("  Verified %zu / %zu\n", i + 1, block_count);
        }
    }
    
    if (warning_count == 10 && corrupted > 10) {
        printf("  ... and %zu more corruptions\n", corrupted - 10);
    }
    
    printf("\nVerification result:\n");
    printf("  Valid: %zu (%.2f%%)\n", 
           block_count - corrupted, 100.0 * (block_count - corrupted) / block_count);
    printf("  Corrupted: %zu (%.2f%%)\n", 
           corrupted, 100.0 * corrupted / block_count);
    
    if (corrupted > 0) {
        printf("\n*** BadRAM DETECTED ***\n");
        printf("Memory corruption indicates physical aliasing.\n");
        
        if (!ask_user("Continue with valid entries?")) {
            return;
        }
    }

    printf("\nWriting to valid pages...\n");
    
    size_t written = 0;
    size_t skipped = 0;
    
    for (size_t i = 0; i < block_count; i++) {
        if (!verify_mem_block(i)) {
            skipped++;
            continue;
        }
        
        uint64_t unique_value = i;
        *(uint64_t *)(mem_blocks[i].addr) = unique_value;
        written++;
        
        if (written % 100000 == 0) {
            printf("  Written %zu pages (skipped %zu)\n", written, skipped);
        }
    }

    printf("\nWrite complete: %zu written, %zu skipped\n", written, skipped);
}

void stage3_check_aliases() {
    printf("\n=== Stage 3: Check Aliases ===\n");
    
    if (block_count < 2) {
        printf("Not enough memory.\n");
        return;
    }

    if (!ask_user("Start alias scan?")) {
        return;
    }

    int num_threads = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_threads <= 0) num_threads = 4;
    if (num_threads > 16) num_threads = 16;

    printf("Scanning with %d threads...\n", num_threads);

    pthread_t threads[num_threads];
    AliasThreadData thread_data[num_threads];
    size_t indices_per_thread = block_count / num_threads;

    g_pairs_found = 0;

    for (int i = 0; i < num_threads; i++) {
        thread_data[i].start_index = i * indices_per_thread;
        if (i == num_threads - 1) {
            thread_data[i].end_index = block_count;
        } else {
            thread_data[i].end_index = (i + 1) * indices_per_thread;
        }
        pthread_create(&threads[i], NULL, alias_worker, &thread_data[i]);
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("\nResult: ");
    if (g_pairs_found == 0) {
        printf("No aliases found\n");
    } else {
        printf("%d alias pair(s) found\n", g_pairs_found);
        printf("*** BadRAM CONFIRMED ***\n");
    }
}

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
        if (!verify_mem_block(i)) {
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
    int found = 0;

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
    printf("BadRAM Detection Tool\n");
    printf("=====================\n\n");
    
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
        if (verify_mem_block(i)) {
            free(mem_blocks[i].addr);
        }
    }
    
    printf("Done.\n");
    return 0;
}
