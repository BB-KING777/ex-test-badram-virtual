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

// Global variables
MemBlock *mem_blocks = NULL;
size_t block_count = 0;
size_t block_capacity = 0;

pthread_mutex_t g_mapping_mutex;
pthread_mutex_t g_print_mutex;
volatile size_t g_processed_procs_count = 0;
pid_t g_self_pid;

// Mutex and shared counter for detected pairs
pthread_mutex_t g_alias_mutex = PTHREAD_MUTEX_INITIALIZER;
int g_pairs_found = 0;

// Information passed to each thread
typedef struct {
    size_t start_index; // Start index for outer loop i
    size_t end_index;   // End index for outer loop i
} AliasThreadData;

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

// Get physical addresses for specified range from pagemap (correct method)
int get_pfn_for_range(pid_t pid, unsigned long vaddr_start, unsigned long vaddr_end,
                      MappingTable *table, const char *comm) {
    char pagemap_path[256];
    snprintf(pagemap_path, sizeof(pagemap_path), "/proc/%d/pagemap", pid);
    
    int fd = open(pagemap_path, O_RDONLY);
    if (fd < 0) return -1;
    
    // Process each page in the range
    for (unsigned long vaddr = vaddr_start; vaddr < vaddr_end; vaddr += PAGE_SIZE) {
        uint64_t offset = (vaddr / PAGE_SIZE) * sizeof(uint64_t);
        
        if (lseek(fd, offset, SEEK_SET) < 0) {
            continue;
        }
        
        uint64_t entry;
        if (read(fd, &entry, sizeof(uint64_t)) != sizeof(uint64_t)) {
            continue;
        }
        
        // Check if page exists in physical memory
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
// Parallel processing (process scanning) - correct method
// =============================================================================

void *scan_worker(void *arg) {
    ScanThreadData *data = (ScanThreadData *)arg;
    char maps_path[256];
    char comm[256];
    
    for (size_t i = 0; i < data->pid_count; i++) {
        pid_t pid = data->pids[i];
        
        get_process_name(pid, comm, sizeof(comm));
        
        // Read /proc/PID/maps to get only actually mapped ranges
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
            
            // Parse virtual address range
            if (sscanf(line, "%lx-%lx", &vaddr_start, &vaddr_end) == 2) {
                // Get physical addresses for this range
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
    
    // List up PIDs
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
    
    // Progress display
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

    // Execute loop for assigned range of i
    for (size_t i = data->start_index; i < data->end_index; i++) {
        uint64_t *ptr_i = (uint64_t *)mem_blocks[i].addr;
        uint64_t original_value_i = *ptr_i;
        *ptr_i = TEST_PATTERN;

        for (size_t j = i + 1; j < block_count; j++) {
            uint64_t *ptr_j = (uint64_t *)mem_blocks[j].addr;
            if (*ptr_j == TEST_PATTERN) {
                // Lock to prevent multiple threads from writing simultaneously
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
    
    printf("Will allocate: max %zu pages (%zu MB, %.2f GB)\n",
           max_pages, max_safe_mb, (double)max_safe_mb / 1024);
    
    if (!ask_user("Start allocating memory?")) {
        printf("Skipping Stage 1\n");
        return;
    }
    
    printf("\nAllocating virtual memory with malloc in 0x1000 (4096 bytes) chunks\n");
    
    size_t total_allocated = 0;
    
    for (size_t i = 0; i < max_pages; i++) {
        void *addr = malloc(PAGE_SIZE);
        
        if (addr == NULL) {
            printf("Allocation failed: %zu pages (%zu MB) allocated\n",
                   i, total_allocated / MB);
            break;
        }
        
        add_mem_block(addr, PAGE_SIZE);
        total_allocated += PAGE_SIZE;
        
        if ((i + 1) % 10000 == 0) {
            printf("  %zu pages (%zu MB) allocated...\n",
                   i + 1, total_allocated / MB);
        }
    }

    printf("\nTotal allocated: %zu pages (%zu MB, %.2f GB)\n",
           block_count, total_allocated / MB, (double)total_allocated / GB);

    if (ask_user("Check pages with physical addresses >= 0x200000000?")) {
        printf("\nChecking pages with physical addresses >= 0x200000000 (8GB)...\n");

        int high_addr_count = 0;
        int checked_count = 0;
        int max_display = 20;
        
        for (size_t i = 0; i < block_count; i++) {
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

    printf("\nWriting unique values to each page...\n");
    
    for (size_t i = 0; i < block_count; i++) {
        uint64_t unique_value = i;
        *(uint64_t *)(mem_blocks[i].addr) = unique_value;
        
        if ((i + 1) % 100000 == 0) {
            printf("  %zu / %zu pages written (%.1f%%)...\n",
                   i + 1, block_count,
                   100.0 * (i + 1) / block_count);
        }
    }

    printf("\nTotal written: %zu pages\n", block_count);
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

    // Get the number of CPU cores on the system (default if not available)
    int num_threads = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_threads <= 0) num_threads = 4; // Fallback
    if (num_threads > 16) num_threads = 16; // Set upper limit

    printf("Scanning alias pairs in parallel with %d threads...\n", num_threads);

    pthread_t threads[num_threads];
    AliasThreadData thread_data[num_threads];
    size_t total_indices = block_count;
    size_t indices_per_thread = total_indices / num_threads;

    g_pairs_found = 0; // Reset counter

    // Create threads and assign tasks
    for (int i = 0; i < num_threads; i++) {
        thread_data[i].start_index = i * indices_per_thread;
        if (i == num_threads - 1) {
            // Last thread handles all remaining indices
            thread_data[i].end_index = total_indices;
        } else {
            thread_data[i].end_index = (i + 1) * indices_per_thread;
        }
        pthread_create(&threads[i], NULL, alias_worker, &thread_data[i]);
    }

    // Wait for all threads to finish
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    // Display final results
    if (g_pairs_found == 0) {
        printf("\n✓ No alias pairs found\n");
    } else {
        printf("\n✗ Found %d alias pair(s)\n", g_pairs_found);
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
    
    // Initialize mutexes
    pthread_mutex_init(&g_mapping_mutex, NULL);
    pthread_mutex_init(&g_print_mutex, NULL);
    
    // Step 1: Get physical addresses of this process
    printf("\nStep 1: Get physical addresses of this process\n");
    
    PageInfo *page_infos = malloc(block_count * sizeof(PageInfo));
    size_t valid_pages = 0;
    
    for (size_t i = 0; i < block_count; i++) {
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

    printf("\rValid pages: %zu\n", valid_pages);

    // Step 2: Scan all processes (correct parallel version)
    printf("\nStep 2: Scanning all processes...\n");
    MappingTable table;
    init_mapping_table(&table);
    scan_all_processes_parallel(&table);

    // Step 2.5: Sort the mapping table
    printf("\nSorting mapping table (%zu entries)...", table.count);
    fflush(stdout);
    qsort(table.mappings, table.count, sizeof(PhysMapping), compare_mappings);
    printf(" Done\n");

    // Step 3: Offset calculation and search
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
    
    // Cleanup
    free(page_infos);
    free(table.mappings);
    pthread_mutex_destroy(&g_mapping_mutex);
    pthread_mutex_destroy(&g_print_mutex);
}

// =============================================================================
// Main function
// =============================================================================

int main() {
    printf("Memory Address Verification Program (Correct High-Speed Version)\n");
    printf("================================================================\n\n");
    
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
    
    // Stage 4 (correct high-speed version)
    if (block_count > 0 && ask_user("Proceed to Stage 4 (offset tracking)?")) {
        stage4_offset_tracking();
    }
    
    // Cleanup
    printf("\n=== Cleanup ===\n");
    for (size_t i = 0; i < block_count; i++) {
        free(mem_blocks[i].addr);
    }
    free(mem_blocks);
    
    printf("Program terminated.\n");
    return 0;
}
