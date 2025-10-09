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

// 定数定義
#define PAGE_SIZE 0x1000
#define MB (1024UL * 1024)
#define GB (1024UL * 1024 * 1024)
#define PHYSICAL_ADDR_THRESHOLD 0x200000000UL
#define PHYSICAL_ADDR_MAXIMAM 0x400000000UL

// pagemapビットフラグ
#define PM_PRESENT (1ULL << 63)
#define PM_PFN_MASK ((1ULL << 55) - 1)

// メモリブロック
typedef struct {
    void *addr;
    size_t size;
} MemBlock;

// 物理アドレスマッピング
typedef struct {
    uint64_t phys_addr;
    unsigned long virt_addr;
    pid_t pid;
    char comm[256];
} PhysMapping;

// マッピングテーブル
typedef struct {
    PhysMapping *mappings;
    size_t count;
    size_t capacity;
} MappingTable;

// ページ情報
typedef struct {
    uint64_t phys;
    void *virt;
} PageInfo;

// スレッド用データ
typedef struct {
    pid_t *pids;
    size_t pid_count;
    MappingTable *table;
} ScanThreadData;

// グローバル変数
MemBlock *mem_blocks = NULL;
size_t block_count = 0;
size_t block_capacity = 0;

pthread_mutex_t g_mapping_mutex;
pthread_mutex_t g_print_mutex;
volatile size_t g_processed_procs_count = 0;
pid_t g_self_pid;


// 検出したペアの数を保護するためのミューテックスと、共有カウンタ
pthread_mutex_t g_alias_mutex = PTHREAD_MUTEX_INITIALIZER;
int g_pairs_found = 0;

// 各スレッドに渡す情報
typedef struct {
    size_t start_index; // 担当する外側ループiの開始インデックス
    size_t end_index;   // 担当する外側ループiの終了インデックス
} AliasThreadData;

// =============================================================================
// ユーティリティ関数
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
// マッピングテーブル関連
// =============================================================================

void init_mapping_table(MappingTable *table) {
    table->capacity = 100000;
    table->count = 0;
    table->mappings = malloc(sizeof(PhysMapping) * table->capacity);
    if (!table->mappings) {
        perror("メモリ割り当て失敗");
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
            perror("メモリ再割り当て失敗");
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
        snprintf(name, size, "不明");
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
        printf("      → PID %d (%s), 仮想: 0x%lx\n",
               found->pid, found->comm, found->virt_addr);
    } else {
        printf("      → 未使用 or スワップアウト\n");
    }
}

// pagemapから指定範囲の物理アドレスを取得（正しい方法）
int get_pfn_for_range(pid_t pid, unsigned long vaddr_start, unsigned long vaddr_end,
                      MappingTable *table, const char *comm) {
    char pagemap_path[256];
    snprintf(pagemap_path, sizeof(pagemap_path), "/proc/%d/pagemap", pid);
    
    int fd = open(pagemap_path, O_RDONLY);
    if (fd < 0) return -1;
    
    // 範囲内のページごとに処理
    for (unsigned long vaddr = vaddr_start; vaddr < vaddr_end; vaddr += PAGE_SIZE) {
        uint64_t offset = (vaddr / PAGE_SIZE) * sizeof(uint64_t);
        
        if (lseek(fd, offset, SEEK_SET) < 0) {
            continue;
        }
        
        uint64_t entry;
        if (read(fd, &entry, sizeof(uint64_t)) != sizeof(uint64_t)) {
            continue;
        }
        
        // ページが物理メモリに存在するか確認
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
// 並列処理（プロセススキャン）- 正しい方法
// =============================================================================

void *scan_worker(void *arg) {
    ScanThreadData *data = (ScanThreadData *)arg;
    char maps_path[256];
    char comm[256];
    
    for (size_t i = 0; i < data->pid_count; i++) {
        pid_t pid = data->pids[i];
        
        get_process_name(pid, comm, sizeof(comm));
        
        // /proc/PID/maps を読んで実際にマップされている範囲だけを取得
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
            
            // 仮想アドレス範囲を解析
            if (sscanf(line, "%lx-%lx", &vaddr_start, &vaddr_end) == 2) {
                // この範囲の物理アドレスを取得
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
        perror("エラー: /procディレクトリを開けません");
        return;
    }
    
    // PIDをリストアップ
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
    
    printf("総プロセス数: %zu (自身のPID %d は除外します)\n", pid_count, g_self_pid);
    
    int num_threads = get_nprocs();
    if (num_threads > 16) num_threads = 16;
    
    printf("並列処理: %dスレッドで全プロセスをスキャン中...\n", num_threads);
    printf("※/proc/PID/mapsの実際にマップされている範囲のみスキャンします\n\n");
    
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
    
    // 進捗表示
    while (g_processed_procs_count < pid_count) {
        int percent = (g_processed_procs_count * 100) / pid_count;
        printf("\r進捗: [");
        int bar_width = 40;
        int filled = (percent * bar_width) / 100;
        for (int i = 0; i < bar_width; i++) {
            printf(i < filled ? "=" : (i == filled ? ">" : " "));
        }
        printf("] %3d%% | %zu/%zu プロセス | %zu マッピング   ",
               percent, (size_t)g_processed_procs_count, pid_count, table->count);
        fflush(stdout);
        usleep(100000);
    }
    
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    free(pids);
    
    printf("\r進捗: [");
    for (int i = 0; i < 40; i++) printf("=");
    printf("] 100%% | %zu/%zu プロセス | %zu マッピング   \n",
           pid_count, pid_count, table->count);
    printf("\nスキャン完了!\n");
}

void *alias_worker(void *arg) {
    AliasThreadData *data = (AliasThreadData *)arg;
    const uint64_t TEST_PATTERN = 0xDEADBEEFCAFEBABE;

    // 割り当てられた範囲のiについてループを実行
    for (size_t i = data->start_index; i < data->end_index; i++) {
        uint64_t *ptr_i = (uint64_t *)mem_blocks[i].addr;
        uint64_t original_value_i = *ptr_i;
        *ptr_i = TEST_PATTERN;

        for (size_t j = i + 1; j < block_count; j++) {
            uint64_t *ptr_j = (uint64_t *)mem_blocks[j].addr;
            if (*ptr_j == TEST_PATTERN) {
                // 複数のスレッドが同時に書き込まないようにロックする
                pthread_mutex_lock(&g_alias_mutex);
                
                g_pairs_found++;
                printf("エイリアスペア検出 (発見者: スレッド %lu):\n", pthread_self());
                printf("    - ページ %zu (仮想アドレス: %p)\n", i, mem_blocks[i].addr);
                printf("    - ページ %zu (仮想アドレス: %p)\n\n", j, mem_blocks[j].addr);
                
                pthread_mutex_unlock(&g_alias_mutex);
            }
        }
        *ptr_i = original_value_i;
    }
    return NULL;
}




// =============================================================================
// ステージ1-3
// =============================================================================

void stage1_allocate_memory() {
    printf("=== stage1 allocate memory ===\n");
    printf("PID: %d\n", getpid());
    printf("Pagesize: 0x%x (%d byte)\n", PAGE_SIZE, PAGE_SIZE);
    
    size_t available_mb = get_available_memory_mb();
    printf("usable memory: %zu MB (%.2f GB)\n",
           available_mb, (double)available_mb / 1024);
    
    size_t max_safe_mb = available_mb * 70 / 100;
    if (max_safe_mb > 10 * 1024) {
        max_safe_mb = 10 * 1024;
    }
    
    size_t max_pages = (max_safe_mb * MB) / PAGE_SIZE;
    
    printf("will allocate : max %zu pages (%zu MB, %.2f GB)\n",
           max_pages, max_safe_mb, (double)max_safe_mb / 1024);
    
    if (!ask_user("Will you start allocating memory?")) {
        printf("skip stage1\n");
        return;
    }
    
    printf("\n0x1000 (4096byte) allocating virtual memory by malloc\n");
    
    size_t total_allocated = 0;
    
    for (size_t i = 0; i < max_pages; i++) {
        void *addr = malloc(PAGE_SIZE);
        
        if (addr == NULL) {
            printf("allocation failed: %zu pages (%zu MB) allocated\n",
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

    if (ask_user("Will you check pages with physical addresses >= 0x200000000?")) {
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
                        printf("  page %zu: virtual: %p -> physical: 0x%lx (%.2f GB)\n",
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
            printf("  ... (他に %d ページ)\n", high_addr_count - max_display);
        }
        
        printf("\nresult:\n");
        printf("  checked pages: %d\n", checked_count);
        printf("  pages with physical addresses >= 0x200000000: %d\n", high_addr_count);
        if (checked_count > 0) {
            printf("  ratio: %.2f%%\n", 100.0 * high_addr_count / checked_count);
        }
    }
}

void stage2_write_pages() {
    printf("\n=== stage2 write pages ===\n");
    
    if (block_count == 0) {
        printf("No allocated memory.\n");
        return;
    }

    printf("will write: %zu pages (about %zu MB)\n",
           block_count, block_count * PAGE_SIZE / MB);

    if (!ask_user("Will you write unique values to each page?")) {
        printf("skip stage2\n");
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
    printf("\n=== stage3 check aliases ===\n");
    if (block_count < 2) {
        printf("Not enough memory to compare.\n");
        return;
    }

    if (!ask_user("Will you start a time-consuming scan for alias pairs in parallel?")) {
        printf("Skip stage3.\n");
        return;
    }

    // Get the number of CPU cores on the system (default if not available)
    int num_threads = sysconf(_SC_NPROCESSORS_ONLN);
    if (num_threads <= 0) num_threads = 4; // フォールバック
    if (num_threads > 16) num_threads = 16; // 上限を設定

    printf("Scanning alias pairs in parallel with %d threads...\n", num_threads);

    pthread_t threads[num_threads];
    AliasThreadData thread_data[num_threads];
    size_t total_indices = block_count;
    size_t indices_per_thread = total_indices / num_threads;

    g_pairs_found = 0; // カウンタをリセット

    // スレッドの生成とタスクの割り当て
    for (int i = 0; i < num_threads; i++) {
        thread_data[i].start_index = i * indices_per_thread;
        if (i == num_threads - 1) {
            // 最後のスレッドは残りすべてを担当
            thread_data[i].end_index = total_indices;
        } else {
            thread_data[i].end_index = (i + 1) * indices_per_thread;
        }
        pthread_create(&threads[i], NULL, alias_worker, &thread_data[i]);
    }

    // 全スレッドの終了を待つ
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    // 最終結果の表示
    if (g_pairs_found == 0) {
        printf("\n✓ cannot find alias pairs\n");
    } else {
        printf("\n✗  %d find alias\n", g_pairs_found);
    }
}


// =============================================================================
// ステージ4
// =============================================================================

void stage4_offset_tracking() {
    printf("\n=== stage4: offset tracking ===\n");
    
    if (block_count == 0) {
        printf("No allocated memory.\n");
        return;
    }
    
    g_self_pid = getpid();
    printf("PID of this process : %d\n", g_self_pid);
    printf("Offset value: -0x200008000\n");
    //printf("※自身のPIDは検索対象から除外します\n");
    //printf("※/proc/PID/mapsの実際のマップ範囲のみスキャンします（高速）\n");
    
    if (!ask_user("Will you start offset tracking?")) {
        printf("Skip stage4.\n");
        return;
    }
    
    // mutexの初期化
    pthread_mutex_init(&g_mapping_mutex, NULL);
    pthread_mutex_init(&g_print_mutex, NULL);
    
    // ステップ1: このプロセスの物理アドレスを取得
    printf("\nstep 1: Get physical addresses of this process\n");
    
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

    // step 2: Scan all processes (correct parallel version)
    printf("\nstep 2: Scanning all processes...\n");
    MappingTable table;
    init_mapping_table(&table);
    scan_all_processes_parallel(&table);

    // step 2.5: Sort the mapping table
    printf("\nsorting mapping table  (%zu entries)...", table.count);
    fflush(stdout);
    qsort(table.mappings, table.count, sizeof(PhysMapping), compare_mappings);
    printf(" 完了\n");

    // step 3: Offset calculation and search
    printf("\nstep 3: Offset calculation and search\n");

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
            printf("      Offset after: 0x%lx - 0x200008000 = 0x%lx\n",
                   original_phys, target_phys);
            
            search_physical_address_bsearch(&table, target_phys);
            printf("\n");
        }
        
        processed++;
    }
    
    printf("============================================================\n");
    printf("complete\n");
    printf("  all pages : %zu\n", valid_pages);
    printf("  processed pages : %d\n", processed);
    printf("  skipped pages : %d (underflow)\n", skipped);
    
    if (processed > display_limit) {
        printf("\nWarning: Displaying only the first %d results due to high volume.\n", display_limit);
    }
    
    // クリーンアップ
    free(page_infos);
    free(table.mappings);
    pthread_mutex_destroy(&g_mapping_mutex);
    pthread_mutex_destroy(&g_print_mutex);
}

// =============================================================================
// メイン関数
// =============================================================================

int main() {
    printf("メモリアドレス検証プログラム (正しい高速版)\n");
    printf("============================================\n\n");
    
    // 第一段階
    stage1_allocate_memory();
    
    // 第二段階
    if (block_count > 0 && ask_user("第二段階に進みますか?")) {
        stage2_write_pages();
    }
    
    // 第三段階
    if (block_count > 0 && ask_user("第三段階に進みますか?")) {
        stage3_check_aliases();
    }
    
    // 第四段階（正しい高速版）
    if (block_count > 0 && ask_user("第四段階（オフセット追跡）に進みますか?")) {
        stage4_offset_tracking();
    }
    
    // クリーンアップ
    printf("\n=== クリーンアップ ===\n");
    for (size_t i = 0; i < block_count; i++) {
        free(mem_blocks[i].addr);
    }
    free(mem_blocks);
    
    printf("プログラムを終了します。\n");
    return 0;
}