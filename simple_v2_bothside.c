#include <stdio.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <stdint.h>
#include <string.h>

#define PAGE_SIZE 4096
#define MAX_ERRORS 10000  // 記録する最大エラー数

typedef struct {
    void *actual_addr;
    void *read_addr;
} ErrorRecord;

int main() {
    printf("========================================\n");
    printf("  Simple BadRAM Detection Tool\n");
    printf("========================================\n\n");
    
    // ステップ1: 空きメモリの確認
    struct sysinfo info;
    if (sysinfo(&info) != 0) {
        perror("sysinfo failed");
        return 1;
    }
    
    size_t free_memory = info.freeram * info.mem_unit;
    size_t alloc_size = (free_memory * 95) / 100;  // 空きメモリの95%を使用
    size_t num_pages = alloc_size / PAGE_SIZE;
    
    printf("Free memory: %zu MB\n", free_memory / (1024 * 1024));
    printf("Memory to allocate: %zu MB (%zu pages)\n", 
           alloc_size / (1024 * 1024), num_pages);
    
    // ステップ2: メモリの確保
    printf("\nAllocating memory...\n");
    void *memory = malloc(alloc_size);
    if (memory == NULL) {
        printf("Memory allocation failed\n");
        return 1;
    }
    printf("Allocation complete\n");
    
    // エラー記録用の配列を確保
    ErrorRecord *errors = malloc(MAX_ERRORS * sizeof(ErrorRecord));
    if (errors == NULL) {
        printf("Error array allocation failed\n");
        free(memory);
        return 1;
    }
    
    // ステップ3: 各ページに仮想アドレスを書き込む
    printf("\nWriting virtual address to each page...\n");
    for (size_t i = 0; i < num_pages; i++) {
        void **page = (void **)((char *)memory + i * PAGE_SIZE);
        *page = page;  // 自分自身のアドレスを書き込む
        
        if ((i + 1) % 100000 == 0) {
            printf("  %zu / %zu pages done\n", i + 1, num_pages);
        }
    }
    printf("Write complete\n");
    
    // ステップ4: 各ページをスキャンしてエラーを検出（エイリアス→オリジナル）
    printf("\nScanning (Alias -> Original)...\n");
    int error_count = 0;
    
    for (size_t i = 0; i < num_pages; i++) {
        void **page = (void **)((char *)memory + i * PAGE_SIZE);
        void *stored_addr = *page;  // 書き込んだアドレスを読み出す
        
        // 書き込んだアドレスと実際のアドレスが異なる場合
        if (stored_addr != page) {
            // エラーを記録
            if (error_count < MAX_ERRORS) {
                errors[error_count].actual_addr = page;
                errors[error_count].read_addr = stored_addr;
                error_count++;
            }
        }
        
        if ((i + 1) % 100000 == 0) {
            printf("  %zu / %zu pages scanned\n", i + 1, num_pages);
        }
    }
    
    // ステップ5: エラーが見つかった場合、逆方向のテストを実行
    int reverse_errors = 0;
    if (error_count > 0) {
        printf("\nTesting reverse direction (Original -> Alias)...\n");
        
        const char *test_pattern = "Is This BadRAM?";
        size_t pattern_len = strlen(test_pattern) + 1;
        
        for (int i = 0; i < error_count; i++) {
            char *actual = (char *)errors[i].actual_addr;
            char *read = (char *)errors[i].read_addr;
            
            // actual addressに文字列を書き込む
            memcpy(actual, test_pattern, pattern_len);
            
            // read addressから読み出す
            if (memcmp(read, test_pattern, pattern_len) == 0) {
                reverse_errors++;
            }
            
            if ((i + 1) % 10000 == 0) {
                printf("  %d / %d pairs tested\n", i + 1, error_count);
            }
        }
    }
    
    // ステップ6: 結果を表示
    printf("\n========================================\n");
    printf("  Results\n");
    printf("========================================\n");
    printf("Pages scanned: %zu\n", num_pages);
    printf("Aliasing errors (Alias -> Original): %d\n", error_count);
    
    if (error_count > 0) {
        printf("Bidirectional aliasing: %d\n", reverse_errors);
        printf("One-way aliasing only: %d\n", error_count - reverse_errors);
        printf("\n*** Possible BadRAM detected! ***\n");
    } else {
        printf("\nNo errors detected.\n");
    }
    
    // 後処理
    free(errors);
    free(memory);
    
    return 0;
}