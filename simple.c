#include <stdio.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <stdint.h>

#define PAGE_SIZE 4096

int main() {
    printf("========================================\n");
    printf("  シンプルなBadRAM検出ツール\n");
    printf("========================================\n\n");
    
    // Step 1: 空きメモリを確認
    struct sysinfo info;
    if (sysinfo(&info) != 0) {
        perror("sysinfo失敗");
        return 1;
    }
    
    size_t free_memory = info.freeram * info.mem_unit;
    size_t alloc_size = (free_memory * 95) / 100;  // 95%を使う
    size_t num_pages = alloc_size / PAGE_SIZE;
    
    printf("空きメモリ: %zu MB\n", free_memory / (1024 * 1024));
    printf("確保するメモリ: %zu MB (%zu ページ)\n", 
           alloc_size / (1024 * 1024), num_pages);
    
    // Step 2: メモリを確保
    printf("\nメモリを確保中...\n");
    void *memory = malloc(alloc_size);
    if (memory == NULL) {
        printf("メモリ確保失敗\n");
        return 1;
    }
    printf("確保完了\n");
    
    // Step 3: 各ページに自分の仮想アドレスを書き込む
    printf("\n各ページに仮想アドレスを書き込み中...\n");
    for (size_t i = 0; i < num_pages; i++) {
        void **page = (void **)((char *)memory + i * PAGE_SIZE);
        *page = page;  // 自分のアドレスを書き込む
        
        if ((i + 1) % 100000 == 0) {
            printf("  %zu / %zu ページ完了\n", i + 1, num_pages);
        }
    }
    printf("書き込み完了\n");
    
    // Step 4: 各ページをスキャンして異常を検出
    printf("\nスキャン中...\n");
    int bad_count = 0;
    
    for (size_t i = 0; i < num_pages; i++) {
        void **page = (void **)((char *)memory + i * PAGE_SIZE);
        void *stored_addr = *page;  // 書き込んだアドレスを読み取る
        
        // 本来のアドレスと読み取ったアドレスが違う場合
        if (stored_addr != page) {
            printf("\n*** 異常検出! ***\n");
            printf("  ページ %zu:\n", i);
            printf("  本来のアドレス: %p\n", page);
            printf("  読み取ったアドレス: %p\n", stored_addr);
            bad_count++;
        }
        
        if ((i + 1) % 100000 == 0) {
            printf("  %zu / %zu ページスキャン完了\n", i + 1, num_pages);
        }
    }
    
    // Step 5: 結果表示
    printf("\n========================================\n");
    printf("  結果\n");
    printf("========================================\n");
    printf("スキャンしたページ数: %zu\n", num_pages);
    printf("異常検出数: %d\n", bad_count);
    
    if (bad_count > 0) {
        printf("\n*** BadRAM の可能性があります! ***\n");
    } else {
        printf("\n異常は検出されませんでした。\n");
    }
    
    // クリーンアップ
    free(memory);
    
    return 0;
}
