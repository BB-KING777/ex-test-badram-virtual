#include <stdio.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <stdint.h>

#define PAGE_SIZE 4096

int main() {
    printf("========================================\n");
    printf("  Simple BadRAM Detection Tool\n");
    printf("========================================\n\n");
    
    // ステップ1: 空きメモリを確認
    struct sysinfo info;
    if (sysinfo(&info) != 0) {
        perror("sysinfo failed");
        return 1;
    }
    
    size_t free_memory = info.freeram * info.mem_unit;
    size_t alloc_size = (free_memory * 95) / 100;  // 95%を使用
    size_t num_pages = alloc_size / PAGE_SIZE;
    
    printf("Free memory: %zu MB\n", free_memory / (1024 * 1024));
    printf("Memory to allocate: %zu MB (%zu pages)\n", 
           alloc_size / (1024 * 1024), num_pages);
    
    // ステップ2: メモリを確保
    printf("\nAllocating memory...\n");
    void *memory = malloc(alloc_size);
    if (memory == NULL) {
        printf("Memory allocation failed\n");
        return 1;
    }
    printf("Allocation complete\n");
    
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
    
    // ステップ4: 各ページをスキャンしてエラーやエイリアスをチェック
    printf("\nScanning...\n");
    int bad_count = 0;
    
    for (size_t i = 0; i < num_pages; i++) {
        void **page = (void **)((char *)memory + i * PAGE_SIZE);
        void *stored_addr = *page;  // 書き込んだアドレスを読み出す
        
        // 保存されたアドレスが実際のアドレスと異なる場合
        if (stored_addr != page) {
            // ダブルチェック: 読み出したアドレスに書き込み、双方向エイリアスを検証
            void **alias_page = (void **)stored_addr;
            
            // stored_addrが確保したメモリ範囲内か確認
            if (stored_addr >= memory && 
                stored_addr < (void *)((char *)memory + alloc_size)) {
                
                // エイリアス先の元の値を保存
                void *original_value = *alias_page;
                
                // テストパターンを書き込む
                void *test_pattern = (void *)0xDEADBEEF;
                *alias_page = test_pattern;
                
                // 変更が実アドレスに反映されるか確認
                if (*page == test_pattern) {
                    printf("\n*** Bidirectional Alias detected! ***\n");
                    printf("  Page %zu:\n", i);
                    printf("  Address A (actual): %p\n", page);
                    printf("  Address B (alias):  %p\n", stored_addr);
                    printf("  -> Writing to B changes A: CONFIRMED\n");
                    
                    // 逆方向も検証
                    *page = page;
                    if (*alias_page == page) {
                        printf("  -> Writing to A changes B: CONFIRMED\n");
                        printf("  => TRUE BIDIRECTIONAL ALIAS\n");
                    }
                    
                    bad_count++;
                } else {
                    // 双方向エイリアスではなく、単なる読み出しエラー
                    printf("\n*** Read Error (not an alias) ***\n");
                    printf("  Page %zu:\n", i);
                    printf("  Actual address: %p\n", page);
                    printf("  Read address: %p (unidirectional error)\n", stored_addr);
                    bad_count++;
                }
                
                // 元の値を復元
                *alias_page = original_value;
                
            } else {
                // アドレスが確保範囲外の場合はメモリ破損
                printf("\n*** Memory Corruption detected! ***\n");
                printf("  Page %zu:\n", i);
                printf("  Actual address: %p\n", page);
                printf("  Read address: %p (outside allocated range)\n", stored_addr);
                bad_count++;
            }
        }
        
        if ((i + 1) % 100000 == 0) {
            printf("  %zu / %zu pages scanned\n", i + 1, num_pages);
        }
    }
    
    // ステップ5: 結果表示
    printf("\n========================================\n");
    printf("  Results\n");
    printf("========================================\n");
    printf("Pages scanned: %zu\n", num_pages);
    printf("Errors detected: %d\n", bad_count);
    
    if (bad_count > 0) {
        printf("\n*** Possible BadRAM detected! ***\n");
    } else {
        printf("No errors detected.\n");
    }
    
    // Cleanup
    free(memory);
    
    return 0;
}