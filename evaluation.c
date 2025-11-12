#include <stdio.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#define PAGE_SIZE 4096
#define MAX_ERRORS 10000 // 記録する最大エラー数
#define CSV_FILENAME "evaluation.csv"

typedef struct {
    void *actual_addr;
    void *read_addr;
} ErrorRecord;

// キャッシュラインサイズ（通常64バイト）
// sysconf(_SC_LEVEL1_DCACHE_LINESIZE) で取得も可能らしい、
// x86_64環境で64に固定されているため定数
#define CACHE_LINE_SIZE 64


static inline void flush_page(void *addr) {
    char *ptr = (char *)addr;
    
    // ページ内のすべてのキャッシュライン（4096 / 64 = 64回）に対して
    // clflushを実行します。
    for (size_t i = 0; i < PAGE_SIZE; i += CACHE_LINE_SIZE) {
        // x86/x64: clflush命令でキャッシュラインをフラッシュ
        asm volatile("clflush (%0)" : : "r"(ptr + i) : "memory");
    }
}

// メモリバリアで入れ替える
static inline void memory_barrier(void) {
    asm volatile("mfence" ::: "memory");
}

//進捗をCSVから読み取る関数
int read_progress(int *start_pct, int *start_trial) {
    FILE *fp = fopen(CSV_FILENAME, "r");
    if (fp == NULL) {
        // ファイルが存在しない場合は最初から
        *start_pct = 95;
        *start_trial = 1;
        return 0;//最初から実行
    }
    
    char line[512];
    int last_pct = 95;
    int last_trial = 0;
    
    // ヘッダー行をスキップ
    fgets(line, sizeof(line), fp);
    
    // 最後の行を読む
    while (fgets(line, sizeof(line), fp) != NULL) {//各行を解析して最後の試行を特定
        int pct, trial;
        if (sscanf(line, "%d,%d", &pct, &trial) == 2) {//行の先頭からpercentageとtrialを読み取る
            last_pct = pct;
            last_trial = trial;//最後の試行を更新
        }
    }
    
    fclose(fp);//クローズ!!!!!!!!!!!!
    
    // 次の試行を計算
    if (last_trial < 50) {//50回未満なら同じパーセンテージで次の試行
        *start_pct = last_pct;
        *start_trial = last_trial + 1;
    } else if (last_pct > 1) {//50回完了していて、まだ1%以上なら次のパーセンテージに移動
        *start_pct = last_pct - 1;
        *start_trial = 1;
    } else {//すべて完了済み
        printf("All experiments already completed!\n");
        exit(0);
    }
    
    return 1;
}

//引数はCSVに保存する各種データの値
void append_result(int percentage, int trial, const char *result, 
                   int error_count, int reverse_errors,
                   size_t allocated_mb, size_t allocated_pages,
                   size_t free_mb, double exec_time) {
    FILE *fp = fopen(CSV_FILENAME, "a");//追記モードで開く
    if (fp == NULL) {
        perror("Failed to open CSV file");
        return;
    }//各データをCSV形式で書き込む
    
    fprintf(fp, "%d,%d,%s,%d,%d,%zu,%zu,%zu,%.2f\n",
            percentage, trial, result, error_count, reverse_errors,
            allocated_mb, allocated_pages, free_mb, exec_time);//各データをCSV形式で書き込む
    
    fclose(fp);//ファイルを閉じる
}


void create_csv_header() {//CSVファイルのヘッダーを作成
    FILE *fp = fopen(CSV_FILENAME, "r");
    if (fp != NULL) {//Not NULLなら既にファイルが存在する
        fclose(fp);
        return; // ファイルが既に存在する
    }
    
    fp = fopen(CSV_FILENAME, "w");//新規作成モードで開く
    if (fp == NULL) {//開けなかった場合
        perror("Failed to create CSV file");
        exit(1);
    }
    
    fprintf(fp, "percentage,trial,result,error_count,reverse_errors,allocated_mb,allocated_pages,free_memory_mb,execution_time_sec\n");//ヘッダー行を書き込む
    fclose(fp);//ファイルを閉じる
}

int main() {
    
    printf("========================================\n");
    printf("  Memory Test Evaluation System\n");
    printf("========================================\n");
    
    // CSV初期化
    create_csv_header();
    
    // 進捗確認
    int start_pct, start_trial;
    int resumed = read_progress(&start_pct, &start_trial);
    
    if (resumed) {
        printf("\nResuming from %d%% - Trial %d\n", start_pct, start_trial);
    } else {
        printf("\nStarting from the beginning (95%% - Trial 1)\n");
    }
    
    printf("========================================\n\n");
    
    // メインループ: 95%から1%まで、各50回ずつ
    for (int percentage = start_pct; percentage >= 1; percentage--) {
        int start = (percentage == start_pct) ? start_trial : 1;
        
        for (int trial = start; trial <= 50; trial++) {//各試行
            clock_t start_time = clock();//時間計測開始!!!
            
            printf("\n----------------------------------------\n");
            printf("[%d%% - Trial %d/50]\n", percentage, trial);
            printf("----------------------------------------\n");
            
            // ステップ1: 空きメモリの確認
            struct sysinfo info;//これマジで便利
            if (sysinfo(&info) != 0) {//失敗した場合
                perror("sysinfo failed");
                continue;
            }
            
            size_t free_memory = info.freeram * info.mem_unit;
            size_t alloc_size = (free_memory * percentage) / 100; // 指定された%を使用,percentage%のメモリを確保
            size_t num_pages = alloc_size / PAGE_SIZE;// ページ数計算
            
            // alloc_sizeをPAGE_SIZEの倍数に丸めます,理由はページ単位で確保するためずれると困る
            alloc_size = num_pages * PAGE_SIZE;

            printf("Free memory: %zu MB\n", free_memory / (1024 * 1024));//MB単位で表示
            printf("Memory to allocate: %zu MB (%zu pages)\n", 
                   alloc_size / (1024 * 1024), num_pages);
            
            // ステップ2: メモリの確保 
            printf("\nAllocating memory (aligned to page size)...\n");
            void *memory = malloc(alloc_size);//メモリ確保
            if (memory == NULL) {//失敗した場合
                printf("Memory allocation failed\n");
                append_result(percentage, trial, "ALLOC_FAIL", 0, 0,
                            alloc_size / (1024 * 1024), num_pages,
                            free_memory / (1024 * 1024), 0.0);//失敗結果をCSVに保存
                continue;
            }
            printf("Allocation complete\n");

            // エラー記録用の配列を確保
            ErrorRecord *errors = malloc(MAX_ERRORS * sizeof(ErrorRecord));//エラー記録用配列確保
            if (errors == NULL) {//失敗した場合
                printf("Error array allocation failed\n");
                free(memory);
                continue;
            }
            
            // ステップ3: 各ページに仮想アドレスを書き込む
            printf("\nWriting virtual address to each page...\n");//各ページに自分自身のアドレスを書き込む
            for (size_t i = 0; i < num_pages; i++) {//ループ開始
                void **page = (void **)((char *)memory + i * PAGE_SIZE);//ページの先頭アドレスを取得
                
                // ページ先頭に自分自身のアドレスを書き込む
                *page = page;
                
                // 書き込み後にページ全体をキャッシュからフラッシュ
                flush_page(page);
                
                if ((i + 1) % 100000 == 0) {
                    printf("  %zu / %zu pages done\n", i + 1, num_pages);//進捗表示
                }
            }
            
            // 全ての書き込みがメモリに反映されるまで待機
            memory_barrier();//みんな大好きメモリバリア
            printf("Write complete (cache flushed)\n");//書き込み完了表示
            
            // ステップ4: 各ページをスキャンしてエラーを検出（エイリアス→オリジナル）
            printf("\nScanning (Alias -> Original)...\n");
            int error_count = 0;
            
            for (size_t i = 0; i < num_pages; i++) {
                void **page = (void **)((char *)memory + i * PAGE_SIZE);//ページの先頭アドレスを取得

                // 読み出し前にページ全体をキャッシュからフラッシュ
                flush_page(page);
                memory_barrier();
                
                void *stored_addr = *page; // 書き込んだアドレスを読み出す
                
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

                    // read addressが確保したメモリ範囲内か一応チェック
                    // (範囲外のアドレスが読めた場合は、それをテスト対象から外す)
                    if ((void*)read < memory || (void*)read >= (memory + alloc_size)) {
                        printf("  Warning: Read address %p is out of bounds. Skipping reverse test.\n", (void*)read);
                        continue;
                    }
                    
                    // actual addressに文字列を書き込む
                    memcpy(actual, test_pattern, pattern_len);

                    // 書き込み後にページ全体をキャッシュをフラッシュ
                    flush_page(actual);
                    memory_barrier();

                    // read addressのページ全体をキャッシュもフラッシュ
                    flush_page(read);
                    memory_barrier();
                    
                    // read addressから読み出す
                    if (memcmp(read, test_pattern, pattern_len) == 0) {
                        reverse_errors++;
                    }
                    
                    if ((i + 1) % 10000 == 0) {
                        printf("  %d / %d pairs tested\n", i + 1, error_count);
                    }
                }
            }
            
            // 実行時間計算
            clock_t end_time = clock();
            double exec_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
            
            // ステップ6: 結果を表示
            printf("\n========================================\n");
            printf("  Results\n");
            printf("========================================\n");
            printf("Pages scanned: %zu\n", num_pages);
            printf("Memory errors (Alias -> Original): %d\n", error_count);
            
            const char *result;
            if (error_count > 0) {
                printf("True aliasing (bidirectional): %d\n", reverse_errors);
                printf("Read errors (not aliasing): %d\n", error_count - reverse_errors);
                printf("\n*** Possible BadRAM detected! ***\n");
                result = "NG";
            } else {
                printf("\nNo errors detected.\n");
                result = "OK";
            }
            printf("Execution time: %.2f seconds\n", exec_time);
            
            // CSVに結果を保存
            append_result(percentage, trial, result, error_count, reverse_errors,
                         alloc_size / (1024 * 1024), num_pages,
                         free_memory / (1024 * 1024), exec_time);
            
            // 後処理
            free(errors);
            free(memory);
        }
    }
    
    printf("\n========================================\n");
    printf("  All experiments completed!\n");
    printf("  Results saved to: %s\n", CSV_FILENAME);
    printf("========================================\n");
    
    return 0;
}