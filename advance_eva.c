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

// 追加: 試行回数とパーセンテージステップの設定
#define NUM_TRIALS 5        
#define PERCENTAGE_STEP 1    
#define START_PERCENTAGE 95  
#define END_PERCENTAGE 1     

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
        *start_pct = START_PERCENTAGE;
        *start_trial = 1;
        return 0;//最初から実行
    }
    
    char line[512];
    int last_pct = START_PERCENTAGE;
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
    if (last_trial < NUM_TRIALS) {//NUM_TRIALS回未満なら同じパーセンテージで次の試行
        *start_pct = last_pct;
        *start_trial = last_trial + 1;
    } else if (last_pct > END_PERCENTAGE) {//NUM_TRIALS回完了していて、まだEND_PERCENTAGE以上なら次のパーセンテージに移動
        *start_pct = last_pct - PERCENTAGE_STEP;
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
    
    printf("Memory Test: %d%%-%d%%, %d trials, step %d%%\n", 
           START_PERCENTAGE, END_PERCENTAGE, NUM_TRIALS, PERCENTAGE_STEP);
    
    // CSV初期化
    create_csv_header();
    
    // 進捗確認
    int start_pct, start_trial;
    int resumed = read_progress(&start_pct, &start_trial);
    
    if (resumed) {
        printf("Resuming from %d%% - Trial %d\n", start_pct, start_trial);
    }
    
    // メインループ: START_PERCENTAGEからEND_PERCENTAGEまで、各NUM_TRIALS回ずつ
    for (int percentage = start_pct; percentage >= END_PERCENTAGE; percentage -= PERCENTAGE_STEP) {
        int start = (percentage == start_pct) ? start_trial : 1;
        
        for (int trial = start; trial <= NUM_TRIALS; trial++) {//各試行
            clock_t start_time = clock();//時間計測開始!!!
            
            printf("[%d%% #%d] ", percentage, trial);
            fflush(stdout);
            
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

            // ステップ2: メモリの確保 
            void *memory = malloc(alloc_size);//メモリ確保
            if (memory == NULL) {//失敗した場合
                printf("ALLOC_FAIL\n");
                append_result(percentage, trial, "ALLOC_FAIL", 0, 0,
                            alloc_size / (1024 * 1024), num_pages,
                            free_memory / (1024 * 1024), 0.0);//失敗結果をCSVに保存
                continue;
            }

            // エラー記録用の配列を確保
            ErrorRecord *errors = malloc(MAX_ERRORS * sizeof(ErrorRecord));//エラー記録用配列確保
            if (errors == NULL) {//失敗した場合
                printf("ERROR_ARRAY_FAIL\n");
                free(memory);
                continue;
            }
            
            // ステップ3: 各ページに仮想アドレスを書き込む
            for (size_t i = 0; i < num_pages; i++) {//ループ開始
                void **page = (void **)((char *)memory + i * PAGE_SIZE);//ページの先頭アドレスを取得
                
                // ページ先頭に自分自身のアドレスを書き込む
                *page = page;
                
                // 書き込み後にページ全体をキャッシュからフラッシュ
                flush_page(page);
            }
            
            // 全ての書き込みがメモリに反映されるまで待機
            memory_barrier();//みんな大好きメモリバリア
            
            // ステップ4: 各ページをスキャンしてエラーを検出（エイリアス→オリジナル）
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
            }
            
            // ステップ5: エラーが見つかった場合、逆方向のテストを実行
            int reverse_errors = 0;
            if (error_count > 0) {
                const char *test_pattern = "Is This BadRAM?";
                size_t pattern_len = strlen(test_pattern) + 1;
                
                for (int i = 0; i < error_count; i++) {
                    char *actual = (char *)errors[i].actual_addr;
                    char *read = (char *)errors[i].read_addr;

                    // read addressが確保したメモリ範囲内か一応チェック
                    // (範囲外のアドレスが読めた場合は、それをテスト対象から外す)
                    if ((void*)read < memory || (void*)read >= (memory + alloc_size)) {
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
                }
            }
            
            // 実行時間計算
            clock_t end_time = clock();
            double exec_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
            
            // ステップ6: 結果を表示
            const char *result;
            if (error_count > 0) {
                printf("NG err=%d rev=%d %.1fs\n", error_count, reverse_errors, exec_time);
                result = "NG";
            } else {
                printf("OK %.1fs\n", exec_time);
                result = "OK";
            }
            
            // CSVに結果を保存
            append_result(percentage, trial, result, error_count, reverse_errors,
                         alloc_size / (1024 * 1024), num_pages,
                         free_memory / (1024 * 1024), exec_time);
            
            // 後処理
            free(errors);
            free(memory);
        }
    }
    
    printf("Done! Results: %s\n", CSV_FILENAME);
    
    return 0;
}
