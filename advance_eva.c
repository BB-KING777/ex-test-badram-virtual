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

// 試行結果を保存する構造体
typedef struct {
    const char *result;
    int error_count;
    int reverse_errors;
    size_t allocated_mb;
    size_t allocated_pages;
    size_t free_mb;
    double exec_time;
} TrialResult;

// キャッシュラインサイズ（通常64バイト）
#define CACHE_LINE_SIZE 64


static inline void flush_page(void *addr) {
    char *ptr = (char *)addr;
    
    for (size_t i = 0; i < PAGE_SIZE; i += CACHE_LINE_SIZE) {
        asm volatile("clflush (%0)" : : "r"(ptr + i) : "memory");
    }
}

static inline void memory_barrier(void) {
    asm volatile("mfence" ::: "memory");
}

//進捗をCSVから読み取る関数（パーセンテージ単位で管理）
int read_progress(int *start_pct) {
    FILE *fp = fopen(CSV_FILENAME, "r");
    if (fp == NULL) {
        *start_pct = START_PERCENTAGE;
        return 0;
    }
    
    char line[512];
    int last_pct = START_PERCENTAGE;
    int trial_count = 0;
    int current_pct = -1;
    
    // ヘッダー行をスキップ
    fgets(line, sizeof(line), fp);
    
    // 最後のパーセンテージと試行数を数える
    while (fgets(line, sizeof(line), fp) != NULL) {
        int pct, trial;
        if (sscanf(line, "%d,%d", &pct, &trial) == 2) {
            if (pct != current_pct) {
                current_pct = pct;
                trial_count = 1;
            } else {
                trial_count++;
            }
            last_pct = pct;
        }
    }
    
    fclose(fp);
    
    // 5回分記録されていれば次のパーセンテージへ
    if (trial_count >= NUM_TRIALS && last_pct > END_PERCENTAGE) {
        *start_pct = last_pct - PERCENTAGE_STEP;
    } else if (trial_count >= NUM_TRIALS && last_pct <= END_PERCENTAGE) {
        printf("All experiments already completed!\n");
        exit(0);
    } else {
        // 途中で止まっている場合（通常は起きないはず）
        *start_pct = last_pct;
    }
    
    return 1;
}

// 指定パーセンテージの結果を読み取り、5回連続で同じエラー数かチェック
// 戻り値: 安定していればそのエラー数、不安定なら-1
int check_previous_stability(int percentage) {
    FILE *fp = fopen(CSV_FILENAME, "r");
    if (fp == NULL) {
        return -1;
    }
    
    char line[512];
    int error_counts[NUM_TRIALS];
    int count = 0;
    
    // ヘッダー行をスキップ
    fgets(line, sizeof(line), fp);
    
    // 指定パーセンテージのエラー数を集める
    while (fgets(line, sizeof(line), fp) != NULL && count < NUM_TRIALS) {
        int pct, trial, err;
        char result[16];
        if (sscanf(line, "%d,%d,%15[^,],%d", &pct, &trial, result, &err) >= 4) {
            if (pct == percentage) {
                error_counts[count++] = err;
            }
        }
    }
    
    fclose(fp);
    
    // 5回分のデータがない場合
    if (count < NUM_TRIALS) {
        return -1;
    }
    
    // 全て同じ値かチェック
    int first_val = error_counts[0];
    for (int i = 1; i < NUM_TRIALS; i++) {
        if (error_counts[i] != first_val) {
            return -1; // 不安定
        }
    }
    
    return first_val; // 安定している場合、そのエラー数を返す
}

// CSVの直近N行が連続でエラー0(OK)かチェック
// 戻り値: 連続OK回数
#define CONSECUTIVE_OK_THRESHOLD 12

int check_consecutive_ok_count(void) {
    FILE *fp = fopen(CSV_FILENAME, "r");
    if (fp == NULL) {
        return 0;
    }
    
    char line[512];
    // 十分な大きさの配列で全エラー数を保持
    int *all_errors = malloc(10000 * sizeof(int));
    if (all_errors == NULL) {
        fclose(fp);
        return 0;
    }
    int total_count = 0;
    
    // ヘッダー行をスキップ
    fgets(line, sizeof(line), fp);
    
    // 全行のエラー数を読み込む
    while (fgets(line, sizeof(line), fp) != NULL && total_count < 10000) {
        int pct, trial, err;
        char result[16];
        if (sscanf(line, "%d,%d,%15[^,],%d", &pct, &trial, result, &err) >= 4) {
            all_errors[total_count++] = err;
        }
    }
    
    fclose(fp);
    
    // 後ろから連続0をカウント
    int consecutive_ok = 0;
    for (int i = total_count - 1; i >= 0; i--) {
        if (all_errors[i] == 0) {
            consecutive_ok++;
        } else {
            break;
        }
    }
    
    free(all_errors);
    return consecutive_ok;
}

void append_result(int percentage, int trial, const char *result, 
                   int error_count, int reverse_errors,
                   size_t allocated_mb, size_t allocated_pages,
                   size_t free_mb, double exec_time) {
    FILE *fp = fopen(CSV_FILENAME, "a");
    if (fp == NULL) {
        perror("Failed to open CSV file");
        return;
    }
    
    fprintf(fp, "%d,%d,%s,%d,%d,%zu,%zu,%zu,%.2f\n",
            percentage, trial, result, error_count, reverse_errors,
            allocated_mb, allocated_pages, free_mb, exec_time);
    
    fclose(fp);
}

// 5回分まとめてCSVに書き込む
void append_all_results(int percentage, TrialResult *results, int actual_trials) {
    for (int i = 0; i < NUM_TRIALS; i++) {
        int src_idx = (i < actual_trials) ? i : actual_trials - 1; // 足りない分は最後の結果をコピー
        append_result(percentage, i + 1, results[src_idx].result,
                     results[src_idx].error_count, results[src_idx].reverse_errors,
                     results[src_idx].allocated_mb, results[src_idx].allocated_pages,
                     results[src_idx].free_mb, results[src_idx].exec_time);
    }
}

void create_csv_header() {
    FILE *fp = fopen(CSV_FILENAME, "r");
    if (fp != NULL) {
        fclose(fp);
        return;
    }
    
    fp = fopen(CSV_FILENAME, "w");
    if (fp == NULL) {
        perror("Failed to create CSV file");
        exit(1);
    }
    
    fprintf(fp, "percentage,trial,result,error_count,reverse_errors,allocated_mb,allocated_pages,free_memory_mb,execution_time_sec\n");
    fclose(fp);
}

// 1回のテストを実行し、結果をTrialResultに格納
// 戻り値: 0=成功, -1=失敗(ALLOC_FAILなど)
int run_single_trial(int percentage, int trial, TrialResult *result) {
    clock_t start_time = clock();
    
    printf("[%d%% #%d] ", percentage, trial);
    fflush(stdout);
    
    struct sysinfo info;
    if (sysinfo(&info) != 0) {
        perror("sysinfo failed");
        return -1;
    }
    
    size_t free_memory = info.freeram * info.mem_unit;
    size_t alloc_size = (free_memory * percentage) / 100;
    size_t num_pages = alloc_size / PAGE_SIZE;
    alloc_size = num_pages * PAGE_SIZE;
    
    result->free_mb = free_memory / (1024 * 1024);
    result->allocated_mb = alloc_size / (1024 * 1024);
    result->allocated_pages = num_pages;
    
    void *memory = malloc(alloc_size);
    if (memory == NULL) {
        printf("ALLOC_FAIL\n");
        result->result = "ALLOC_FAIL";
        result->error_count = 0;
        result->reverse_errors = 0;
        result->exec_time = 0.0;
        return -1;
    }

    ErrorRecord *errors = malloc(MAX_ERRORS * sizeof(ErrorRecord));
    if (errors == NULL) {
        printf("ERROR_ARRAY_FAIL\n");
        free(memory);
        return -1;
    }
    
    // 書き込み
    for (size_t i = 0; i < num_pages; i++) {
        void **page = (void **)((char *)memory + i * PAGE_SIZE);
        *page = page;
        flush_page(page);
    }
    memory_barrier();
    
    // スキャン
    int error_count = 0;
    for (size_t i = 0; i < num_pages; i++) {
        void **page = (void **)((char *)memory + i * PAGE_SIZE);
        flush_page(page);
        memory_barrier();
        
        void *stored_addr = *page;
        if (stored_addr != page) {
            if (error_count < MAX_ERRORS) {
                errors[error_count].actual_addr = page;
                errors[error_count].read_addr = stored_addr;
                error_count++;
            }
        }
    }
    
    // 逆方向テスト
    int reverse_errors = 0;
    if (error_count > 0) {
        const char *test_pattern = "Is This BadRAM?";
        size_t pattern_len = strlen(test_pattern) + 1;
        
        for (int i = 0; i < error_count; i++) {
            char *actual = (char *)errors[i].actual_addr;
            char *read = (char *)errors[i].read_addr;

            if ((void*)read < memory || (void*)read >= (memory + alloc_size)) {
                continue;
            }
            
            memcpy(actual, test_pattern, pattern_len);
            flush_page(actual);
            memory_barrier();
            flush_page(read);
            memory_barrier();
            
            if (memcmp(read, test_pattern, pattern_len) == 0) {
                reverse_errors++;
            }
        }
    }
    
    clock_t end_time = clock();
    double exec_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    
    // 結果を格納
    result->result = (error_count > 0) ? "NG" : "OK";
    result->error_count = error_count;
    result->reverse_errors = reverse_errors;
    result->exec_time = exec_time;
    
    if (error_count > 0) {
        printf("NG err=%d rev=%d %.1fs\n", error_count, reverse_errors, exec_time);
    } else {
        printf("OK %.1fs\n", exec_time);
    }
    
    free(errors);
    free(memory);
    
    return 0;
}

int main() {
    
    printf("Memory Test: %d%%-%d%%, %d trials, step %d%%\n", 
           START_PERCENTAGE, END_PERCENTAGE, NUM_TRIALS, PERCENTAGE_STEP);
    printf("Optimization: skip remaining trials if errors=MAX or errors=0\n");
    
    create_csv_header();
    
    int start_pct;
    int resumed = read_progress(&start_pct);
    
    if (resumed) {
        printf("Resuming from %d%%\n", start_pct);
    }
    
    for (int percentage = start_pct; percentage >= END_PERCENTAGE; percentage -= PERCENTAGE_STEP) {
        printf("\n=== %d%% ===\n", percentage);
        
        TrialResult results[NUM_TRIALS];
        int actual_trials = 0;
        int found_error = 0;
        
        // 前のパーセンテージが安定していたかチェック
        int prev_pct = percentage + PERCENTAGE_STEP;
        int prev_stable_errors = -1;
        if (prev_pct <= START_PERCENTAGE) {
            prev_stable_errors = check_previous_stability(prev_pct);
            if (prev_stable_errors >= 0) {
                printf("  Previous %d%% was stable (err=%d)\n", prev_pct, prev_stable_errors);
            }
        }
        
        // 直近の連続OK回数をチェック
        int consecutive_ok = check_consecutive_ok_count();
        if (consecutive_ok >= CONSECUTIVE_OK_THRESHOLD) {
            printf("  Last %d results were OK\n", consecutive_ok);
        }
        
        // 最初の試行
        if (run_single_trial(percentage, 1, &results[0]) == 0) {
            actual_trials = 1;
            
            if (results[0].error_count >= MAX_ERRORS) {
                // エラーが上限に達した場合：1回で終了
                printf("  -> MAX_ERRORS reached, skipping remaining trials\n");
                append_all_results(percentage, results, actual_trials);
                continue;
            }
            
            // 前のパーセンテージが安定していて、今回も同じエラー数なら1回で終了
            if (prev_stable_errors >= 0 && results[0].error_count == prev_stable_errors) {
                printf("  -> Same as stable previous (%d), skipping remaining trials\n", prev_stable_errors);
                append_all_results(percentage, results, actual_trials);
                continue;
            }
            
            // 直近12回以上OKで、今回もOKなら1回で終了
            if (consecutive_ok >= CONSECUTIVE_OK_THRESHOLD && results[0].error_count == 0) {
                printf("  -> Consecutive OK (%d+1), skipping remaining trials\n", consecutive_ok);
                append_all_results(percentage, results, actual_trials);
                continue;
            }
            
            if (results[0].error_count > 0) {
                found_error = 1;
            }
        } else {
            // 失敗した場合は5回分記録して次へ
            actual_trials = 1;
            append_all_results(percentage, results, actual_trials);
            continue;
        }
        
        // エラー0件の場合：最大3回まで
        // エラーあり(1-9999)の場合：5回実行
        int max_trials_for_zero = 3;
        
        for (int trial = 2; trial <= NUM_TRIALS; trial++) {
            // エラー0件で、まだエラーが見つかっておらず、3回目を超えた場合はスキップ
            if (!found_error && trial > max_trials_for_zero) {
                printf("  -> No errors in %d trials, skipping remaining\n", max_trials_for_zero);
                break;
            }
            
            if (run_single_trial(percentage, trial, &results[actual_trials]) == 0) {
                actual_trials++;
                
                if (results[actual_trials - 1].error_count >= MAX_ERRORS) {
                    // 途中でMAX_ERRORSに達した場合も終了
                    printf("  -> MAX_ERRORS reached, skipping remaining trials\n");
                    break;
                }
                
                if (results[actual_trials - 1].error_count > 0) {
                    found_error = 1;
                }
            }
        }
        
        // CSVに5回分記録
        append_all_results(percentage, results, actual_trials);
    }
    
    printf("\nDone! Results: %s\n", CSV_FILENAME);
    
    return 0;
}
