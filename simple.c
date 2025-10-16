#include <stdio.h>
#include <stdlib.h>
#include <sys/sysinfo.h>
#include <stdint.h>

#define PAGE_SIZE 4096

int main() {
    printf("========================================\n");
    printf("  Simple BadRAM Detection Tool\n");
    printf("========================================\n\n");
    
    // Step 1: Check free memory
    struct sysinfo info;
    if (sysinfo(&info) != 0) {
        perror("sysinfo failed");
        return 1;
    }
    
    size_t free_memory = info.freeram * info.mem_unit;
    size_t alloc_size = (free_memory * 95) / 100;  // Use 95%
    size_t num_pages = alloc_size / PAGE_SIZE;
    
    printf("Free memory: %zu MB\n", free_memory / (1024 * 1024));
    printf("Memory to allocate: %zu MB (%zu pages)\n", 
           alloc_size / (1024 * 1024), num_pages);
    
    // Step 2: Allocate memory
    printf("\nAllocating memory...\n");
    void *memory = malloc(alloc_size);
    if (memory == NULL) {
        printf("Memory allocation failed\n");
        return 1;
    }
    printf("Allocation complete\n");
    
    // Step 3: Write virtual address to each page
    printf("\nWriting virtual address to each page...\n");
    for (size_t i = 0; i < num_pages; i++) {
        void **page = (void **)((char *)memory + i * PAGE_SIZE);
        *page = page;  // Write its own address
        
        if ((i + 1) % 100000 == 0) {
            printf("  %zu / %zu pages done\n", i + 1, num_pages);
        }
    }
    printf("Write complete\n");
    
    // Step 4: Scan each page for errors
    printf("\nScanning...\n");
    int bad_count = 0;
    
    for (size_t i = 0; i < num_pages; i++) {
        void **page = (void **)((char *)memory + i * PAGE_SIZE);
        void *stored_addr = *page;  // Read written address
        
        // If the stored address is different from the actual address
        if (stored_addr != page) {
            printf("\n*** Error detected! ***\n");
            printf("  Page %zu:\n", i);
            printf("  Actual address: %p\n", page);
            printf("  Read address: %p\n", stored_addr);
            bad_count++;
        }
        
        if ((i + 1) % 100000 == 0) {
            printf("  %zu / %zu pages scanned\n", i + 1, num_pages);
        }
    }
    
    // Step 5: Show results
    printf("\n========================================\n");
    printf("  Results\n");
    printf("========================================\n");
    printf("Pages scanned: %zu\n", num_pages);
    printf("Errors detected: %d\n", bad_count);
    
    if (bad_count > 0) {
        printf("\n*** Possible BadRAM detected! ***\n");
    } else {
        printf("\nNo errors detected.\n");
    }
    
    // Cleanup
    free(memory);
    
    return 0;
}
