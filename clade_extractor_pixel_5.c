#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include "clade_api.h"
#include "clade2_api.h"
#include "clade2_trace.h"

clade_memblock_t* client_alloc(clade_memblock_t *request, clade_memblock_t *previous, void *mem) {
    clade_memblock_t* return_block;
    
    clade_memblock_t* request_temp = request;

    do {
        return_block = (clade_memblock_t*)malloc(sizeof(clade_memblock_t));

        return_block->id[0] = 0;
        return_block->wordsize = 1;
        return_block->len = 0;
        return_block->addr = 0;
        return_block->data = 0;
        return_block->next = 0;
        return_block->prev = 0;

        if (previous) {
            previous->prev->next = return_block;
            return_block->prev = previous->prev;
            previous->prev = return_block;
            return_block->next = previous;
        }
        else {
            return_block->prev = return_block;
            return_block->next = return_block;
            previous = return_block;
        }

        return_block->wordsize = request_temp->wordsize;
        return_block->addr = request_temp->addr;
        return_block->len = request_temp->len;

        return_block->data = (uint8_t*)malloc(request_temp->len * request_temp->wordsize);

        request_temp = request_temp->next;
    } while (request_temp != request);
    return previous;
}

clade_memblock_t* client_lookup(clade_memblock_t *request, void* mem) {
    
    clade_memblock_t* request_temp = request;

    do {
        request_temp->data = (uint8_t*)malloc(request_temp->len * request_temp->wordsize);

        uint64_t temp_base = 0;
        do {
            request_temp->data[temp_base] = *(((uint8_t*)request_temp->addr) + temp_base);
            temp_base += 1;
        } while(request_temp->len != temp_base);

        request_temp = request_temp->next;
    } while (request_temp != request);
    return request;
}

int client_free(clade_memblock_t *request) {

    clade_memblock_t* request_temp = request;

    do {
        if (request->data) {
            // free(request->data);
            // request->data = 0;
        }
        request_temp = request->next;
    } while (request_temp != request);
    return 1;
}

int main(int argc, char** argv) {
    // Check Args
    if (argc < 2) {
        printf("usage: %s <out_file>\n", argv[0]);
        return 1;
    }
    char* out_file = argv[1];
    /* CLADE 1  */
    // Setup clade debug trace
    printf("Decompressing CLADE section...\n");
    clade_create_trace_file("stdout");
    // clade_set_trace(0xFF); // enable all log messages
    // Define some addresses
    uint32_t clade_dict_addr = 0xCF5E8000;
    uint64_t* clade_dict_ptrs[3];
    clade_dict_ptrs[0] = clade_dict_addr;
    clade_dict_ptrs[1] = clade_dict_addr + 0x2000;
    clade_dict_ptrs[2] = clade_dict_addr + 0x4000;
    uint64_t clade_compressed_ptr = 0xCD100000;
    uint64_t clade_compressed_ptr_hi = 0xcf2e0000;
    // Setup pd params
    static clade_pd_params_t pd;
    pd.comp = clade_compressed_ptr;
    pd.exc_hi = clade_compressed_ptr_hi;
    // Setup clade config
    static clade_config_t config;
    config.region = clade_compressed_ptr;
    config.num_pds = 1;
    config.num_dicts = 3;
    config.dict_len = 0x2000;
    config.pd_params = &pd;
    config.dicts = (uint32_t **)clade_dict_ptrs;
    clade_init(&config);
    // Create requested memory block
    clade_memblock_t request;
    request.addr = clade_compressed_ptr;
    request.data = 0;
    request.wordsize = 1;
    request.len = 0x21DF2C0;
    request.next = &request;
    request.prev = &request;
    // Decompress
    clade_memblock_t* read_block = clade_read(&request, NULL, client_alloc, client_lookup, client_free);
    // Write data to file
    printf("Writing to file: %s\n", out_file);
    FILE* f = fopen(out_file, "wb");
    fwrite(read_block->data, read_block->len, read_block->wordsize, f);
    fclose(f);
    // Copy memory to D page
    // uint8_t* dpage_addr = 0xd8000000;
    // clade_memblock_t* temp_block = read_block;
    // uint64_t temp_base = 0;
    // printf("Copying decompressed data to DPage: 0x%llx", dpage_addr);
    // do {
    //     size_t data_size = temp_block->wordsize * temp_block->len;
    //     memcpy(&dpage_addr[temp_base], temp_block->data, data_size);
    //     temp_base += data_size;
    //     temp_block = temp_block->next;
    // } while(temp_block != read_block);


    /* CLADE 2, NOT WORKING */
    // static clade2_config_t config;



    // clade2_init(&config);
    // clade2_set_trace(0xFF);
    // clade2_create_trace_file("stdout", "w");
    

    // uint64_t clade2_addr = 0xcf2e0000;
    // uint64_t clade2_size = 0x100;//0x308000;

    // config.c_base_addr = clade2_addr;
    // config.c_data_len = clade2_size;
    // config.anchor_0 = clade2_addr;
    // config.anchor_1 = clade2_addr+2048;
    // config.anchor_2 = clade2_addr+4096;
    // config.anchor_3 = clade2_addr+6144;

    // config.pd_params[0].meta_base_addr = 0xC0100000;
    // config.pd_params[0].meta_len = 0x1348;

    // clade2_init(&config);

    // clade_memblock_t request;
    // request.addr = clade2_addr;
    // request.data = 0;
    // request.wordsize = 1;
    // request.len = clade2_size;
    // request.next = &request;
    // request.prev = &request;
    // clade_memblock_t* read_block = clade2_read(&request, NULL, client_alloc, client_lookup, client_free);
    // printf("Error: %s\n", clade2_get_error_string(&config));


    printf("Done!\n");
}