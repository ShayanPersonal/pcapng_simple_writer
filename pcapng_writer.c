#include <stdio.h>
#include <stdint.h>

struct pcapng_option_item {
    uint16_t option_code;
    uint16_t option_length;
    uint8_t *option_value;
};

struct pcapng_shb_block {
    uint32_t block_type;
    uint32_t block_total_length;
    uint32_t byte_order_magic;
    uint16_t major_version;
    uint16_t minor_version;
    uint64_t section_length;
    struct pcapng_option_item *options;
    //End options with Option Code == opt_endofopt  |  Option Length == 0 
    //End with block_total_length
};

struct pcapng_idb_block {
    uint32_t block_type;
    uint32_t block_total_length;
    uint16_t linktype;
    uint16_t reserved;
    uint32_t snaplen;
    struct pcapng_option_item *options;
    //End options with Option Code == opt_endofopt  |  Option Length == 0 
    //End with block_total_length
};

struct pcapng_epb_block {
    uint32_t block_type;
    uint32_t block_total_length;
    uint32_t interface_id;
    uint32_t timestamp_high;
    uint32_t timestamp_low;
    uint32_t captured_len;
    uint32_t packet_len;
    uint8_t *packet_data;
    struct pcapng_options_item *options;
    //End options with Option Code == opt_endofopt  |  Option Length == 0 
    //End with block_total_length
};

struct pcapng_simple_capture {
    //Simplest pcapng capture. Starts with a section header and interface description, 
    //followed by list of epb blocks.
    struct pcapng_shb_block *shb_block;
    struct pcapng_idb_block *idb_block;
    struct pcapng_epb_block **epb_blocks;
    size_t epb_count;
};

int pcapng_dump_shb(FILE *dump_fd, struct pcapng_shb_block *shb_block) {
    fwrite(&(shb_block -> block_type), 4, 1, dump_fd);
    fwrite(&(shb_block -> block_total_length), 4, 1, dump_fd);
    fwrite(&(shb_block -> byte_order_magic), 4, 1, dump_fd);
    fwrite(&(shb_block -> major_version), 2, 1, dump_fd);
    fwrite(&(shb_block -> minor_version), 2, 1, dump_fd);
    fwrite(&(shb_block -> section_length), 8, 1, dump_fd);
    fwrite(&(shb_block -> block_total_length), 4, 1, dump_fd);
    return 0;
}

int pcapng_dump_idb(FILE *dump_fd, struct pcapng_idb_block *idb_block) {
    fwrite(&(idb_block -> block_type), 4, 1, dump_fd);
    fwrite(&(idb_block -> block_total_length), 4, 1, dump_fd);
    fwrite(&(idb_block -> linktype), 2, 1, dump_fd);
    fwrite(&(idb_block -> reserved), 2, 1, dump_fd);
    fwrite(&(idb_block -> snaplen), 4, 1, dump_fd);
    fwrite(&(idb_block -> block_total_length), 4, 1, dump_fd);
    return 0;
}

int pcapng_dump_epb(FILE *dump_fd, struct pcapng_epb_block *epb_block) {
    fwrite(&(epb_block -> block_type), 4, 1, dump_fd);
    fwrite(&(epb_block -> block_total_length), 4, 1, dump_fd);
    fwrite(&(epb_block -> interface_id), 4, 1, dump_fd);
    fwrite(&(epb_block -> timestamp_high), 4, 1, dump_fd);
    fwrite(&(epb_block -> timestamp_low), 4, 1, dump_fd);
    fwrite(&(epb_block -> captured_len), 4, 1, dump_fd);
    fwrite(&(epb_block -> packet_len), 4, 1, dump_fd);
    fwrite(&(epb_block -> packet_data), epb_block -> captured_len, 1, dump_fd);
    fwrite(&(epb_block -> block_total_length), 4, 1, dump_fd);
    return 0;
}

int pcapng_simple_dump(FILE *dump_fd, struct pcapng_simple_capture *capture) {
    if (!capture->shb_block || !capture->idb_block || !capture->epb_blocks)
        return 1;
    pcapng_dump_shb(dump_fd, capture->shb_block);
    pcapng_dump_idb(dump_fd, capture->idb_block);
    for (size_t i = 0; i < capture->epb_count; i++)
        pcapng_dump_epb(dump_fd, capture->epb_blocks[i]);
    printf("Finished dump\n");
    return 0;
}

int pcapng_test() {
    FILE *dump_fd = fopen("test.pcapng", "wb");
    struct pcapng_shb_block shb_block = { 
        .block_type = 0x0a0d0d0a,
        .block_total_length = 28,
        .byte_order_magic = 0x1a2b3c4d,
        .major_version = 0x0001,
        .minor_version = 0x0000,
        .section_length = 0,
        .options = NULL
    };
    struct pcapng_idb_block idb_block = { 
        .block_type = 0x00000001,
        .block_total_length = 20,
        .linktype = 1,
        .reserved = 0,
        .snaplen = 0x0000FFFF,
        .options = NULL
    };
    struct pcapng_epb_block epb_block = { 
        .block_type = 0x00000006,
        .block_total_length = 36,
        .interface_id = 0,
        .timestamp_low = 0,
        .timestamp_high = 0,
        .captured_len = 4,
        .packet_len = 4,
        .packet_data = "Hel",
        .options = NULL
    };
    struct pcapng_epb_block *epb_block_p = &epb_block;
    struct pcapng_simple_capture capture = {
        .shb_block = &shb_block,
        .idb_block = &idb_block,
        .epb_blocks = &epb_block_p,
        .epb_count = 1,
    };
    pcapng_simple_dump(dump_fd, &capture);
    fclose(dump_fd);
    return 0;
}

int main() {
    pcapng_test();
}