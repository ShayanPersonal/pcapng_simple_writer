#include <stdio.h>
#include <stdint.h>
#include <pcap.h>

/*TODO:
    -Timestamp output appears to be broken.
*/

uint32_t four_align(uint32_t x) {
    if (x % 4 == 0)
        return x;
    return x + 4 - (x % 4);
}

uint32_t get_ts_low(struct timeval ts) {
    uint64_t s_to_usec = ts.tv_sec * 1000000;
    uint64_t timestamp = ts.tv_usec + s_to_usec;
    uint32_t lower = timestamp & 0x00000000FFFFFFFF;
    return lower;
}

uint32_t get_ts_high(struct timeval ts) {
    uint64_t s_to_usec = ts.tv_sec * 1000000;
    uint64_t timestamp = ts.tv_usec + s_to_usec;
    uint32_t higher = timestamp >> 32;
    return higher;
}

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
    struct pcapng_option_item *option;
    //End options with Option Code == opt_endofopt  |  Option Length == 0 
    //End with block_total_length
};

struct pcapng_idb_block {
    uint32_t block_type;
    uint32_t block_total_length;
    uint16_t linktype;
    uint16_t reserved;
    uint32_t snaplen;
    struct pcapng_option_item *option;
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
    struct pcapng_option_item *option;
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
    char zeros[] = {0, 0, 0, 0};
    fwrite(&(epb_block -> block_type), 4, 1, dump_fd);
    fwrite(&(epb_block -> block_total_length), 4, 1, dump_fd);
    fwrite(&(epb_block -> interface_id), 4, 1, dump_fd);
    fwrite(&(epb_block -> timestamp_high), 4, 1, dump_fd);
    fwrite(&(epb_block -> timestamp_low), 4, 1, dump_fd);
    fwrite(&(epb_block -> captured_len), 4, 1, dump_fd);
    fwrite(&(epb_block -> packet_len), 4, 1, dump_fd);
    fwrite(epb_block -> packet_data, epb_block -> captured_len, 1, dump_fd);
    fwrite(zeros, four_align(epb_block -> captured_len) - epb_block -> captured_len, 1, dump_fd);
    if (epb_block -> option != NULL) {
        struct pcapng_option_item* opt = epb_block -> option;
        fwrite(&(opt->option_code), 2, 1, dump_fd);
        fwrite(&(opt->option_length), 2, 1, dump_fd);
        fwrite(opt->option_value, opt->option_length, 1, dump_fd);
        //write endopt
        fwrite(zeros, 2, 1, dump_fd);
        fwrite(zeros, 2, 1, dump_fd);
    }
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

int pcapng_dump_init(FILE *dump_fd) {
    struct pcapng_shb_block shb_block = { 
        .block_type = 0x0a0d0d0a,
        .block_total_length = 28,
        .byte_order_magic = 0x1a2b3c4d,
        .major_version = 0x0001,
        .minor_version = 0x0000,
        .section_length = 0,
        .option = NULL
    };
    struct pcapng_idb_block idb_block = { 
        .block_type = 0x00000001,
        .block_total_length = 20,
        .linktype = 1,
        .reserved = 0,
        .snaplen = 0x0000FFFF,
        .option = NULL
    };
    pcapng_dump_shb(dump_fd, &shb_block);
    pcapng_dump_idb(dump_fd, &idb_block);
}

void got_packet(u_char *file, const struct pcap_pkthdr *header, const u_char *packet) {
    struct pcapng_option_item option = {
        .option_code = 1,
        .option_length = 8,
        .option_value = "Comment."
    };
    struct pcapng_epb_block epb_block = { 
        .block_type = 0x00000006,
        .block_total_length = 32 + four_align(header->caplen) + 12 + 4,
        .interface_id = 0,
        .timestamp_low = get_ts_low(header->ts),
        .timestamp_high = get_ts_high(header->ts),
        .captured_len = header->caplen,
        .packet_len = header->len,
        .packet_data = packet,
        .option = &option
    };
    pcapng_dump_epb((FILE*)file, &epb_block);
}

int main() {
    pcap_t *handle;			/* Session handle */
    char *dev;			/* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
    bpf_u_int32 mask;		/* Our netmask */
    bpf_u_int32 net;		/* Our IP */
    struct pcap_pkthdr header;	/* The header that pcap gives us */
    const u_char *packet;		/* The actual packet */
    pcap_if_t *alldevsp;

    pcap_findalldevs(&alldevsp, errbuf);
    dev = alldevsp -> name; //use alldevsp -> next -> name if default doesn't work
    printf("Using device %s (%s)\n", dev, alldevsp -> description);

    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }

    FILE *dump_fd = fopen("test.pcapng", "wb");
    pcapng_dump_init(dump_fd);

    printf("Starting loop\n");
    pcap_loop(handle, 20, got_packet, (u_char*)dump_fd);
    printf("Done looping");

    pcap_close(handle);
    fclose(dump_fd);
    return 0;
}
