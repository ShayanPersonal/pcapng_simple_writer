# pcapng_simple_writer
Uses libpcap to sniff traffic and outputs in the pcapng format.

libpcap does not support writing to pcapng which can be a headache for developers relying on the new format.
This project demonstrates how simple it is to write a pcapng dumper by hand. libpcap is used to sniff traffic which is dumped to the unspported pcapng format.
