# ebpf-mqtts-dumper

This is not really a specific MQTTs dumper.

It filters, via ePBF, and dumps TCP packets, on a chosen interfaces, from and to a chosen port. It's called `mqtts_dumper.py` due to the suggested usage reported in the eBPF series of the [IoT withit blog](https://iotwith.it/blog/).

    # ./mqtts_dumper.py -i_p my_ifc,my_port > dumped.txt

Feed [`pktstream_to_pcap`](https://github.com/iotwithit/pktstream_to_pcap) Python script with dumped.txt file to convert dumped packets to pcap format to analyze them with Wireshark.

