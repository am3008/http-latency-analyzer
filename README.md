# http-latency-analyzer
Analyze HTTP server response times from PCAPs with latency metrics, percentiles, and KL divergence.

Analyze HTTP server response times from a PCAP file.

This tool extracts HTTP request/response pairs from packet captures and computes
latency statistics such as average response time, percentiles, and distribution
comparisons against an exponential model. It also reports the KL divergence
between measured and modeled latency distributions.
