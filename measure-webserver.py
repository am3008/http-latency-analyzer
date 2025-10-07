#!/usr/bin/env python3
"""
measure-webserver.py

Analyze HTTP server response times from a PCAP file.
- Extracts HTTP request/response pairs.
- Computes latency statistics (average, percentiles).
- Compares observed distribution against an exponential model.
- Computes KL divergence between measured and modeled distributions.

"""

import argparse
import math
import logging
from scapy.all import rdpcap, IP, TCP, load_layer
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse


# -------------------- Utility Functions --------------------

def percentile(data, percentile):
    """
    Compute a percentile using linear interpolation.

    Args:
        data (list[float]): Input data points.
        percentile (float): Desired percentile in [0, 1].

    Returns:
        float: Interpolated percentile value, or 0 if data is empty.
    """
    if not data:
        return 0.0
    sorted_data = sorted(data)
    index = percentile * (len(sorted_data) - 1)
    floor_index = int(index)
    ceil_index = min(floor_index + 1, len(sorted_data) - 1)
    if floor_index == ceil_index:
        return sorted_data[floor_index]
    lower = sorted_data[floor_index]
    upper = sorted_data[ceil_index]
    return lower + (index - floor_index) * (upper - lower)


def find_divergence(measured_distribution, modeled_distribution):
    """
    Compute KL divergence between measured and modeled distributions.

    Args:
        measured_distribution (list[float]): Empirical distribution.
        modeled_distribution (list[float]): Theoretical distribution.

    Returns:
        float: KL divergence in bits.
    """
    if len(measured_distribution) != len(modeled_distribution):
        raise ValueError("Distributions must have the same length.")

    kl_sum = 0.0
    for m, p in zip(measured_distribution, modeled_distribution):
        if m > 0 and p > 0:  # avoid log(0)
            kl_sum += m * math.log2(m / p)

    return kl_sum


def exponential_distribution(data, mean_response_time, num_buckets=10):
    """
    Compare observed latencies with an exponential distribution model.

    Args:
        data (list[float]): Observed latencies.
        mean_response_time (float): Average latency to parameterize the exponential distribution.
        num_buckets (int): Number of histogram buckets.

    Returns:
        tuple[list[float], list[float]]: (modeled_distribution, measured_distribution)
    """
    if not data or mean_response_time <= 0:
        return [], []

    rate = 1 / mean_response_time
    max_latency = max(data)
    bucket_edges = [i * max_latency / num_buckets for i in range(num_buckets + 1)]

    # Measured distribution
    measured_counts = [0] * num_buckets
    for latency in data:
        for i in range(num_buckets):
            if bucket_edges[i] <= latency < bucket_edges[i + 1]:
                measured_counts[i] += 1
                break

    total = len(data)
    measured_dist = [count / total for count in measured_counts]

    # Modeled exponential distribution
    modeled_dist = []
    for i in range(1, num_buckets + 1):
        cdf_high = 1 - math.exp(-rate * bucket_edges[i])
        cdf_low = 1 - math.exp(-rate * bucket_edges[i - 1])
        modeled_dist.append(cdf_high - cdf_low)

    # Normalize
    modeled_dist = [p / sum(modeled_dist) for p in modeled_dist]

    return modeled_dist, measured_dist


# -------------------- Core Measurement --------------------

def measure(pcap_file, server_ip, server_port):
    """
    Analyze HTTP request/response latencies from a PCAP capture.

    Args:
        pcap_file (str): Path to input PCAP file.
        server_ip (str): Server IP address to filter.
        server_port (int): Server port number to filter.
    """
    load_layer("http")
    packets = rdpcap(pcap_file)
    request_times = {}
    latencies = []

    for packet in packets:
        if packet.haslayer(IP) and packet.haslayer(TCP):
            src_ip = packet[IP].src
            dest_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dest_port = packet[TCP].dport

            if packet.haslayer(HTTP) and packet.haslayer(HTTPRequest):
                if dest_ip == server_ip and dest_port == int(server_port):
                    request_times[(src_ip, src_port, dest_ip, dest_port)] = packet.time

            elif packet.haslayer(HTTP) and packet.haslayer(HTTPResponse):
                if src_ip == server_ip and src_port == int(server_port):
                    request_key = (dest_ip, dest_port, src_ip, src_port)
                    if request_key in request_times:
                        latency = packet.time - request_times[request_key]
                        latencies.append(latency)
                        del request_times[request_key]

    latencies = list(map(float, latencies))
    if latencies:
        avg_latency = sum(latencies) / len(latencies)
        logging.info(f"AVERAGE LATENCY: {avg_latency:.5f}")
    else:
        avg_latency = 0.0
        logging.warning("No HTTP latencies found in the capture.")

    percentiles = [
        percentile(latencies, p)
        for p in (0.25, 0.50, 0.75, 0.95, 0.99)
    ]
    logging.info(
        "PERCENTILES: 25th=%.5f 50th=%.5f 75th=%.5f 95th=%.5f 99th=%.5f",
        *percentiles
    )

    modeled, measured = exponential_distribution(latencies, avg_latency)
    if modeled and measured:
        kl_divergence = find_divergence(measured, modeled)
        logging.info(f"KL DIVERGENCE: {kl_divergence:.5f}")


# -------------------- CLI --------------------

def parse_args():
    parser = argparse.ArgumentParser(description="Measure HTTP server latency from a PCAP file.")
    parser.add_argument("pcap_file", help="Input PCAP file")
    parser.add_argument("server_ip", help="Server IP address")
    parser.add_argument("server_port", type=int, help="Server port number")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    return parser.parse_args()


def main():
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s"
    )
    measure(args.pcap_file, args.server_ip, args.server_port)


if __name__ == "__main__":
    main()
