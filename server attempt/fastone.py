
import os
import csv
import multiprocessing
from scapy.all import IP, ICMP, sr, conf

# ─── CONFIG ─────────────────────────────────────────────────────────────
INPUT_FILE  = "v4.addrs"
OUTPUT_FILE = "results.csv"

SEND_SIZE   = 500    # IPs per chunk — smaller = more accurate timeout accounting
NUM_WORKERS = 14      # parallel sender processes
TIMEOUT     = 0.5     # seconds to wait after last packet (covers ~1.5s RTT)
RETRY       = 4      # resend unanswered packets this many times before giving up
INTER       = 0.009   # seconds between packets — prevents NIC burst drops
# ────────────────────────────────────────────────────────────────────────


def ping_chunk(args):
    chunk, chunk_id = args

    conf.use_pcap   = True
    conf.verb       = 0

   
    icmp_id = chunk_id & 0xFFFF

    packets = [IP(dst=ip, ttl=64) / ICMP(id=icmp_id, seq=i)
               for i, ip in enumerate(chunk)]

    ans, unans = sr(
        packets,
        timeout=TIMEOUT,
        retry=RETRY,
        inter=INTER,
        verbose=False,
        prebuild=True,
    )

    active = {snd.dst for snd, rcv in ans}
    return [(ip, "alive" if ip in active else "dead") for ip in chunk]


def result_writer(queue):
    with open(OUTPUT_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        while True:
            msg = queue.get()
            if msg == "kill":
                break
            writer.writerow(msg)
            f.flush()


def flush_results(results):
    for row in results:
        queue.put(row)


def file_chunker():
    # FIX 5: iterate `f` (the file object), not INPUT_FILE (the filename string)
    with open(INPUT_FILE) as f:
        chunk = []
        for line in f:
            ip = line.strip()
            if ip and not ip.startswith("#"):
                chunk.append(ip)
                if len(chunk) == SEND_SIZE:
                    yield chunk
                    chunk = []
        if chunk:
            yield chunk


if __name__ == "__main__":
    # Write CSV header
    with open(OUTPUT_FILE, "w", newline="") as f:
        csv.writer(f).writerow(["ip", "status"])

    manager = multiprocessing.Manager()
    queue   = manager.Queue()
    pool    = multiprocessing.Pool(processes=NUM_WORKERS)

    # One dedicated writer — never blocks a sender
    pool.apply_async(result_writer, (queue,))

    chunks  = list(file_chunker())
    total   = sum(len(c) for c in chunks)
    print(f"Loaded {total:,} IPs across {len(chunks)} chunks.")
    print(f"Workers: {NUM_WORKERS} | Chunk size: {SEND_SIZE} | "
          f"Timeout: {TIMEOUT}s | Retry: {RETRY}x | Inter: {INTER}s")

    workers = []
    for i, chunk in enumerate(chunks):
        task = pool.apply_async(
            ping_chunk,
            ((chunk, i),),
            callback=flush_results,
        )
        workers.append(task)

    done = 0
    for task in workers:
        task.get()
        done += 1
        if done % 20 == 0 or done == len(chunks):
            print(f"  {done}/{len(chunks)} chunks complete")

    queue.put("kill")
    pool.close()
    pool.join()
    print(f"Done! Results → {OUTPUT_FILE}")