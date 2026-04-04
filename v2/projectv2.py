import random, os
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import seaborn as sns
from collections import defaultdict

random.seed(42)
np.random.seed(42)
os.makedirs('output', exist_ok=True)


def parse_real_pcap(filepath):
    from scapy.all import rdpcap, TCP, IP

    pkts      = rdpcap(filepath)
    records   = []
    syn_table = {}
    seq_table = {}

    def classify(dport, sport):
        if dport in (80, 8080) or sport in (80, 8080):
            return 'HTTP (Port 80)'
        elif dport == 443 or sport == 443:
            return 'HTTPS / Remote (Port 443)'
        elif dport in (22, 21, 25, 53) or sport in (22, 21, 25, 53):
            return 'Other Services'
        else:
            return 'Unknown TCP'

    for pkt in pkts:
        if not (IP in pkt and TCP in pkt):
            continue
        ip, tcp     = pkt[IP], pkt[TCP]
        ts          = float(pkt.time)
        fwd         = (ip.src, tcp.sport, ip.dst, tcp.dport)
        rev         = (ip.dst, tcp.dport, ip.src, tcp.sport)
        fid         = f"{ip.src}:{tcp.sport}->{ip.dst}:{tcp.dport}"
        cat         = classify(tcp.dport, tcp.sport)
        payload_len = len(bytes(tcp.payload))

        # Method 1: SYN → SYN-ACK
        if (tcp.flags & 0x02) and not (tcp.flags & 0x10):
            syn_table[fwd] = ts

        if (tcp.flags & 0x02) and (tcp.flags & 0x10):
            if rev in syn_table:
                rtt_ms = (ts - syn_table.pop(rev)) * 1000
                if 0 < rtt_ms < 5000:
                    records.append(dict(
                        category=cat, flow_id=fid,
                        src_ip=ip.src, dst_ip=ip.dst,
                        time_s=round(ts, 6), rtt_ms=round(rtt_ms, 4),
                        method='SYN-SYNACK'
                    ))

        # Method 2: Data → ACK
        if payload_len > 0 and not (tcp.flags & 0x02):
            seq_table[(fwd, tcp.seq + payload_len)] = (ts, fid, ip.src, ip.dst, cat)

        if tcp.flags & 0x10:
            key = (rev, tcp.ack)
            if key in seq_table:
                t_seq, flow_id, src, dst, c = seq_table.pop(key)
                rtt_ms = (ts - t_seq) * 1000
                if 0 < rtt_ms < 5000:
                    records.append(dict(
                        category=c, flow_id=flow_id,
                        src_ip=src, dst_ip=dst,
                        time_s=round(ts, 6), rtt_ms=round(rtt_ms, 4),
                        method='DATA-ACK'
                    ))

    print(f"[✓] Extracted {len(records)} RTT samples from {filepath}")
    return records


def compute_stats(df):
    flow_stats = df.groupby(['category', 'flow_id'])['rtt_ms'].agg(
        count='count',
        mean='mean',
        std='std',
        p50=lambda x: np.percentile(x, 50),
        p90=lambda x: np.percentile(x, 90),
        p95=lambda x: np.percentile(x, 95),
        max='max'
    ).round(3).reset_index()
    flow_stats.to_csv('output/flow_stats.csv', index=False)

    cat_stats = df.groupby('category')['rtt_ms'].agg(
        Samples='count',
        Mean_ms='mean',
        Std_ms='std',
        Min_ms='min',
        P50_ms=lambda x: np.percentile(x, 50),
        P90_ms=lambda x: np.percentile(x, 90),
        P95_ms=lambda x: np.percentile(x, 95),
        Max_ms='max'
    ).round(3)
    cat_stats.to_csv('output/category_stats.csv')

    print("=== Per-Category RTT Summary ===")
    print(cat_stats.to_string())
    print()
    return flow_stats, cat_stats


def detect_spikes(df, multiplier=2.5):
    df      = df.copy()
    medians = df.groupby('flow_id')['rtt_ms'].transform('median')
    df['is_spike'] = df['rtt_ms'] > (multiplier * medians)

    summary = df.groupby('category').apply(
        lambda g: pd.Series({
            'Total Samples':   len(g),
            'Spikes Detected': int(g['is_spike'].sum()),
            'Spike Rate (%)':  round(g['is_spike'].mean() * 100, 2)
        }),
        include_groups=False
    )
    summary.to_csv('output/spike_summary.csv')
    print("=== Congestion/Spike Detection ===")
    print(summary.to_string())
    print()
    return df


COLOR_POOL = ['#01696f', '#d19900', '#a12c7b', '#006494', '#437a22', '#a13544']

def make_palette(cats):
    return {cat: COLOR_POOL[i % len(COLOR_POOL)] for i, cat in enumerate(cats)}


def plot_all(df, cat_stats):
    cats    = sorted(df['category'].unique().tolist())
    palette = make_palette(cats)

    fig = plt.figure(figsize=(18, 15))
    fig.patch.set_facecolor('#f7f6f2')
    gs  = gridspec.GridSpec(3, 2, figure=fig, hspace=0.48, wspace=0.32)

    ax1 = fig.add_subplot(gs[0, :])
    for cat in cats:
        data = df[df['category'] == cat]['rtt_ms']
        ax1.hist(data, bins=60, alpha=0.55, label=cat,
                 color=palette[cat], edgecolor='white', linewidth=0.3)
    ax1.set_title('RTT Distribution by Network Category',
                  fontsize=14, fontweight='bold', pad=10)
    ax1.set_xlabel('RTT (ms)', fontsize=11)
    ax1.set_ylabel('Frequency', fontsize=11)
    ax1.legend(fontsize=10)
    p95_max = float(cat_stats['P95_ms'].max())
    ax1.set_xlim(0, min(p95_max * 1.5, 600))
    ax1.set_facecolor('#fafaf8')

    ax2 = fig.add_subplot(gs[1, 0])
    data_list = [df[df['category'] == c]['rtt_ms'].values for c in cats]
    bp = ax2.boxplot(data_list, patch_artist=True, notch=False,
                     medianprops=dict(color='white', linewidth=2),
                     whiskerprops=dict(linewidth=1.2),
                     capprops=dict(linewidth=1.2))
    for patch, cat in zip(bp['boxes'], cats):
        patch.set_facecolor(palette[cat])
        patch.set_alpha(0.75)
    ax2.set_xticks(range(1, len(cats) + 1))
    ax2.set_xticklabels([c.replace(' ', '\n') for c in cats], fontsize=9)
    ax2.set_title('RTT Spread per Category (Box Plot)',
                  fontsize=12, fontweight='bold')
    ax2.set_ylabel('RTT (ms)', fontsize=11)
    ax2.set_facecolor('#fafaf8')

    ax3 = fig.add_subplot(gs[1, 1])
    x   = np.arange(len(cats))
    w   = 0.25
    for i, (metric, label) in enumerate([('Mean_ms', 'Mean'),
                                          ('P50_ms',  'P50 (Median)'),
                                          ('P95_ms',  'P95')]):
        vals = [cat_stats.loc[c, metric] if c in cat_stats.index else 0
                for c in cats]
        ax3.bar(x + i * w, vals, width=w, label=label,
                color=COLOR_POOL[i], alpha=0.82, edgecolor='white')
    ax3.set_xticks(x + w)
    ax3.set_xticklabels([c.replace(' ', '\n') for c in cats], fontsize=9)
    ax3.set_title('RTT Percentile Comparison per Category',
                  fontsize=12, fontweight='bold')
    ax3.set_ylabel('RTT (ms)', fontsize=11)
    ax3.legend(fontsize=9)
    ax3.set_facecolor('#fafaf8')

    ax4 = fig.add_subplot(gs[2, :])
    for cat in cats:
        sub  = df[df['category'] == cat].copy()
        fid  = sub.groupby('flow_id').size().idxmax()
        flow = sub[sub['flow_id'] == fid].sort_values('time_s')
        ax4.plot(flow['time_s'], flow['rtt_ms'],
                 label=cat, color=palette[cat],
                 linewidth=1.4, alpha=0.85)
        spikes = flow[flow['is_spike']]
        if len(spikes):
            ax4.scatter(spikes['time_s'], spikes['rtt_ms'],
                        color=palette[cat], s=40, zorder=5, marker='x')
    ax4.set_title(
        'RTT over Time — One Representative Flow per Category  (✗ = detected spike)',
        fontsize=12, fontweight='bold')
    ax4.set_xlabel('Time (seconds)', fontsize=11)
    ax4.set_ylabel('RTT (ms)', fontsize=11)
    ax4.legend(fontsize=9)
    ax4.set_facecolor('#fafaf8')

    fig.suptitle(
        'Continuous RTT Monitoring & Path Quality Analysis\n'
        'Passive TCP Measurement — Inspired by Dart (Princeton, SIGCOMM 2022)',
        fontsize=15, fontweight='bold', y=0.98)

    plt.savefig('output/rtt_analysis.png', dpi=150,
                bbox_inches='tight', facecolor=fig.get_facecolor())
    plt.close()
    print("[✓] Plot saved → output/rtt_analysis.png")


if __name__ == '__main__':
    print("\n" + "=" * 55)
    print("  RTT Monitoring Tool — REAL DATA MODE")
    print("=" * 55 + "\n")

    records = parse_real_pcap('real/capture.pcap')

    if not records:
        print("[!] No RTT samples extracted. Check pcap file.")
        exit(1)

    df = pd.DataFrame(records).sort_values('time_s').reset_index(drop=True)
    df.to_csv('output/rtt_data_real.csv', index=False)

    print(f"\nCategories found : {df['category'].value_counts().to_dict()}")
    print(f"Methods used     : {df['method'].value_counts().to_dict()}\n")

    flow_stats, cat_stats = compute_stats(df)
    df = detect_spikes(df)
    plot_all(df, cat_stats)

    print("\n[✓] All outputs saved to ./output/")
    print("    rtt_data_real.csv   — raw RTT samples")
    print("    flow_stats.csv      — per-flow statistics")
    print("    category_stats.csv  — per-category summary")
    print("    spike_summary.csv   — congestion detection")
    print("    rtt_analysis.png    — result plots\n")
