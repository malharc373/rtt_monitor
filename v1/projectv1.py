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


def generate_trace():
    categories = {
        'LAN (Wired)':     dict(rtt_base=1.2,  rtt_std=0.4,  n_flows=15, spike_prob=0.04),
        'Campus WiFi':     dict(rtt_base=8.5,  rtt_std=3.2,  n_flows=15, spike_prob=0.15),
        'Remote Internet': dict(rtt_base=45.0, rtt_std=12.0, n_flows=10, spike_prob=0.10),
    }
    records = []
    for cat, c in categories.items():
        pfx = {'LAN (Wired)': '192.168.1', 'Campus WiFi': '192.168.2', 'Remote Internet': '10.0.5'}[cat]
        for f in range(c['n_flows']):
            src = f"{pfx}.{random.randint(2,254)}"
            dst = f"172.16.{random.randint(1,5)}.{random.randint(2,254)}"
            sp  = random.randint(49152, 65535)
            dp  = random.choice([80, 443, 22, 8080])
            t0  = random.uniform(0, 100)
            for i in range(random.randint(25, 90)):
                t   = t0 + i * random.uniform(0.05, 0.4)
                rtt = max(0.1, np.random.normal(c['rtt_base'], c['rtt_std']))
                if random.random() < c['spike_prob']:
                    rtt *= random.uniform(3, 9)
                records.append(dict(
                    category=cat,
                    flow_id=f"{src}:{sp}->{dst}:{dp}",
                    src_ip=src, dst_ip=dst,
                    time_s=round(t, 4),
                    rtt_ms=round(rtt, 4)
                ))
    df = pd.DataFrame(records).sort_values('time_s').reset_index(drop=True)
    df.to_csv('output/rtt_data.csv', index=False)
    print(f"[✓] Trace: {len(df)} RTT samples, {df['flow_id'].nunique()} flows\n")
    return df


def compute_stats(df):
    flow_stats = df.groupby(['category','flow_id'])['rtt_ms'].agg(
        count='count',
        mean='mean',
        std='std',
        p50=lambda x: np.percentile(x,50),
        p90=lambda x: np.percentile(x,90),
        p95=lambda x: np.percentile(x,95),
        max='max'
    ).round(3).reset_index()
    flow_stats.to_csv('output/flow_stats.csv', index=False)

    cat_stats = df.groupby('category')['rtt_ms'].agg(
        Samples='count',
        Mean_ms='mean',
        Std_ms='std',
        Min_ms='min',
        P50_ms=lambda x: np.percentile(x,50),
        P90_ms=lambda x: np.percentile(x,90),
        P95_ms=lambda x: np.percentile(x,95),
        Max_ms='max'
    ).round(3)
    cat_stats.to_csv('output/category_stats.csv')

    print("=== Per-Category RTT Summary ===")
    print(cat_stats.to_string())
    print()
    return flow_stats, cat_stats


def detect_spikes(df, multiplier=2.5):
    df = df.copy()
    medians = df.groupby('flow_id')['rtt_ms'].transform('median')
    df['is_spike'] = df['rtt_ms'] > (multiplier * medians)

    summary = df.groupby('category').apply(
        lambda g: pd.Series({
            'Total Samples': len(g),
            'Spikes Detected': g['is_spike'].sum(),
            'Spike Rate (%)': round(g['is_spike'].mean() * 100, 2)
        })
    )
    summary.to_csv('output/spike_summary.csv')
    print("=== Congestion/Spike Detection ===")
    print(summary.to_string())
    print()
    return df


palette = {
    'LAN (Wired)':     '#01696f',
    'Campus WiFi':     '#d19900',
    'Remote Internet': '#a12c7b'
}


def plot_all(df, cat_stats):
    fig = plt.figure(figsize=(18, 15))
    fig.patch.set_facecolor('#f7f6f2')
    gs = gridspec.GridSpec(3, 2, figure=fig, hspace=0.48, wspace=0.32)

    cats = list(palette.keys())

    ax1 = fig.add_subplot(gs[0, :])
    for cat in cats:
        data = df[df['category'] == cat]['rtt_ms']
        ax1.hist(data, bins=60, alpha=0.55, label=cat,
                 color=palette[cat], edgecolor='white', linewidth=0.3)
    ax1.set_title('RTT Distribution by Network Category', fontsize=14, fontweight='bold', pad=10)
    ax1.set_xlabel('RTT (ms)', fontsize=11)
    ax1.set_ylabel('Frequency', fontsize=11)
    ax1.legend(fontsize=10)
    ax1.set_xlim(0, 200)
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
    ax2.set_xticks(range(1, len(cats)+1))
    ax2.set_xticklabels([c.replace(' ','\n') for c in cats], fontsize=9)
    ax2.set_title('RTT Spread per Category (Box Plot)', fontsize=12, fontweight='bold')
    ax2.set_ylabel('RTT (ms)', fontsize=11)
    ax2.set_ylim(0, 250)
    ax2.set_facecolor('#fafaf8')

    ax3 = fig.add_subplot(gs[1, 1])
    percentiles = ['P50_ms', 'P90_ms', 'P95_ms']
    x = np.arange(len(cats))
    width = 0.25
    colors_p = ['#01696f', '#d19900', '#a12c7b']
    for i, (p, col) in enumerate(zip(percentiles, colors_p)):
        vals = [cat_stats.loc[c, p] for c in cats]
        bars = ax3.bar(x + i*width, vals, width, label=p.replace('_ms',''),
                       color=col, alpha=0.82, edgecolor='white')
        for bar, v in zip(bars, vals):
            ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5,
                     f'{v:.1f}', ha='center', va='bottom', fontsize=7.5)
    ax3.set_xticks(x + width)
    ax3.set_xticklabels([c.replace(' ','\n') for c in cats], fontsize=9)
    ax3.set_title('RTT Percentiles (P50/P90/P95)', fontsize=12, fontweight='bold')
    ax3.set_ylabel('RTT (ms)', fontsize=11)
    ax3.legend(fontsize=9)
    ax3.set_facecolor('#fafaf8')

    ax4 = fig.add_subplot(gs[2, :])
    for cat in cats:
        flow = df[df['category'] == cat].groupby('flow_id').size().idxmax()
        fdata = df[df['flow_id'] == flow].sort_values('time_s')
        ax4.plot(fdata['time_s'], fdata['rtt_ms'],
                 color=palette[cat], alpha=0.8, linewidth=1.2, label=f"{cat} (busiest flow)")
        spikes = fdata[fdata['rtt_ms'] > 2.5 * fdata['rtt_ms'].median()]
        ax4.scatter(spikes['time_s'], spikes['rtt_ms'],
                    color=palette[cat], s=40, zorder=5, marker='x')

    ax4.set_title('RTT over Time — One Representative Flow per Category  (✗ = detected spike)',
                  fontsize=12, fontweight='bold')
    ax4.set_xlabel('Time (seconds)', fontsize=11)
    ax4.set_ylabel('RTT (ms)', fontsize=11)
    ax4.legend(fontsize=9)
    ax4.set_facecolor('#fafaf8')

    fig.suptitle('Continuous RTT Monitoring & Path Quality Analysis\n'
                 'Passive TCP Measurement — Inspired by Dart (Princeton, SIGCOMM 2022)',
                 fontsize=15, fontweight='bold', y=0.98)

    plt.savefig('output/rtt_analysis.png', dpi=150, bbox_inches='tight',
                facecolor=fig.get_facecolor())
    plt.close()
    print("[✓] Plot saved → output/rtt_analysis.png")


def parse_pcap(filepath):
    """Parse a pcap file and extract RTT samples using SEQ/ACK matching."""
    from scapy.all import rdpcap, TCP, IP

    pkts = rdpcap(filepath)
    seq_table = {}
    records   = []

    for pkt in pkts:
        if not (IP in pkt and TCP in pkt):
            continue
        ip, tcp = pkt[IP], pkt[TCP]
        ts   = float(pkt.time)
        fwd  = (ip.src, tcp.sport, ip.dst, tcp.dport)
        rev  = (ip.dst, tcp.dport, ip.src, tcp.sport)
        fid  = f"{ip.src}:{tcp.sport}->{ip.dst}:{tcp.dport}"

        if tcp.flags & 0x02:  # SYN
            continue

        payload_len = len(tcp.payload)

        if payload_len > 0:
            expected_ack = tcp.seq + payload_len
            key = (fwd, expected_ack)
            seq_table[key] = (ts, fid)

        if tcp.flags & 0x10:  # ACK
            key = (rev, tcp.ack)
            if key in seq_table:
                t_seq, flow_id = seq_table.pop(key)
                rtt_ms = (ts - t_seq) * 1000
                if 0 < rtt_ms < 5000:
                    records.append(dict(
                        flow_id=flow_id,
                        src_ip=ip.dst, dst_ip=ip.src,
                        time_s=round(ts, 6),
                        rtt_ms=round(rtt_ms, 4),
                        category='PCAP Traffic'
                    ))

    df = pd.DataFrame(records)
    print(f"[✓] Parsed {len(df)} RTT samples from {filepath}")
    return df


if __name__ == '__main__':
    print("\n" + "="*55)
    print("  RTT Monitoring Tool — Starting")
    print("="*55 + "\n")

    df = generate_trace()
    flow_stats, cat_stats = compute_stats(df)
    df = detect_spikes(df)
    plot_all(df, cat_stats)

    print("\n[✓] All outputs saved to ./output/")
    print("    rtt_data.csv        — raw RTT samples")
    print("    flow_stats.csv      — per-flow statistics")
    print("    category_stats.csv  — per-category summary")
    print("    spike_summary.csv   — congestion detection results")
    print("    rtt_analysis.png    — all 4 plots\n")
