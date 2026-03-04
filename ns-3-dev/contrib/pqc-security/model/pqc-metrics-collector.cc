/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#include "pqc-metrics-collector.h"

#include "ns3/log.h"
#include "ns3/simulator.h"

#include <iomanip>

namespace ns3
{
namespace pqc
{

NS_LOG_COMPONENT_DEFINE("PqcMetricsCollector");
NS_OBJECT_ENSURE_REGISTERED(PqcMetricsCollector);

TypeId
PqcMetricsCollector::GetTypeId()
{
    static TypeId tid = TypeId("ns3::pqc::PqcMetricsCollector")
                            .SetParent<Object>()
                            .SetGroupName("PqcSecurity")
                            .AddConstructor<PqcMetricsCollector>();
    return tid;
}

PqcMetricsCollector::PqcMetricsCollector()
{
}

PqcMetricsCollector::~PqcMetricsCollector()
{
}

void
PqcMetricsCollector::Record(const std::string& name, double value)
{
    m_metrics[name].Add(Simulator::Now(), value);
}

// ── Control plane ──
void PqcMetricsCollector::RecordRrcRequestSize(uint32_t bytes) { Record("rrc_request_size_bytes", bytes); }
void PqcMetricsCollector::RecordRrcSetupSize(uint32_t bytes) { Record("rrc_setup_size_bytes", bytes); }
void PqcMetricsCollector::RecordPdcpHeaderOverhead(uint32_t orig, uint32_t enc) { Record("pdcp_overhead_bytes", enc - orig); }

// ── Latency ──
void PqcMetricsCollector::RecordRrcSetupLatency(Time t) { Record("rrc_setup_latency_us", t.GetMicroSeconds()); }
void PqcMetricsCollector::RecordKeyGenLatency(Time t) { Record("keygen_latency_us", t.GetMicroSeconds()); }
void PqcMetricsCollector::RecordEncapsLatency(Time t) { Record("encaps_latency_us", t.GetMicroSeconds()); }
void PqcMetricsCollector::RecordDecapsLatency(Time t) { Record("decaps_latency_us", t.GetMicroSeconds()); }
void PqcMetricsCollector::RecordAuthSignLatency(Time t) { Record("auth_sign_latency_us", t.GetMicroSeconds()); }
void PqcMetricsCollector::RecordAuthVerifyLatency(Time t) { Record("auth_verify_latency_us", t.GetMicroSeconds()); }
void PqcMetricsCollector::RecordHandshakeLatency(Time t) { Record("handshake_latency_us", t.GetMicroSeconds()); }
void PqcMetricsCollector::RecordE2eApplicationLatency(Time t) { Record("e2e_app_latency_ms", t.GetMilliSeconds()); }
void PqcMetricsCollector::RecordQueueingDelay(Time t) { Record("queueing_delay_us", t.GetMicroSeconds()); }

// ── Application Performance ──
void PqcMetricsCollector::RecordThroughputBytes(uint32_t b) { Record("throughput_bytes", b); }
void PqcMetricsCollector::RecordPacketLoss() { Record("packet_loss_events", 1); }

// ── Handover ──
void PqcMetricsCollector::RecordHandoverInterruptionTime(Time t) { Record("ho_interruption_time_ms", t.GetMilliSeconds()); }
void PqcMetricsCollector::RecordHandoverRekeyTime(Time t) { Record("ho_rekey_time_us", t.GetMicroSeconds()); }
void PqcMetricsCollector::RecordHandoverCount(uint32_t c) { Record("ho_count", c); }
void PqcMetricsCollector::RecordHandoverFailure() { Record("ho_failures", 1); }

// ── Fragmentation ──
void PqcMetricsCollector::RecordRlcSegmentation(uint32_t orig, uint32_t segs) { Record("rlc_segments_per_pdu", segs); Record("rlc_original_pdu_size", orig); }

// ── Encryption ──
void PqcMetricsCollector::RecordEncryptionLatency(Time t) { Record("encrypt_latency_us", t.GetMicroSeconds()); }
void PqcMetricsCollector::RecordDecryptionLatency(Time t) { Record("decrypt_latency_us", t.GetMicroSeconds()); }

// ── Resource Usage ──
void PqcMetricsCollector::RecordCryptoEnergyMicroJoules(double e) { Record("crypto_energy_uj", e); }
void PqcMetricsCollector::RecordCryptoMemoryBytes(uint32_t m) { Record("crypto_memory_bytes", m); }

PqcMetricsCollector::MetricStats
PqcMetricsCollector::GetStats(const std::string& metricName) const
{
    MetricStats stats;
    auto it = m_metrics.find(metricName);
    if (it == m_metrics.end())
    {
        return stats;
    }

    const auto& series = it->second;
    stats.count = static_cast<uint32_t>(series.samples.size());
    stats.mean = series.Mean();
    stats.stddev = series.StdDev();
    stats.min = series.Min();
    stats.max = series.Max();
    stats.p50 = series.Percentile(50);
    stats.p95 = series.Percentile(95);
    stats.p99 = series.Percentile(99);

    return stats;
}

void
PqcMetricsCollector::ExportToCsv(const std::string& filename)
{
    std::ofstream csv(filename);
    if (!csv.is_open())
    {
        NS_LOG_ERROR("PqcMetrics: Cannot open " << filename << " for writing!");
        return;
    }

    // Header
    csv << "metric,count,mean,stddev,min,max,p50,p95,p99\n";

    for (const auto& [name, series] : m_metrics)
    {
        auto stats = GetStats(name);
        csv << name << ","
            << stats.count << ","
            << std::fixed << std::setprecision(3)
            << stats.mean << ","
            << stats.stddev << ","
            << stats.min << ","
            << stats.max << ","
            << stats.p50 << ","
            << stats.p95 << ","
            << stats.p99 << "\n";
    }

    csv.close();
    NS_LOG_INFO("PqcMetrics: Exported " << m_metrics.size() << " metrics to " << filename);

    // Also export time-series data
    std::string tsFilename = filename.substr(0, filename.find_last_of('.')) + "_timeseries.csv";
    std::ofstream tsCsv(tsFilename);
    if (tsCsv.is_open())
    {
        tsCsv << "metric,time_ms,value\n";
        for (const auto& [name, series] : m_metrics)
        {
            for (const auto& [t, v] : series.samples)
            {
                tsCsv << name << "," << std::fixed << std::setprecision(6)
                       << t.GetMilliSeconds() << "," << v << "\n";
            }
        }
        tsCsv.close();
        NS_LOG_INFO("PqcMetrics: Exported time-series to " << tsFilename);
    }
}

void
PqcMetricsCollector::PrintSummary()
{
    NS_LOG_INFO("");
    NS_LOG_INFO("╔════════════════════════════════════════════════════════╗");
    NS_LOG_INFO("║           PQC METRICS SUMMARY                        ║");
    NS_LOG_INFO("╚════════════════════════════════════════════════════════╝");

    for (const auto& [name, series] : m_metrics)
    {
        auto stats = GetStats(name);
        if (stats.count == 0) continue;

        NS_LOG_INFO("  " << name << ":");
        NS_LOG_INFO("    count=" << stats.count
                    << " mean=" << std::fixed << std::setprecision(1) << stats.mean
                    << " stddev=" << stats.stddev
                    << " p50=" << stats.p50
                    << " p95=" << stats.p95
                    << " p99=" << stats.p99);
    }
    NS_LOG_INFO("");
}

} // namespace pqc
} // namespace ns3
