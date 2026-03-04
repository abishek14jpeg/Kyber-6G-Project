/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#include "pqc-security-helper.h"

#include "ns3/boolean.h"
#include "ns3/log.h"
#include "ns3/simulator.h"

namespace ns3
{
namespace pqc
{

NS_LOG_COMPONENT_DEFINE("PqcSecurityHelper");

PqcSecurityHelper::PqcSecurityHelper()
    : m_kyberLevel(CrystalsKyberKem::KYBER_768),
      m_mlDsaLevel(MlDsaSigner::ML_DSA_65),
      m_enableHybrid(true),
      m_enableAuth(true),
      m_enableQuantumAttacker(false),
      m_enableForwardSecrecy(true)
{
    m_metricsCollector = CreateObject<PqcMetricsCollector>();
}

PqcSecurityHelper::~PqcSecurityHelper()
{
}

void PqcSecurityHelper::SetKyberLevel(CrystalsKyberKem::SecurityLevel level) { m_kyberLevel = level; }
void PqcSecurityHelper::SetMlDsaLevel(MlDsaSigner::Level level) { m_mlDsaLevel = level; }
void PqcSecurityHelper::SetEnableHybridKem(bool enable) { m_enableHybrid = enable; }
void PqcSecurityHelper::SetEnableAuthentication(bool enable) { m_enableAuth = enable; }
void PqcSecurityHelper::SetEnableQuantumAttacker(bool enable) { m_enableQuantumAttacker = enable; }
void PqcSecurityHelper::SetEnableForwardSecrecy(bool enable) { m_enableForwardSecrecy = enable; }

void
PqcSecurityHelper::Install(NetDeviceContainer gnbDevices, NetDeviceContainer ueDevices)
{
    NS_LOG_INFO("");
    NS_LOG_INFO("╔══════════════════════════════════════════════════════╗");
    NS_LOG_INFO("║  PQC Security Framework — Installing on NR devices  ║");
    NS_LOG_INFO("╚══════════════════════════════════════════════════════╝");
    NS_LOG_INFO("  Kyber level: " << m_kyberLevel);
    NS_LOG_INFO("  ML-DSA level: " << m_mlDsaLevel);
    NS_LOG_INFO("  Hybrid KEM: " << (m_enableHybrid ? "ENABLED" : "DISABLED"));
    NS_LOG_INFO("  Authentication: " << (m_enableAuth ? "ENABLED" : "DISABLED"));
    NS_LOG_INFO("  Quantum Attacker: " << (m_enableQuantumAttacker ? "ENABLED" : "DISABLED"));
    NS_LOG_INFO("  Forward Secrecy: " << (m_enableForwardSecrecy ? "ENABLED" : "DISABLED"));
    NS_LOG_INFO("");

    // Create PQC contexts for each gNB
    for (uint32_t i = 0; i < gnbDevices.GetN(); ++i)
    {
        GnbPqcContext ctx;

        ctx.rrcExtension = CreateObject<PqcRrcExtension>();
        ctx.rrcExtension->SetRole(PqcRrcExtension::GNB_ROLE);
        ctx.rrcExtension->SetAttribute("EnableAuthentication", BooleanValue(m_enableAuth));

        ctx.pdcpLayer = CreateObject<PqcPdcpLayer>();
        ctx.rrcExtension->SetPdcpLayer(ctx.pdcpLayer);

        m_gnbContexts.push_back(ctx);

        NS_LOG_INFO("  gNB #" << i << ": PQC RRC Extension + PDCP layer installed");
    }

    // Create PQC contexts for each UE
    for (uint32_t i = 0; i < ueDevices.GetN(); ++i)
    {
        UePqcContext ctx;

        ctx.rrcExtension = CreateObject<PqcRrcExtension>();
        ctx.rrcExtension->SetRole(PqcRrcExtension::UE_ROLE);
        ctx.rrcExtension->SetAttribute("EnableAuthentication", BooleanValue(m_enableAuth));

        ctx.pdcpLayer = CreateObject<PqcPdcpLayer>();
        ctx.rrcExtension->SetPdcpLayer(ctx.pdcpLayer);

        if (m_enableForwardSecrecy)
        {
            ctx.handoverManager = CreateObject<PqcHandoverManager>();
            ctx.handoverManager->SetPdcpLayer(ctx.pdcpLayer);
        }

        m_ueContexts.push_back(ctx);

        NS_LOG_INFO("  UE #" << i << ": PQC RRC Extension + PDCP layer"
                    << (m_enableForwardSecrecy ? " + Handover Manager" : "") << " installed");
    }

    // Set up quantum attacker if enabled
    if (m_enableQuantumAttacker)
    {
        m_quantumAttacker = CreateObject<QuantumAttacker>();
        NS_LOG_INFO("  Quantum Attacker: INSTALLED (HNDL mode)");
    }

    // Connect trace sources to metrics collector
    ConnectTraces();

    NS_LOG_INFO("");
    NS_LOG_INFO("  Total: " << gnbDevices.GetN() << " gNBs + "
                << ueDevices.GetN() << " UEs secured");
}

void
PqcSecurityHelper::ScheduleHandshakes(Time handshakeTime)
{
    NS_LOG_INFO("Scheduling PQC handshakes at t=" << handshakeTime.As(Time::MS));

    // Schedule a handshake for each UE with the nearest gNB
    // In a multi-gNB scenario, this would use the attachment mapping
    for (uint32_t ueIdx = 0; ueIdx < m_ueContexts.size(); ++ueIdx)
    {
        uint32_t gnbIdx = ueIdx % m_gnbContexts.size(); // Round-robin for now

        // Stagger handshakes slightly to avoid simultaneous processing
        Time staggeredTime = handshakeTime + MicroSeconds(ueIdx * 100);

        Simulator::Schedule(staggeredTime,
                            &PqcSecurityHelper::DoHandshake,
                            this,
                            ueIdx,
                            gnbIdx);
    }
}

void
PqcSecurityHelper::DoHandshake(uint32_t ueIndex, uint32_t gnbIndex)
{
    NS_LOG_INFO("");
    NS_LOG_INFO("═══ PQC HANDSHAKE: UE #" << ueIndex << " <-> gNB #" << gnbIndex << " ═══");

    auto& ueCtx = m_ueContexts[ueIndex];
    auto& gnbCtx = m_gnbContexts[gnbIndex];

    // Step 1: UE generates Connection Request
    auto requestPayload = ueCtx.rrcExtension->GenerateConnectionRequest();
    m_metricsCollector->RecordRrcRequestSize(requestPayload.TotalSize());

    // Step 2: gNB processes request and generates Setup
    auto setupPayload = gnbCtx.rrcExtension->ProcessConnectionRequest(requestPayload);

    if (setupPayload.rejected)
    {
        NS_LOG_WARN("Handshake REJECTED for UE #" << ueIndex);
        return;
    }

    m_metricsCollector->RecordRrcSetupSize(setupPayload.TotalSize());

    // Step 3: UE completes key exchange
    auto sessionKeys = ueCtx.rrcExtension->CompleteKeyExchange(setupPayload);

    // Record metrics
    m_metricsCollector->RecordHandshakeLatency(
        ueCtx.rrcExtension->GetHandshakeProcessingTime());

    // Record in quantum attacker if enabled
    if (m_quantumAttacker)
    {
        QuantumAttacker::CapturedHandshake ch;
        ch.requestPayload = requestPayload;
        ch.setupPayload = setupPayload;
        ch.isHybrid = m_enableHybrid;
        ch.captureTime = Simulator::Now();
        m_quantumAttacker->CaptureHandshake(ueIndex, ch);
    }

    // Pre-compute handover keys if forward secrecy is enabled
    if (ueCtx.handoverManager)
    {
        ueCtx.handoverManager->PrecomputeHandoverKeys();
    }

    NS_LOG_INFO("═══ HANDSHAKE COMPLETE ═══");
    NS_LOG_INFO("");
}

void
PqcSecurityHelper::RunQuantumAttack()
{
    if (!m_quantumAttacker)
    {
        NS_LOG_WARN("Quantum attacker not enabled!");
        return;
    }

    auto report = m_quantumAttacker->AttemptRetroactiveDecryption();

    // Log the report to the metrics collector
    m_metricsCollector->RecordRrcRequestSize(0); // marker for report boundary
}

void
PqcSecurityHelper::ConnectTraces()
{
    // Connect UE trace sources to metrics collector
    for (auto& ctx : m_ueContexts)
    {
        ctx.rrcExtension->m_rrcRequestSizeTrace.ConnectWithoutContext(
            MakeCallback(&PqcMetricsCollector::RecordRrcRequestSize, m_metricsCollector));

        ctx.rrcExtension->m_handshakeLatencyTrace.ConnectWithoutContext(
            MakeCallback(&PqcMetricsCollector::RecordHandshakeLatency, m_metricsCollector));

        ctx.pdcpLayer->m_encryptLatencyTrace.ConnectWithoutContext(
            MakeCallback(&PqcMetricsCollector::RecordEncryptionLatency, m_metricsCollector));

        ctx.pdcpLayer->m_decryptLatencyTrace.ConnectWithoutContext(
            MakeCallback(&PqcMetricsCollector::RecordDecryptionLatency, m_metricsCollector));

        if (ctx.handoverManager)
        {
            ctx.handoverManager->m_handoverRekeyLatencyTrace.ConnectWithoutContext(
                MakeCallback(&PqcMetricsCollector::RecordHandoverRekeyTime, m_metricsCollector));

            ctx.handoverManager->m_handoverInterruptionTimeTrace.ConnectWithoutContext(
                MakeCallback(&PqcMetricsCollector::RecordHandoverInterruptionTime,
                             m_metricsCollector));
        }
    }

    // Connect gNB trace sources
    for (auto& ctx : m_gnbContexts)
    {
        ctx.rrcExtension->m_rrcSetupSizeTrace.ConnectWithoutContext(
            MakeCallback(&PqcMetricsCollector::RecordRrcSetupSize, m_metricsCollector));

        ctx.rrcExtension->m_processingTimeTrace.ConnectWithoutContext(
            MakeCallback(&PqcMetricsCollector::RecordRrcSetupLatency, m_metricsCollector));
    }
}

Ptr<PqcMetricsCollector>
PqcSecurityHelper::GetMetricsCollector() const
{
    return m_metricsCollector;
}

Ptr<QuantumAttacker>
PqcSecurityHelper::GetQuantumAttacker() const
{
    return m_quantumAttacker;
}

Ptr<PqcRrcExtension>
PqcSecurityHelper::GetUeRrcExtension(uint32_t ueIndex) const
{
    NS_ASSERT_MSG(ueIndex < m_ueContexts.size(), "UE index out of range");
    return m_ueContexts[ueIndex].rrcExtension;
}

Ptr<PqcPdcpLayer>
PqcSecurityHelper::GetUePdcpLayer(uint32_t ueIndex) const
{
    NS_ASSERT_MSG(ueIndex < m_ueContexts.size(), "UE index out of range");
    return m_ueContexts[ueIndex].pdcpLayer;
}

Ptr<PqcHandoverManager>
PqcSecurityHelper::GetHandoverManager(uint32_t ueIndex) const
{
    NS_ASSERT_MSG(ueIndex < m_ueContexts.size(), "UE index out of range");
    return m_ueContexts[ueIndex].handoverManager;
}

} // namespace pqc
} // namespace ns3
