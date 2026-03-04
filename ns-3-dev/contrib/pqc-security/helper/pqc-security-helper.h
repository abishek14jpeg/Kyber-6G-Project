/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#ifndef PQC_SECURITY_HELPER_H
#define PQC_SECURITY_HELPER_H

#include "ns3/net-device-container.h"
#include "ns3/node-container.h"
#include "ns3/object-factory.h"
#include "ns3/crystals-kyber-kem.h"
#include "ns3/ml-dsa-signer.h"
#include "ns3/pqc-handover-manager.h"
#include "ns3/pqc-metrics-collector.h"
#include "ns3/pqc-pdcp-layer.h"
#include "ns3/pqc-rrc-extension.h"
#include "ns3/quantum-attacker.h"

#include <map>
#include <vector>

namespace ns3
{
namespace pqc
{

/**
 * \brief One-line API to install the PQC security framework on NR devices.
 *
 * Usage:
 * \code
 *   PqcSecurityHelper pqc;
 *   pqc.SetKyberLevel(CrystalsKyberKem::KYBER_768);
 *   pqc.SetMlDsaLevel(MlDsaSigner::ML_DSA_65);
 *   pqc.SetEnableHybridKem(true);
 *   pqc.SetEnableQuantumAttacker(true);
 *   pqc.Install(gnbNetDevices, ueNetDevices);
 *
 *   // After simulation:
 *   pqc.GetMetricsCollector()->ExportToCsv("results.csv");
 * \endcode
 */
class PqcSecurityHelper
{
  public:
    PqcSecurityHelper();
    ~PqcSecurityHelper();

    // ── Configuration ──

    void SetKyberLevel(CrystalsKyberKem::SecurityLevel level);
    void SetMlDsaLevel(MlDsaSigner::Level level);
    void SetEnableHybridKem(bool enable);
    void SetEnableAuthentication(bool enable);
    void SetEnableQuantumAttacker(bool enable);
    void SetEnableForwardSecrecy(bool enable);

    // ── Installation ──

    /**
     * \brief Install PQC security on all gNB and UE devices.
     *
     * Creates PqcRrcExtension and PqcPdcpLayer for each device,
     * performs the hybrid PQC handshake, and installs session keys.
     *
     * \param gnbDevices Container of gNB net devices.
     * \param ueDevices Container of UE net devices.
     */
    void Install(NetDeviceContainer gnbDevices, NetDeviceContainer ueDevices);

    /**
     * \brief Execute all PQC handshakes at the specified time.
     *
     * Schedules the hybrid KEM handshake for each UE-gNB pair.
     * \param handshakeTime When to begin the handshakes.
     */
    void ScheduleHandshakes(Time handshakeTime);

    /**
     * \brief Run the quantum attacker analysis after simulation.
     */
    void RunQuantumAttack();

    // ── Accessors ──

    Ptr<PqcMetricsCollector> GetMetricsCollector() const;
    Ptr<QuantumAttacker> GetQuantumAttacker() const;

    /**
     * \brief Get the PQC RRC extension for a specific UE (by index).
     */
    Ptr<PqcRrcExtension> GetUeRrcExtension(uint32_t ueIndex) const;

    /**
     * \brief Get the PQC PDCP layer for a specific UE (by index).
     */
    Ptr<PqcPdcpLayer> GetUePdcpLayer(uint32_t ueIndex) const;

    /**
     * \brief Get the handover manager for a specific UE (by index).
     */
    Ptr<PqcHandoverManager> GetHandoverManager(uint32_t ueIndex) const;

  private:
    // Configuration
    CrystalsKyberKem::SecurityLevel m_kyberLevel;
    MlDsaSigner::Level m_mlDsaLevel;
    bool m_enableHybrid;
    bool m_enableAuth;
    bool m_enableQuantumAttacker;
    bool m_enableForwardSecrecy;

    // Per-device PQC objects
    struct UePqcContext
    {
        Ptr<PqcRrcExtension> rrcExtension;
        Ptr<PqcPdcpLayer> pdcpLayer;
        Ptr<PqcHandoverManager> handoverManager;
    };

    struct GnbPqcContext
    {
        Ptr<PqcRrcExtension> rrcExtension;
        Ptr<PqcPdcpLayer> pdcpLayer;
    };

    std::vector<UePqcContext> m_ueContexts;
    std::vector<GnbPqcContext> m_gnbContexts;

    Ptr<PqcMetricsCollector> m_metricsCollector;
    Ptr<QuantumAttacker> m_quantumAttacker;

    // Internal methods
    void DoHandshake(uint32_t ueIndex, uint32_t gnbIndex);
    void ConnectTraces();
};

} // namespace pqc
} // namespace ns3

#endif // PQC_SECURITY_HELPER_H
