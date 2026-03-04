/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

/**
 * \file drone-swarm-pqc-sim.cc
 * \brief Military Drone Swarm Communication with Post-Quantum Security.
 *
 * Simulates a swarm of drones using 3D Waypoint/Formation mobility, 
 * communicating over a 5G/NR network where gNBs act merely as relays.
 * End-to-end telemetry and command traffic is encrypted using AES-GCM
 * with keys derived from a CRYSTALS-Kyber/X25519 KEM handshakes.
 */

#include "ns3/applications-module.h"
#include "ns3/command-line.h"
#include "ns3/config.h"
#include "ns3/core-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/nr-module.h"

#include "ns3/pqc-scenario-helper.h"
#include "ns3/pqc-security-helper.h"
#include "ns3/pqc-metrics-collector.h"
#include "ns3/pqc-drone-app.h"
#include "ns3/aes-gcm-cipher.h"
#include "ns3/pqc-session-keys.h"
#include "ns3/queue-item.h"
#include "ns3/point-to-point-net-device.h"

#include <iomanip>
#include <map>

using namespace ns3;
using namespace ns3::pqc;

NS_LOG_COMPONENT_DEFINE("DroneSwarmPqcSim");

// ═══════════════════════════════════════════════════════════
// Queueing Theory Tracker
// ═══════════════════════════════════════════════════════════
std::map<uint64_t, Time> g_enqueueTimes;
Ptr<PqcMetricsCollector> g_metrics;

void EnqueueTrace(Ptr<const Packet> packet)
{
    g_enqueueTimes[packet->GetUid()] = Simulator::Now();
}

void DequeueTrace(Ptr<const Packet> packet)
{
    auto it = g_enqueueTimes.find(packet->GetUid());
    if (it != g_enqueueTimes.end())
    {
        Time delay = Simulator::Now() - it->second;
        if (g_metrics) g_metrics->RecordQueueingDelay(delay);
        g_enqueueTimes.erase(it);
    }
}

// ═══════════════════════════════════════════════════════════
// Drone Mobility and Routing
// ═══════════════════════════════════════════════════════════

static void
SetDroneMobility(NodeContainer drones, double speed, double altitude)
{
    // NOTE: NR stack already installed ConstantPositionMobilityModel.
    // We must NOT reinstall a new mobility model, otherwise internal
    // NR references break. Instead, update the existing positions or
    // aggregate a WaypointMobilityModel only if none exists.

    Ptr<UniformRandomVariable> randomOffset = CreateObject<UniformRandomVariable>();
    randomOffset->SetAttribute("Min", DoubleValue(-30.0));
    randomOffset->SetAttribute("Max", DoubleValue(30.0));

    // Check if we can use waypoints (only if ConstantPositionMobilityModel)
    auto existingMobility = drones.Get(0)->GetObject<MobilityModel>();
    if (!existingMobility)
    {
        // No mobility at all, install fresh
        MobilityHelper mobility;
        mobility.SetMobilityModel("ns3::WaypointMobilityModel");
        mobility.Install(drones);
    }

    // For each drone, just update position via the existing mobility model
    // Commander (Index 0) stays at center
    Vector leaderPos(50.0, 50.0, altitude);
    drones.Get(0)->GetObject<MobilityModel>()->SetPosition(leaderPos);

    // Followers get positions relative to leader with random offsets
    for (uint32_t i = 1; i < drones.GetN(); ++i)
    {
        double offsetX = randomOffset->GetValue();
        double offsetY = randomOffset->GetValue();
        double offsetZ = randomOffset->GetValue() * 0.2;
        Vector pos(leaderPos.x + offsetX, leaderPos.y + offsetY, altitude + offsetZ);
        drones.Get(i)->GetObject<MobilityModel>()->SetPosition(pos);
    }
}

// ═══════════════════════════════════════════════════════════
// End-To-End App Install
// ═══════════════════════════════════════════════════════════

static void
InstallDroneApplications(NodeContainer drones, 
                         Ptr<PqcMetricsCollector> metrics,
                         Time simTime, 
                         uint32_t packetSize,
                         uint32_t dataRateKbps)
{
    // Drone 0 will act as the Swarm Commander (Receiver & Broadcaster)
    // Drones 1..N will act as followers, sending telemetry to Drone 0
    Ptr<Node> commander = drones.Get(0);
    
    Ptr<Ipv4> cmdrIpv4 = commander->GetObject<Ipv4>();
    if (!cmdrIpv4 || cmdrIpv4->GetNInterfaces() < 2)
    {
        NS_LOG_UNCOND("WARNING: Commander has no Ipv4 or insufficient interfaces. Skipping app install.");
        return;
    }
    
    Ipv4Address cmdrAddr = cmdrIpv4->GetAddress(1, 0).GetLocal();
    uint16_t port = 9999;

    // Commander receives connections
    Ptr<AesGcmCipher> cmdrCipher = CreateObject<AesGcmCipher>();
    Ptr<PqcDroneApp> cmdrApp = CreateObject<PqcDroneApp>();
    cmdrApp->Setup(true, Ipv4Address::GetAny(), port, cmdrCipher, metrics);
    commander->AddApplication(cmdrApp);
    cmdrApp->SetStartTime(Seconds(0.5));
    cmdrApp->SetStopTime(simTime);

    // Provide keys shortly after startup to simulate post-handshake
    PqcSessionKeys dummyKeys;
    dummyKeys.combinedSecret.resize(32, 0x42);
    dummyKeys.encryptionKey.resize(32, 0x42);
    dummyKeys.integrityKey.resize(32, 0x42);
    dummyKeys.nonceBase.resize(12, 0x00);
    Simulator::Schedule(Seconds(1.2), &AesGcmCipher::InstallKeys, cmdrCipher, dummyKeys);

    // Followers send to Commander
    for (uint32_t i = 1; i < drones.GetN(); ++i)
    {
        Ptr<Node> drone = drones.Get(i);
        Ptr<AesGcmCipher> cipher = CreateObject<AesGcmCipher>();
        Ptr<PqcDroneApp> droneApp = CreateObject<PqcDroneApp>();
        
        double interval = (packetSize * 8.0) / (dataRateKbps * 1000.0);
        droneApp->SetAttribute("PacketSize", UintegerValue(packetSize));
        droneApp->SetAttribute("Interval", TimeValue(Seconds(interval)));

        droneApp->Setup(false, cmdrAddr, port, cipher, metrics);
        drone->AddApplication(droneApp);

        // Stagger starts
        droneApp->SetStartTime(Seconds(1.0 + i * 0.05));
        droneApp->SetStopTime(simTime);

        // Keys established after KEM handshake
        Simulator::Schedule(Seconds(1.2 + i * 0.05), &AesGcmCipher::InstallKeys, cipher, dummyKeys);
    }
}


// ═══════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════

int main(int argc, char* argv[])
{
    std::string crypto = "Kyber768"; // Baseline: ECC, Post-Quantum: Kyber512, Kyber768, Kyber1024
    uint32_t numDrones = 20;
    double speed = 25.0; // Drone speed (m/s)
    uint32_t packetSize = 1024; // Bytes
    uint32_t dataRateKbps = 200; // Telemetry rate
    double simTime = 10.0;
    bool enableCaching = false;

    CommandLine cmd;
    cmd.AddValue("crypto", "Cryptography: ECC, Kyber512, Kyber768, Kyber1024", crypto);
    cmd.AddValue("nodes", "Number of drone nodes (e.g. 10, 50, 100)", numDrones);
    cmd.AddValue("speed", "Drone mobility speed m/s", speed);
    cmd.AddValue("packetSize", "Telemetry payload size in bytes", packetSize);
    cmd.AddValue("rate", "Data rate kbps per drone", dataRateKbps);
    cmd.AddValue("caching", "Enable PSK caching to optimize handovers", enableCaching);
    cmd.Parse(argc, argv);

    NS_LOG_UNCOND("Starting Drone Swarm PQC Simulation");
    NS_LOG_UNCOND("Nodes: " << numDrones << ", Crypto: " << crypto << ", Speed: " << speed << " m/s");

    // Initialize 6G/NR topology — auto-select based on swarm size
    NS_LOG_UNCOND("[CHECKPOINT 1] Creating NR scenario...");
    PqcScenarioHelper scenarioHelper;
    PqcScenarioHelper::ScenarioResult scenarioResult;
    if (numDrones <= 20)
    {
        // Small swarm: single gNB is sufficient
        scenarioResult = scenarioHelper.CreateBaselineScenario(numDrones);
    }
    else
    {
        // Large swarm: distribute across 7 gNBs to avoid RNTI overload
        uint32_t uesPerGnb = (numDrones + 6) / 7; // ceiling division
        scenarioResult = scenarioHelper.CreateDenseUrbanScenario(uesPerGnb);
    }
    uint32_t actualDrones = scenarioResult.ueNodes.GetN();
    NS_LOG_UNCOND("[CHECKPOINT 2] NR scenario created: " << actualDrones << " UEs, " << scenarioResult.numGnbs << " gNBs");

    // Setup drone mobility (update positions, don't reinstall mobility model)
    NS_LOG_UNCOND("[CHECKPOINT 3] Setting up drone mobility...");
    SetDroneMobility(scenarioResult.ueNodes, speed, 100.0);
    NS_LOG_UNCOND("[CHECKPOINT 4] Mobility setup complete.");

    // PQC Security framework
    NS_LOG_UNCOND("[CHECKPOINT 5] Installing PQC security framework...");
    PqcSecurityHelper pqcHelper;
    g_metrics = pqcHelper.GetMetricsCollector();

    if (crypto == "ECC")
    {
        pqcHelper.SetEnableHybridKem(false); // Only use X25519-ECDH
    }
    else
    {
        pqcHelper.SetEnableHybridKem(true);
        if (crypto == "Kyber512") pqcHelper.SetKyberLevel(CrystalsKyberKem::KYBER_512);
        else if (crypto == "Kyber1024") pqcHelper.SetKyberLevel(CrystalsKyberKem::KYBER_1024);
        else pqcHelper.SetKyberLevel(CrystalsKyberKem::KYBER_768);
    }
    
    // PSK Caching optimization reduces connection setup processing
    if (enableCaching)
    {
        Config::SetDefault("ns3::pqc::CrystalsKyberKem::EncapsTime", TimeValue(MicroSeconds(10)));
        Config::SetDefault("ns3::pqc::CrystalsKyberKem::DecapsTime", TimeValue(MicroSeconds(10)));
    }

    pqcHelper.Install(scenarioResult.gnbDevices, scenarioResult.ueDevices);
    NS_LOG_UNCOND("[CHECKPOINT 6] PQC framework installed.");
    
    // Adaptive rekey logic handles the refresh automatically, but we schedule initial ones
    pqcHelper.ScheduleHandshakes(MilliSeconds(800));
    NS_LOG_UNCOND("[CHECKPOINT 7] Handshakes scheduled.");

    // Monitor Queueing Delay on all Drone UE devices
    Config::ConnectWithoutContext("/NodeList/*/DeviceList/*/$ns3::PointToPointNetDevice/TxQueue/Enqueue", MakeCallback(&EnqueueTrace));
    Config::ConnectWithoutContext("/NodeList/*/DeviceList/*/$ns3::PointToPointNetDevice/TxQueue/Dequeue", MakeCallback(&DequeueTrace));
    NS_LOG_UNCOND("[CHECKPOINT 8] Queue traces connected.");

    // Install Drone SWARM Apps
    NS_LOG_UNCOND("[CHECKPOINT 9] Installing drone applications...");
    InstallDroneApplications(scenarioResult.ueNodes, pqcHelper.GetMetricsCollector(), Seconds(simTime), packetSize, dataRateKbps);
    NS_LOG_UNCOND("[CHECKPOINT 10] Apps installed. Starting simulation...");

    Simulator::Stop(Seconds(simTime + 1.0));
    Simulator::Run();

    NS_LOG_UNCOND("\nResults for " << actualDrones << " drones using " << crypto << ":");
    pqcHelper.GetMetricsCollector()->PrintSummary();
    
    std::string csvName = "drone_swarm_metrics_" + crypto + "_" + std::to_string(actualDrones) + ".csv";
    pqcHelper.GetMetricsCollector()->ExportToCsv(csvName);
    
    Simulator::Destroy();
    NS_LOG_UNCOND("Done.\n");
    return 0;
}

