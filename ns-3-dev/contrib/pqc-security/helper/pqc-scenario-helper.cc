/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#include "pqc-scenario-helper.h"

#include "ns3/antenna-module.h"
#include "ns3/boolean.h"
#include "ns3/config.h"
#include "ns3/constant-velocity-mobility-model.h"
#include "ns3/double.h"
#include "ns3/ideal-beamforming-helper.h"
#include "ns3/internet-module.h"
#include "ns3/log.h"
#include "ns3/nr-module.h"
#include "ns3/point-to-point-helper.h"
#include "ns3/box.h"
#include "ns3/gauss-markov-mobility-model.h"
#include "ns3/pointer.h"
#include "ns3/uinteger.h"

#include <cmath>

namespace ns3
{
namespace pqc
{

NS_LOG_COMPONENT_DEFINE("PqcScenarioHelper");

PqcScenarioHelper::PqcScenarioHelper()
{
}

PqcScenarioHelper::~PqcScenarioHelper()
{
}

PqcScenarioHelper::ScenarioResult
PqcScenarioHelper::SetupNrStack(NodeContainer& gnbNodes,
                                 NodeContainer& ueNodes,
                                 double frequency,
                                 double bandwidth)
{
    ScenarioResult result;
    result.gnbNodes = gnbNodes;
    result.ueNodes = ueNodes;
    result.numGnbs = gnbNodes.GetN();
    result.numUes = ueNodes.GetN();

    Config::SetDefault("ns3::LteRlcUm::MaxTxBufferSize", UintegerValue(999999999));
    // Config::SetDefault("ns3::NrHelper::UseIdealRrc", BooleanValue(false)); // Not valid in 5G-LENA NrHelper

    // Create helpers
    result.epcHelper = CreateObject<NrPointToPointEpcHelper>();
    auto idealBeamformingHelper = CreateObject<IdealBeamformingHelper>();
    result.nrHelper = CreateObject<NrHelper>();

    result.nrHelper->SetBeamformingHelper(idealBeamformingHelper);
    result.nrHelper->SetEpcHelper(result.epcHelper);

    // Setup MEC Backhaul
    NodeContainer mecNode;
    mecNode.Create(1);
    PointToPointHelper p2pMec;
    p2pMec.SetDeviceAttribute("DataRate", DataRateValue(DataRate("10Gbps")));
    p2pMec.SetChannelAttribute("Delay", TimeValue(MilliSeconds(2.0)));
    p2pMec.Install(result.epcHelper->GetPgwNode(), mecNode.Get(0));


    // Setup Handover Algorithm
    // result.nrHelper->SetHandoverAlgorithmType("ns3::NrA3RsrpHandoverAlgorithm");
    // result.nrHelper->SetHandoverAlgorithmAttribute("Hysteresis", DoubleValue(3.0));
    // result.nrHelper->SetHandoverAlgorithmAttribute("TimeToTrigger", TimeValue(MilliSeconds(256)));

    // Spectrum configuration
    CcBwpCreator ccBwpCreator;
    CcBwpCreator::SimpleOperationBandConf bandConf(frequency,
                                                    bandwidth,
                                                    1,
                                                    BandwidthPartInfo::UMi_StreetCanyon);
    OperationBandInfo band = ccBwpCreator.CreateOperationBandContiguousCc(bandConf);

    Config::SetDefault("ns3::ThreeGppChannelModel::UpdatePeriod", TimeValue(MilliSeconds(0)));
    // result.nrHelper->SetChannelConditionModelAttribute("TypeId", StringValue("ns3::ThreeGppChannelConditionModel"));
    // result.nrHelper->SetChannelConditionModelAttribute("Scenario", StringValue("UMa-AV"));
    // result.nrHelper->SetPathlossModel("ns3::ThreeGppPropagationLossModel");
    result.nrHelper->SetPathlossAttribute("ShadowingEnabled", BooleanValue(false));
    result.nrHelper->InitializeOperationBand(&band);

    BandwidthPartInfoPtrVector allBwps = CcBwpCreator::GetAllBwps({band});

    idealBeamformingHelper->SetAttribute(
        "BeamformingMethod",
        TypeIdValue(DirectPathBeamforming::GetTypeId()));

    result.epcHelper->SetAttribute("S1uLinkDelay", TimeValue(MilliSeconds(0)));

    // UE antenna config
    result.nrHelper->SetUeAntennaAttribute("NumRows", UintegerValue(2));
    result.nrHelper->SetUeAntennaAttribute("NumColumns", UintegerValue(4));
    result.nrHelper->SetUeAntennaAttribute(
        "AntennaElement",
        PointerValue(CreateObject<IsotropicAntennaModel>()));

    // gNB antenna config
    result.nrHelper->SetGnbAntennaAttribute("NumRows", UintegerValue(4));
    result.nrHelper->SetGnbAntennaAttribute("NumColumns", UintegerValue(8));
    result.nrHelper->SetGnbAntennaAttribute(
        "AntennaElement",
        PointerValue(CreateObject<IsotropicAntennaModel>()));

    // BWP manager
    result.nrHelper->SetGnbBwpManagerAlgorithmAttribute("NGBR_LOW_LAT_EMBB", UintegerValue(0));
    result.nrHelper->SetUeBwpManagerAlgorithmAttribute("NGBR_LOW_LAT_EMBB", UintegerValue(0));

    // Install NR stack (gNB Internet stack is installed internally by EpcHelper::AddEnb)
    result.gnbDevices = result.nrHelper->InstallGnbDevice(gnbNodes, allBwps);
    result.ueDevices = result.nrHelper->InstallUeDevice(ueNodes, allBwps);

    // Enable X2/Xn interfaces AFTER InstallGnbDevice (gNBs need Ipv4 from AddEnb first)
    for (uint32_t i = 0; i < gnbNodes.GetN(); ++i) {
        for (uint32_t j = i + 1; j < gnbNodes.GetN(); ++j) {
            result.epcHelper->AddX2Interface(gnbNodes.Get(i), gnbNodes.Get(j));
        }
    }

    // Assign random streams
    int64_t randomStream = 1;
    randomStream += result.nrHelper->AssignStreams(result.gnbDevices, randomStream);
    randomStream += result.nrHelper->AssignStreams(result.ueDevices, randomStream);

    // Configure gNB PHY
    for (uint32_t i = 0; i < result.gnbDevices.GetN(); ++i)
    {
        result.nrHelper->GetGnbPhy(result.gnbDevices.Get(i), 0)
            ->SetAttribute("Numerology", UintegerValue(1));
        result.nrHelper->GetGnbPhy(result.gnbDevices.Get(i), 0)
            ->SetAttribute("TxPower", DoubleValue(35.0));
    }

    // Finalize configs
    for (auto it = result.gnbDevices.Begin(); it != result.gnbDevices.End(); ++it)
    {
        DynamicCast<NrGnbNetDevice>(*it)->UpdateConfig();
    }
    for (auto it = result.ueDevices.Begin(); it != result.ueDevices.End(); ++it)
    {
        DynamicCast<NrUeNetDevice>(*it)->UpdateConfig();
    }

    // Internet stack on UEs — MUST be after InstallUeDevice (per NR examples)
    // Do NOT install on gnbNodes — EpcHelper::AddEnb already does it
    InternetStackHelper internet;
    internet.Install(ueNodes);

    auto ueIpIfaces = result.epcHelper->AssignUeIpv4Address(result.ueDevices);

    Ipv4StaticRoutingHelper routingHelper;
    for (uint32_t j = 0; j < ueNodes.GetN(); ++j)
    {
        auto ueRouting = routingHelper.GetStaticRouting(ueNodes.Get(j)->GetObject<Ipv4>());
        ueRouting->SetDefaultRoute(result.epcHelper->GetUeDefaultGatewayAddress(), 1);
    }

    // Attach UEs to closest gNB
    result.nrHelper->AttachToClosestEnb(result.ueDevices, result.gnbDevices);

    return result;
}

PqcScenarioHelper::ScenarioResult
PqcScenarioHelper::CreateDenseUrbanScenario(uint32_t numUesPerGnb,
                                              double isd,
                                              double frequency,
                                              double bandwidth)
{
    const uint32_t numGnbs = 7; // Hexagonal: 1 center + 6
    const double gnbHeight = 25.0;
    const double ueHeight = 1.5;

    NS_LOG_INFO("Creating Dense Urban Scenario: " << numGnbs << " gNBs, "
                << numUesPerGnb << " UEs/cell, ISD=" << isd << "m");

    NodeContainer gnbNodes;
    gnbNodes.Create(numGnbs);

    NodeContainer ueNodes;
    ueNodes.Create(numGnbs * numUesPerGnb);

    // gNB placement: hexagonal grid
    MobilityHelper gnbMobility;
    gnbMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");

    Ptr<ListPositionAllocator> gnbPositions = CreateObject<ListPositionAllocator>();
    gnbPositions->Add(Vector(0.0, 0.0, gnbHeight)); // Center cell

    for (uint32_t i = 0; i < 6; ++i)
    {
        double angle = 2.0 * M_PI * i / 6.0;
        double x = isd * std::cos(angle);
        double y = isd * std::sin(angle);
        gnbPositions->Add(Vector(x, y, gnbHeight));
    }

    gnbMobility.SetPositionAllocator(gnbPositions);
    gnbMobility.Install(gnbNodes);

    // UE placement: Gauss-Markov mobility
    MobilityHelper ueMobility;
    ueMobility.SetMobilityModel("ns3::GaussMarkovMobilityModel",
        "Bounds", BoxValue(Box(-5000, 5000, -5000, 5000, 80, 80)),
        "TimeStep", TimeValue(Seconds(0.5)),
        "Alpha", DoubleValue(0.85),
        "MeanVelocity", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=25.0]"),
        "MeanDirection", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=6.283185307]"),
        "MeanPitch", StringValue("ns3::UniformRandomVariable[Min=0.0|Max=0.0]"));

    Ptr<ListPositionAllocator> uePositions = CreateObject<ListPositionAllocator>();
    Ptr<UniformRandomVariable> rng = CreateObject<UniformRandomVariable>();

    for (uint32_t g = 0; g < numGnbs; ++g)
    {
        auto gnbMob = gnbNodes.Get(g)->GetObject<MobilityModel>();
        Vector gnbPos = gnbMob->GetPosition();

        for (uint32_t u = 0; u < numUesPerGnb; ++u)
        {
            double r = rng->GetValue(10.0, isd / 2.0);
            double theta = rng->GetValue(0, 2.0 * M_PI);
            double x = gnbPos.x + r * std::cos(theta);
            double y = gnbPos.y + r * std::sin(theta);
            uePositions->Add(Vector(x, y, 80.0)); // Initial position at altitude 80m
        }
    }

    ueMobility.SetPositionAllocator(uePositions);
    ueMobility.Install(ueNodes);

    return SetupNrStack(gnbNodes, ueNodes, frequency, bandwidth);
}

PqcScenarioHelper::ScenarioResult
PqcScenarioHelper::CreateHighSpeedMobilityScenario(uint32_t numGnbs,
                                                     uint32_t numUes,
                                                     double speed,
                                                     double gnbSpacing)
{
    const double gnbHeight = 25.0;
    const double ueHeight = 1.5;
    const double trackOffset = 50.0; // Track is 50m from gNB line

    NS_LOG_INFO("Creating High-Speed Mobility Scenario: " << numGnbs
                << " gNBs, " << numUes << " UEs, speed=" << speed << " m/s ("
                << speed * 3.6 << " km/h)");

    NodeContainer gnbNodes;
    gnbNodes.Create(numGnbs);

    NodeContainer ueNodes;
    ueNodes.Create(numUes);

    // gNB placement: linear along corridor
    MobilityHelper gnbMobility;
    gnbMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");

    Ptr<ListPositionAllocator> gnbPositions = CreateObject<ListPositionAllocator>();
    for (uint32_t i = 0; i < numGnbs; ++i)
    {
        gnbPositions->Add(Vector(i * gnbSpacing, 0.0, gnbHeight));
    }
    gnbMobility.SetPositionAllocator(gnbPositions);
    gnbMobility.Install(gnbNodes);

    // UE placement: constant velocity along the track
    MobilityHelper ueMobility;
    ueMobility.SetMobilityModel("ns3::ConstantVelocityMobilityModel");

    // Start UEs behind the first gNB
    Ptr<ListPositionAllocator> uePositions = CreateObject<ListPositionAllocator>();
    for (uint32_t i = 0; i < numUes; ++i)
    {
        double startX = -200.0 - (i * 10.0); // Staggered start
        uePositions->Add(Vector(startX, trackOffset, ueHeight));
    }
    ueMobility.SetPositionAllocator(uePositions);
    ueMobility.Install(ueNodes);

    // Set velocity for each UE
    for (uint32_t i = 0; i < numUes; ++i)
    {
        auto mob = ueNodes.Get(i)->GetObject<ConstantVelocityMobilityModel>();
        mob->SetVelocity(Vector(speed, 0.0, 0.0)); // Moving east at high speed
    }

    return SetupNrStack(gnbNodes, ueNodes, 3.5e9, 20e6);
}

PqcScenarioHelper::ScenarioResult
PqcScenarioHelper::CreateBaselineScenario(uint32_t numUes)
{
    NS_LOG_INFO("Creating Baseline Scenario: 1 gNB, " << numUes << " UEs");

    NodeContainer gnbNodes;
    gnbNodes.Create(1);

    NodeContainer ueNodes;
    ueNodes.Create(numUes);

    // gNB at center
    MobilityHelper gnbMobility;
    gnbMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    Ptr<ListPositionAllocator> gnbPos = CreateObject<ListPositionAllocator>();
    gnbPos->Add(Vector(0.0, 0.0, 10.0));
    gnbMobility.SetPositionAllocator(gnbPos);
    gnbMobility.Install(gnbNodes);

    // UEs in a circle around gNB
    MobilityHelper ueMobility;
    ueMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    Ptr<ListPositionAllocator> uePos = CreateObject<ListPositionAllocator>();

    for (uint32_t i = 0; i < numUes; ++i)
    {
        double angle = 2.0 * M_PI * i / numUes;
        double x = 20.0 * std::cos(angle);
        double y = 20.0 * std::sin(angle);
        uePos->Add(Vector(x, y, 1.5));
    }
    ueMobility.SetPositionAllocator(uePos);
    ueMobility.Install(ueNodes);

    return SetupNrStack(gnbNodes, ueNodes, 3.5e9, 20e6);
}

} // namespace pqc
} // namespace ns3
