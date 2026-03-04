/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#ifndef PQC_SCENARIO_HELPER_H
#define PQC_SCENARIO_HELPER_H

#include "ns3/mobility-helper.h"
#include "ns3/net-device-container.h"
#include "ns3/node-container.h"
#include "ns3/nr-helper.h"
#include "ns3/nr-point-to-point-epc-helper.h"
#include "ns3/position-allocator.h"

#include <cstdint>

namespace ns3
{
namespace pqc
{

/**
 * \brief Pre-configured network scenarios for PQC experiments.
 *
 * Provides ready-made topology setups with associated mobility
 * models, covering the publication experiment matrix:
 *   - DenseUrban: 7-cell hexagonal grid, 50-100 UEs
 *   - HighSpeedMobility: Linear corridor with bullet-train UEs
 *   - Baseline: Simple 1 gNB, 2 UEs for functional testing
 */
class PqcScenarioHelper
{
  public:
    /// Scenario result containing created nodes and devices
    struct ScenarioResult
    {
        NodeContainer gnbNodes;
        NodeContainer ueNodes;
        NetDeviceContainer gnbDevices;
        NetDeviceContainer ueDevices;
        Ptr<NrPointToPointEpcHelper> epcHelper;
        Ptr<NrHelper> nrHelper;
        uint32_t numGnbs;
        uint32_t numUes;
    };

    PqcScenarioHelper();
    ~PqcScenarioHelper();

    /**
     * \brief Create a dense urban hexagonal cell layout.
     *
     * 7-cell hex grid (1 center + 6 surrounding) with uniform
     * random UE distribution within each cell.
     *
     * \param numUesPerGnb UEs per cell (default: 15, total: 105)
     * \param isd Inter-site distance in meters (default: 200)
     * \param frequency Central frequency in Hz (default: 3.5 GHz)
     * \param bandwidth Channel bandwidth in Hz (default: 20 MHz)
     * \return ScenarioResult with all created nodes/devices.
     */
    ScenarioResult CreateDenseUrbanScenario(uint32_t numUesPerGnb = 15,
                                             double isd = 200.0,
                                             double frequency = 3.5e9,
                                             double bandwidth = 20e6);

    /**
     * \brief Create a high-speed mobility corridor scenario.
     *
     * Linear corridor with gNBs spaced along a rail line.
     * UEs move at configurable speed (default: 120 m/s / 432 km/h).
     *
     * \param numGnbs Number of gNBs along the corridor
     * \param numUes Number of mobile UE nodes
     * \param speed UE speed in m/s (default: 120)
     * \param gnbSpacing Spacing between gNBs in meters
     * \return ScenarioResult.
     */
    ScenarioResult CreateHighSpeedMobilityScenario(uint32_t numGnbs = 5,
                                                     uint32_t numUes = 10,
                                                     double speed = 120.0,
                                                     double gnbSpacing = 200.0);

    /**
     * \brief Create a simple baseline scenario (1 gNB, configurable UEs).
     *
     * \param numUes Number of UEs (default: 2)
     * \return ScenarioResult.
     */
    ScenarioResult CreateBaselineScenario(uint32_t numUes = 2);

  private:
    /// Common NR helper setup
    ScenarioResult SetupNrStack(NodeContainer& gnbNodes,
                                NodeContainer& ueNodes,
                                double frequency,
                                double bandwidth);
};

} // namespace pqc
} // namespace ns3

#endif // PQC_SCENARIO_HELPER_H
