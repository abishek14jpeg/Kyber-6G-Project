/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

#include "hybrid-kem-combiner.h"

#include "ns3/double.h"
#include "ns3/log.h"
#include "ns3/simulator.h"

namespace ns3
{
namespace pqc
{

NS_LOG_COMPONENT_DEFINE("HybridKemCombiner");
NS_OBJECT_ENSURE_REGISTERED(HybridKemCombiner);

TypeId
HybridKemCombiner::GetTypeId()
{
    static TypeId tid =
        TypeId("ns3::pqc::HybridKemCombiner")
            .SetParent<Object>()
            .SetGroupName("PqcSecurity")
            .AddConstructor<HybridKemCombiner>()
            .AddTraceSource("HybridKeyGenLatency",
                            "Total time for hybrid (ECDH+Kyber) key generation",
                            MakeTraceSourceAccessor(&HybridKemCombiner::m_hybridKeyGenTrace),
                            "ns3::Time::TracedCallback")
            .AddTraceSource("HybridEncapsLatency",
                            "Total time for hybrid encapsulation",
                            MakeTraceSourceAccessor(&HybridKemCombiner::m_hybridEncapsTrace),
                            "ns3::Time::TracedCallback")
            .AddTraceSource("HybridDecapsLatency",
                            "Total time for hybrid decapsulation",
                            MakeTraceSourceAccessor(&HybridKemCombiner::m_hybridDecapsTrace),
                            "ns3::Time::TracedCallback")
            .AddTraceSource("TotalPublicKeySize",
                            "Combined ECDH+Kyber public key size in bytes",
                            MakeTraceSourceAccessor(&HybridKemCombiner::m_totalPublicKeySizeTrace),
                            "ns3::TracedValueCallback::Uint32")
            .AddTraceSource(
                "TotalEncapsSize",
                "Combined ECDH pub + Kyber ciphertext size in bytes",
                MakeTraceSourceAccessor(&HybridKemCombiner::m_totalEncapsSizeTrace),
                "ns3::TracedValueCallback::Uint32");

    return tid;
}

HybridKemCombiner::HybridKemCombiner()
{
    m_ecdh = CreateObject<X25519Ecdh>();
    m_kyber = CreateObject<CrystalsKyberKem>();
    m_rng = CreateObject<UniformRandomVariable>();
    m_rng->SetAttribute("Min", DoubleValue(0.0));
    m_rng->SetAttribute("Max", DoubleValue(255.0));
}

HybridKemCombiner::~HybridKemCombiner()
{
}

HybridKemCombiner::HybridKeyPair
HybridKemCombiner::GenerateKeyPair()
{
    HybridKeyPair hkp;

    // Generate both key pairs
    hkp.ecdhKeys = m_ecdh->KeyGen();
    hkp.kyberKeys = m_kyber->KeyGen();

    // Total time is the sum (sequential generation)
    hkp.totalGenerationTime = hkp.ecdhKeys.generationTime + hkp.kyberKeys.generationTime;

    NS_LOG_INFO("Hybrid KeyGen: ECDH(32B) + Kyber(" << hkp.kyberKeys.publicKey.size()
                                                     << "B) total_pk="
                                                     << hkp.TotalPublicKeySize()
                                                     << "B time=" << hkp.totalGenerationTime.As(Time::US));

    m_hybridKeyGenTrace(hkp.totalGenerationTime);
    m_totalPublicKeySizeTrace(hkp.TotalPublicKeySize());

    return hkp;
}

std::vector<uint8_t>
HybridKemCombiner::SimulatedHkdf(const std::vector<uint8_t>& ecdhSs,
                                  const std::vector<uint8_t>& kyberSs)
{
    // Simulated HKDF-SHA256(ecdhSs || kyberSs, "Kyber6G-HybridKEM-v1")
    // In simulation we combine by XOR + randomization to produce a 32-byte output.
    // The important thing is the SIZE and TIMING, not the cryptographic correctness.
    std::vector<uint8_t> combined(32);
    for (uint32_t i = 0; i < 32; ++i)
    {
        uint8_t a = (i < ecdhSs.size()) ? ecdhSs[i] : 0;
        uint8_t b = (i < kyberSs.size()) ? kyberSs[i] : 0;
        combined[i] = a ^ b ^ static_cast<uint8_t>(m_rng->GetInteger(0, 255));
    }
    return combined;
}

HybridKemCombiner::HybridEncapsResult
HybridKemCombiner::Encapsulate(const std::vector<uint8_t>& initiatorEcdhPk,
                                const std::vector<uint8_t>& initiatorKyberPk)
{
    HybridEncapsResult result;

    // 1. Generate our own ECDH ephemeral key and compute shared secret
    auto ecdhKp = m_ecdh->KeyGen();
    auto ecdhSs = m_ecdh->ComputeSharedSecret(ecdhKp.secretKey, initiatorEcdhPk);

    // 2. Encapsulate with Kyber toward the initiator's public key
    auto kyberResult = m_kyber->Encapsulate(initiatorKyberPk);

    // 3. Combine shared secrets via HKDF
    result.ecdhPublicKey = ecdhKp.publicKey;
    result.kyberCiphertext = kyberResult.ciphertext;
    result.combinedSecret = SimulatedHkdf(ecdhSs.sharedSecret, kyberResult.sharedSecret);

    // Total time: ECDH keygen + DH + Kyber encaps + HKDF (~negligible)
    result.totalTime = ecdhKp.generationTime + ecdhSs.computeTime +
                       kyberResult.encapsulationTime + MicroSeconds(5); // HKDF overhead

    NS_LOG_INFO("Hybrid Encaps: ecdh_pk=32B + kyber_ct="
                << kyberResult.ciphertext.size()
                << "B total_wire=" << result.TotalWireSize()
                << "B time=" << result.totalTime.As(Time::US));

    m_hybridEncapsTrace(result.totalTime);
    m_totalEncapsSizeTrace(result.TotalWireSize());

    return result;
}

std::vector<uint8_t>
HybridKemCombiner::Decapsulate(const HybridKeyPair& myKeys,
                                const std::vector<uint8_t>& responderEcdhPk,
                                const std::vector<uint8_t>& kyberCiphertext)
{
    // 1. ECDH shared secret
    auto ecdhSs = m_ecdh->ComputeSharedSecret(myKeys.ecdhKeys.secretKey, responderEcdhPk);

    // 2. Kyber decapsulation
    auto kyberResult = m_kyber->Decapsulate(myKeys.kyberKeys.secretKey, kyberCiphertext);

    // 3. Combine via HKDF
    auto combined = SimulatedHkdf(ecdhSs.sharedSecret, kyberResult.sharedSecret);

    Time totalTime = ecdhSs.computeTime + kyberResult.decapsulationTime + MicroSeconds(5);

    NS_LOG_INFO("Hybrid Decaps: time=" << totalTime.As(Time::US));
    m_hybridDecapsTrace(totalTime);

    return combined;
}

PqcSessionKeys
HybridKemCombiner::DeriveSessionKeys(const std::vector<uint8_t>& combinedSecret)
{
    PqcSessionKeys keys;
    keys.combinedSecret = combinedSecret;

    // Derive enc key, int key, nonce from the combined secret
    // Simulated: split the 32-byte secret and expand with pseudo-randomness
    keys.encryptionKey.resize(32);
    keys.integrityKey.resize(32);
    keys.nonceBase.resize(12);

    for (uint32_t i = 0; i < 32; ++i)
    {
        keys.encryptionKey[i] = combinedSecret[i] ^ 0x01;
        keys.integrityKey[i] = combinedSecret[i] ^ 0x02;
    }
    for (uint32_t i = 0; i < 12; ++i)
    {
        keys.nonceBase[i] = combinedSecret[i] ^ 0x03;
    }

    keys.nonceCounter = 0;
    keys.establishedAt = Simulator::Now();
    keys.isHybrid = true;
    keys.keyGeneration = 0;

    NS_LOG_INFO("Session keys derived: enc=32B int=32B nonce_base=12B at t="
                << keys.establishedAt.As(Time::MS));

    return keys;
}

} // namespace pqc
} // namespace ns3
