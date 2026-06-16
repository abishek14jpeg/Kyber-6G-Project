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
    : m_cryptoMode(CryptoMode::HYBRID_KYBER_ECDH)
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

void
HybridKemCombiner::SetCryptoMode(CryptoMode mode)
{
    m_cryptoMode = mode;
}

HybridKemCombiner::HybridKeyPair
HybridKemCombiner::GenerateKeyPair()
{
    HybridKeyPair hkp;

    hkp.totalGenerationTime = Seconds(0);

    if (m_cryptoMode == CryptoMode::ECC_ONLY || m_cryptoMode == CryptoMode::HYBRID_KYBER_ECDH)
    {
        hkp.ecdhKeys = m_ecdh->KeyGen();
        hkp.totalGenerationTime += hkp.ecdhKeys.generationTime;
    }
    
    if (m_cryptoMode == CryptoMode::KYBER_ONLY || m_cryptoMode == CryptoMode::KYBER_CACHED || m_cryptoMode == CryptoMode::HYBRID_KYBER_ECDH)
    {
        hkp.kyberKeys = m_kyber->KeyGen();
        hkp.totalGenerationTime += hkp.kyberKeys.generationTime;
    }

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

    result.totalTime = Seconds(0);
    std::vector<uint8_t> ecdhSecret, kyberSecret;

    if (m_cryptoMode == CryptoMode::ECC_ONLY || m_cryptoMode == CryptoMode::HYBRID_KYBER_ECDH)
    {
        auto ecdhKp = m_ecdh->KeyGen();
        auto ecdhSs = m_ecdh->ComputeSharedSecret(ecdhKp.secretKey, initiatorEcdhPk);
        result.ecdhPublicKey = ecdhKp.publicKey;
        ecdhSecret = ecdhSs.sharedSecret;
        result.totalTime += ecdhKp.generationTime + ecdhSs.computeTime;
    }

    if (m_cryptoMode == CryptoMode::KYBER_ONLY || m_cryptoMode == CryptoMode::KYBER_CACHED || m_cryptoMode == CryptoMode::HYBRID_KYBER_ECDH)
    {
        auto kyberResult = m_kyber->Encapsulate(initiatorKyberPk);
        result.kyberCiphertext = kyberResult.ciphertext;
        kyberSecret = kyberResult.sharedSecret;
        result.totalTime += kyberResult.encapsulationTime;
    }

    result.combinedSecret = SimulatedHkdf(ecdhSecret, kyberSecret);
    result.totalTime += MicroSeconds(5); // HKDF overhead

    NS_LOG_INFO("Hybrid Encaps: ecdh_pk=32B + kyber_ct="
                << result.kyberCiphertext.size()
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
    Time totalTime = Seconds(0);
    std::vector<uint8_t> ecdhSecret, kyberSecret;

    if (m_cryptoMode == CryptoMode::ECC_ONLY || m_cryptoMode == CryptoMode::HYBRID_KYBER_ECDH)
    {
        auto ecdhSs = m_ecdh->ComputeSharedSecret(myKeys.ecdhKeys.secretKey, responderEcdhPk);
        ecdhSecret = ecdhSs.sharedSecret;
        totalTime += ecdhSs.computeTime;
    }

    if (m_cryptoMode == CryptoMode::KYBER_ONLY || m_cryptoMode == CryptoMode::KYBER_CACHED || m_cryptoMode == CryptoMode::HYBRID_KYBER_ECDH)
    {
        auto kyberResult = m_kyber->Decapsulate(myKeys.kyberKeys.secretKey, kyberCiphertext);
        kyberSecret = kyberResult.sharedSecret;
        totalTime += kyberResult.decapsulationTime;
    }

    auto combined = SimulatedHkdf(ecdhSecret, kyberSecret);
    totalTime += MicroSeconds(5);

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
