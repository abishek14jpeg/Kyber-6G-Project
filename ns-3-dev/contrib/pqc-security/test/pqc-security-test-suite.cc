/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */

// Copyright (c) 2026 Kyber-6G Project
// SPDX-License-Identifier: GPL-2.0-only

/**
 * \file pqc-security-test-suite.cc
 * \brief Unit tests for the PQC security framework.
 */

#include "ns3/aes-gcm-cipher.h"
#include "ns3/crystals-kyber-kem.h"
#include "ns3/hybrid-kem-combiner.h"
#include "ns3/ml-dsa-signer.h"
#include "ns3/pqc-pdcp-layer.h"
#include "ns3/pqc-rrc-extension.h"
#include "ns3/pqc-session-keys.h"
#include "ns3/x25519-ecdh.h"

#include "ns3/enum.h"
#include "ns3/log.h"
#include "ns3/simulator.h"
#include "ns3/test.h"

using namespace ns3;
using namespace ns3::pqc;

// ════════════════════════════════════════════════════════
// Test 1: Kyber KEM sizes match FIPS 203
// ════════════════════════════════════════════════════════
class KyberSizesTestCase : public TestCase
{
  public:
    KyberSizesTestCase()
        : TestCase("Kyber KEM output sizes match FIPS 203")
    {
    }

    void DoRun() override
    {
        // Test Kyber-512
        auto kyber512 = CreateObject<CrystalsKyberKem>();
        kyber512->SetAttribute("SecurityLevel", EnumValue(CrystalsKyberKem::KYBER_512));
        auto kp512 = kyber512->KeyGen();
        NS_TEST_ASSERT_MSG_EQ(kp512.publicKey.size(), 800u, "Kyber-512 PK should be 800 bytes");
        NS_TEST_ASSERT_MSG_EQ(kp512.secretKey.size(), 1632u, "Kyber-512 SK should be 1632 bytes");
        auto enc512 = kyber512->Encapsulate(kp512.publicKey);
        NS_TEST_ASSERT_MSG_EQ(enc512.ciphertext.size(), 768u, "Kyber-512 CT should be 768 bytes");
        NS_TEST_ASSERT_MSG_EQ(enc512.sharedSecret.size(), 32u, "SS should be 32 bytes");

        // Test Kyber-768
        auto kyber768 = CreateObject<CrystalsKyberKem>();
        kyber768->SetAttribute("SecurityLevel", EnumValue(CrystalsKyberKem::KYBER_768));
        auto kp768 = kyber768->KeyGen();
        NS_TEST_ASSERT_MSG_EQ(kp768.publicKey.size(), 1184u, "Kyber-768 PK should be 1184 bytes");
        NS_TEST_ASSERT_MSG_EQ(kp768.secretKey.size(), 2400u, "Kyber-768 SK should be 2400 bytes");
        auto enc768 = kyber768->Encapsulate(kp768.publicKey);
        NS_TEST_ASSERT_MSG_EQ(enc768.ciphertext.size(), 1088u, "Kyber-768 CT should be 1088 bytes");

        // Test Kyber-1024
        auto kyber1024 = CreateObject<CrystalsKyberKem>();
        kyber1024->SetAttribute("SecurityLevel", EnumValue(CrystalsKyberKem::KYBER_1024));
        auto kp1024 = kyber1024->KeyGen();
        NS_TEST_ASSERT_MSG_EQ(kp1024.publicKey.size(), 1568u, "Kyber-1024 PK should be 1568 bytes");
        auto enc1024 = kyber1024->Encapsulate(kp1024.publicKey);
        NS_TEST_ASSERT_MSG_EQ(enc1024.ciphertext.size(), 1568u, "Kyber-1024 CT should be 1568 bytes");

        Simulator::Destroy();
    }
};

// ════════════════════════════════════════════════════════
// Test 2: X25519 ECDH sizes
// ════════════════════════════════════════════════════════
class X25519SizesTestCase : public TestCase
{
  public:
    X25519SizesTestCase()
        : TestCase("X25519 ECDH sizes are correct")
    {
    }

    void DoRun() override
    {
        auto ecdh = CreateObject<X25519Ecdh>();
        auto kp = ecdh->KeyGen();
        NS_TEST_ASSERT_MSG_EQ(kp.publicKey.size(), 32u, "X25519 PK should be 32 bytes");
        NS_TEST_ASSERT_MSG_EQ(kp.secretKey.size(), 32u, "X25519 SK should be 32 bytes");

        auto ss = ecdh->ComputeSharedSecret(kp.secretKey, kp.publicKey);
        NS_TEST_ASSERT_MSG_EQ(ss.sharedSecret.size(), 32u, "X25519 SS should be 32 bytes");

        Simulator::Destroy();
    }
};

// ════════════════════════════════════════════════════════
// Test 3: Hybrid KEM combiner total sizes
// ════════════════════════════════════════════════════════
class HybridKemSizesTestCase : public TestCase
{
  public:
    HybridKemSizesTestCase()
        : TestCase("Hybrid KEM total wire sizes are correct")
    {
    }

    void DoRun() override
    {
        auto hybrid = CreateObject<HybridKemCombiner>();
        auto hkp = hybrid->GenerateKeyPair();

        // Total PK = 32 (ECDH) + 1184 (Kyber-768) = 1216
        NS_TEST_ASSERT_MSG_EQ(hkp.TotalPublicKeySize(), 1216u,
                              "Hybrid PK should be 1216 bytes for Kyber-768");

        auto encResult = hybrid->Encapsulate(hkp.ecdhKeys.publicKey,
                                              hkp.kyberKeys.publicKey);

        // Total encaps = 32 (ECDH PK) + 1088 (Kyber CT) = 1120
        NS_TEST_ASSERT_MSG_EQ(encResult.TotalWireSize(), 1120u,
                              "Hybrid encaps wire size should be 1120 bytes");
        NS_TEST_ASSERT_MSG_EQ(encResult.combinedSecret.size(), 32u,
                              "Combined secret should be 32 bytes");

        Simulator::Destroy();
    }
};

// ════════════════════════════════════════════════════════
// Test 4: ML-DSA signature sizes match FIPS 204
// ════════════════════════════════════════════════════════
class MlDsaSizesTestCase : public TestCase
{
  public:
    MlDsaSizesTestCase()
        : TestCase("ML-DSA signature and key sizes match FIPS 204")
    {
    }

    void DoRun() override
    {
        // ML-DSA-65
        auto signer65 = CreateObject<MlDsaSigner>();
        signer65->SetAttribute("Level", EnumValue(MlDsaSigner::ML_DSA_65));

        std::vector<uint8_t> message = {0x01, 0x02, 0x03};
        auto sig = signer65->Sign(message);
        NS_TEST_ASSERT_MSG_EQ(sig.sigBytes.size(), 3293u, "ML-DSA-65 sig should be 3293 bytes");

        auto pk = signer65->GetPublicKey();
        NS_TEST_ASSERT_MSG_EQ(pk.size(), 1952u, "ML-DSA-65 PK should be 1952 bytes");

        // Verify should succeed
        auto result = signer65->Verify(message, sig, pk);
        NS_TEST_ASSERT_MSG_EQ(result.valid, true, "Valid signature should verify");

        Simulator::Destroy();
    }
};

// ════════════════════════════════════════════════════════
// Test 5: AES-GCM overhead
// ════════════════════════════════════════════════════════
class AesGcmOverheadTestCase : public TestCase
{
  public:
    AesGcmOverheadTestCase()
        : TestCase("AES-GCM adds correct 28-byte overhead")
    {
    }

    void DoRun() override
    {
        auto cipher = CreateObject<AesGcmCipher>();

        // Install dummy keys
        PqcSessionKeys keys;
        keys.combinedSecret.resize(32, 0x42);
        keys.encryptionKey.resize(32, 0x42);
        keys.integrityKey.resize(32, 0x42);
        keys.nonceBase.resize(12, 0x00);
        cipher->InstallKeys(keys);

        // Encrypt 100 bytes → should get 128 bytes (12 nonce + 100 data + 16 tag)
        std::vector<uint8_t> plaintext(100, 0xAB);
        auto encResult = cipher->Encrypt(plaintext);
        NS_TEST_ASSERT_MSG_EQ(encResult.ciphertext.size(), 128u,
                              "100B plaintext + 28B overhead = 128B");
        NS_TEST_ASSERT_MSG_EQ(encResult.overhead, 28u, "GCM overhead should be 28 bytes");

        // Decrypt → should get back 100 bytes
        auto decResult = cipher->Decrypt(encResult.ciphertext);
        NS_TEST_ASSERT_MSG_EQ(decResult.plaintext.size(), 100u,
                              "Decrypted should be 100 bytes");
        NS_TEST_ASSERT_MSG_EQ(decResult.authenticated, true, "Auth should succeed");

        Simulator::Destroy();
    }
};

// ════════════════════════════════════════════════════════
// Test 6: Full handshake end-to-end
// ════════════════════════════════════════════════════════
class FullHandshakeTestCase : public TestCase
{
  public:
    FullHandshakeTestCase()
        : TestCase("Full hybrid PQC handshake completes successfully")
    {
    }

    void DoRun() override
    {
        // Create UE-side and gNB-side RRC extensions
        auto ueRrc = CreateObject<PqcRrcExtension>();
        ueRrc->SetRole(PqcRrcExtension::UE_ROLE);
        auto uePdcp = CreateObject<PqcPdcpLayer>();
        ueRrc->SetPdcpLayer(uePdcp);

        auto gnbRrc = CreateObject<PqcRrcExtension>();
        gnbRrc->SetRole(PqcRrcExtension::GNB_ROLE);
        auto gnbPdcp = CreateObject<PqcPdcpLayer>();
        gnbRrc->SetPdcpLayer(gnbPdcp);

        // Step 1: UE generates connection request
        auto requestPayload = ueRrc->GenerateConnectionRequest();
        NS_TEST_ASSERT_MSG_GT(requestPayload.TotalSize(), 0u,
                              "Request payload should not be empty");
        NS_TEST_ASSERT_MSG_EQ(requestPayload.rejected, false,
                              "Request should not be rejected");

        // Step 2: gNB processes request
        auto setupPayload = gnbRrc->ProcessConnectionRequest(requestPayload);
        NS_TEST_ASSERT_MSG_EQ(setupPayload.rejected, false,
                              "Setup should not be rejected");
        NS_TEST_ASSERT_MSG_GT(setupPayload.kyberCiphertext.size(), 0u,
                              "Should have Kyber ciphertext");

        // Step 3: UE completes key exchange
        auto sessionKeys = ueRrc->CompleteKeyExchange(setupPayload);
        NS_TEST_ASSERT_MSG_EQ(sessionKeys.IsValid(), true,
                              "Session keys should be valid");
        NS_TEST_ASSERT_MSG_EQ(sessionKeys.isHybrid, true,
                              "Keys should be hybrid");

        // Verify both sides have completed
        NS_TEST_ASSERT_MSG_EQ(ueRrc->IsHandshakeComplete(), true,
                              "UE handshake should be complete");
        NS_TEST_ASSERT_MSG_EQ(gnbRrc->IsHandshakeComplete(), true,
                              "gNB handshake should be complete");

        // Verify PDCP layers are in ENCRYPTED mode
        NS_TEST_ASSERT_MSG_EQ(uePdcp->GetMode(), PqcPdcpLayer::ENCRYPTED,
                              "UE PDCP should be ENCRYPTED");
        NS_TEST_ASSERT_MSG_EQ(gnbPdcp->GetMode(), PqcPdcpLayer::ENCRYPTED,
                              "gNB PDCP should be ENCRYPTED");

        Simulator::Destroy();
    }
};

// ════════════════════════════════════════════════════════
// Test Suite Registration
// ════════════════════════════════════════════════════════
class PqcSecurityTestSuite : public TestSuite
{
  public:
    PqcSecurityTestSuite()
        : TestSuite("pqc-security", Type::UNIT)
    {
        AddTestCase(new KyberSizesTestCase, TestCase::Duration::QUICK);
        AddTestCase(new X25519SizesTestCase, TestCase::Duration::QUICK);
        AddTestCase(new HybridKemSizesTestCase, TestCase::Duration::QUICK);
        AddTestCase(new MlDsaSizesTestCase, TestCase::Duration::QUICK);
        AddTestCase(new AesGcmOverheadTestCase, TestCase::Duration::QUICK);
        AddTestCase(new FullHandshakeTestCase, TestCase::Duration::QUICK);
    }
};

static PqcSecurityTestSuite g_pqcSecurityTestSuite;
