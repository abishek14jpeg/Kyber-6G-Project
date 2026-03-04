#!/usr/bin/env python3
"""Create all Kyber-6G project files."""
import os

BASE = '/home/abishek14/Kyber-6G project/ns-3-dev/scratch/kyber-6g'
os.makedirs(BASE, exist_ok=True)
os.makedirs(os.path.join(BASE, 'lib'), exist_ok=True)

# ============================================================
# FILE 1: CMakeLists.txt
# ============================================================
with open(os.path.join(BASE, 'CMakeLists.txt'), 'w') as f:
    f.write(r'''# Kyber-6G Project - Build Configuration
add_library(
  kyber-6g-lib
  lib/kyber-crypto.cc
)

# Link liboqs and OpenSSL to our crypto library
target_include_directories(kyber-6g-lib PUBLIC /usr/local/include)
target_link_libraries(kyber-6g-lib /usr/local/lib/liboqs.a -lssl -lcrypto)

build_exec(
  EXECNAME kyber-6g-sim
  SOURCE_FILES kyber-6g-sim.cc
  LIBRARIES_TO_LINK kyber-6g-lib
                    ${libcore}
                    ${libnetwork}
                    ${libinternet}
                    ${libmobility}
                    ${libapplications}
                    ${libnr}
                    ${liblte}
                    ${libflow-monitor}
                    ${libpoint-to-point}
                    ${libantenna}
                    ${libspectrum}
                    ${libpropagation}
                    ${libbuildings}
                    ${libconfig-store}
                    ${libstats}
                    ${libinternet-apps}
  EXECUTABLE_DIRECTORY_PATH ${CMAKE_OUTPUT_DIRECTORY}/scratch/kyber-6g
)
''')

# ============================================================
# FILE 2: lib/kyber-crypto.h - Kyber + AES wrapper
# ============================================================
with open(os.path.join(BASE, 'lib', 'kyber-crypto.h'), 'w') as f:
    f.write(r'''#ifndef KYBER_CRYPTO_H
#define KYBER_CRYPTO_H

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace kyber6g {

// ===================================================================
// Kyber Key Exchange Wrapper
// ===================================================================
struct KyberKeyPair {
    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> secretKey;
};

struct KyberCiphertext {
    std::vector<uint8_t> ciphertext;
};

struct KyberSharedSecret {
    std::vector<uint8_t> secret; // 32 bytes
};

// Security levels mapping to liboqs algorithm names
enum class KyberLevel {
    Kyber512,   // NIST Level 1 (AES-128 equivalent)
    Kyber768,   // NIST Level 3 (AES-192 equivalent)
    Kyber1024   // NIST Level 5 (AES-256 equivalent)
};

// Get liboqs algorithm name for each Kyber level
inline const char* GetKyberAlgName(KyberLevel level) {
    switch (level) {
        case KyberLevel::Kyber512:  return OQS_KEM_alg_kyber_512;
        case KyberLevel::Kyber768:  return OQS_KEM_alg_kyber_768;
        case KyberLevel::Kyber1024: return OQS_KEM_alg_kyber_1024;
        default: return OQS_KEM_alg_kyber_768;
    }
}

// Get public key size for each level
inline size_t GetKyberPublicKeySize(KyberLevel level) {
    switch (level) {
        case KyberLevel::Kyber512:  return 800;
        case KyberLevel::Kyber768:  return 1184;
        case KyberLevel::Kyber1024: return 1568;
        default: return 1184;
    }
}

// Get ciphertext size for each level
inline size_t GetKyberCiphertextSize(KyberLevel level) {
    switch (level) {
        case KyberLevel::Kyber512:  return 768;
        case KyberLevel::Kyber768:  return 1088;
        case KyberLevel::Kyber1024: return 1568;
        default: return 1088;
    }
}

// Simulated ECC key sizes (for comparison baseline)
inline size_t GetEccPublicKeySize() { return 65; }   // P-256 uncompressed
inline size_t GetEccCiphertextSize() { return 65; }   // ECDH ephemeral

// Generate Kyber keypair
bool KyberKeygen(KyberLevel level, KyberKeyPair& kp);

// Encapsulate: generate ciphertext + shared secret from public key
bool KyberEncaps(KyberLevel level,
                 const std::vector<uint8_t>& publicKey,
                 KyberCiphertext& ct,
                 KyberSharedSecret& ss);

// Decapsulate: recover shared secret from ciphertext + secret key
bool KyberDecaps(KyberLevel level,
                 const std::vector<uint8_t>& ciphertext,
                 const std::vector<uint8_t>& secretKey,
                 KyberSharedSecret& ss);

// ===================================================================
// AES-256-GCM Encryption/Decryption
// ===================================================================
struct AesEncrypted {
    std::vector<uint8_t> iv;          // 12 bytes
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> tag;         // 16 bytes
};

// Encrypt data with AES-256-GCM using a 32-byte key
bool AesEncrypt(const std::vector<uint8_t>& key,
                const std::vector<uint8_t>& plaintext,
                AesEncrypted& out);

// Decrypt AES-256-GCM ciphertext
bool AesDecrypt(const std::vector<uint8_t>& key,
                const AesEncrypted& encrypted,
                std::vector<uint8_t>& plaintext);

// Get total encrypted message size (iv + ciphertext + tag)
inline size_t AesOverhead() { return 12 + 16; } // IV + GCM tag

// Utility: hex string for debugging
std::string ToHex(const std::vector<uint8_t>& data, size_t maxBytes = 8);

} // namespace kyber6g

#endif // KYBER_CRYPTO_H
''')

# ============================================================
# FILE 3: lib/kyber-crypto.cc - Implementation
# ============================================================
with open(os.path.join(BASE, 'lib', 'kyber-crypto.cc'), 'w') as f:
    f.write(r'''#include "kyber-crypto.h"

namespace kyber6g {

bool KyberKeygen(KyberLevel level, KyberKeyPair& kp) {
    OQS_KEM *kem = OQS_KEM_new(GetKyberAlgName(level));
    if (!kem) {
        std::cerr << "Failed to initialize Kyber KEM" << std::endl;
        return false;
    }

    kp.publicKey.resize(kem->length_public_key);
    kp.secretKey.resize(kem->length_secret_key);

    OQS_STATUS rc = OQS_KEM_keypair(kem, kp.publicKey.data(), kp.secretKey.data());
    OQS_KEM_free(kem);

    return rc == OQS_SUCCESS;
}

bool KyberEncaps(KyberLevel level,
                 const std::vector<uint8_t>& publicKey,
                 KyberCiphertext& ct,
                 KyberSharedSecret& ss) {
    OQS_KEM *kem = OQS_KEM_new(GetKyberAlgName(level));
    if (!kem) return false;

    ct.ciphertext.resize(kem->length_ciphertext);
    ss.secret.resize(kem->length_shared_secret);

    OQS_STATUS rc = OQS_KEM_encaps(kem, ct.ciphertext.data(),
                                    ss.secret.data(), publicKey.data());
    OQS_KEM_free(kem);

    return rc == OQS_SUCCESS;
}

bool KyberDecaps(KyberLevel level,
                 const std::vector<uint8_t>& ciphertext,
                 const std::vector<uint8_t>& secretKey,
                 KyberSharedSecret& ss) {
    OQS_KEM *kem = OQS_KEM_new(GetKyberAlgName(level));
    if (!kem) return false;

    ss.secret.resize(kem->length_shared_secret);

    OQS_STATUS rc = OQS_KEM_decaps(kem, ss.secret.data(),
                                    ciphertext.data(), secretKey.data());
    OQS_KEM_free(kem);

    return rc == OQS_SUCCESS;
}

bool AesEncrypt(const std::vector<uint8_t>& key,
                const std::vector<uint8_t>& plaintext,
                AesEncrypted& out) {
    if (key.size() != 32) return false;

    // Generate random IV (12 bytes for GCM)
    out.iv.resize(12);
    RAND_bytes(out.iv.data(), 12);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len = 0;
    out.ciphertext.resize(plaintext.size() + 16); // max expansion
    out.tag.resize(16);

    bool ok = true;
    ok = ok && (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1);
    ok = ok && (EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), out.iv.data()) == 1);
    ok = ok && (EVP_EncryptUpdate(ctx, out.ciphertext.data(), &len,
                                   plaintext.data(), plaintext.size()) == 1);
    int ciphertext_len = len;
    ok = ok && (EVP_EncryptFinal_ex(ctx, out.ciphertext.data() + len, &len) == 1);
    ciphertext_len += len;
    out.ciphertext.resize(ciphertext_len);
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out.tag.data()) == 1);

    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool AesDecrypt(const std::vector<uint8_t>& key,
                const AesEncrypted& encrypted,
                std::vector<uint8_t>& plaintext) {
    if (key.size() != 32) return false;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len = 0;
    plaintext.resize(encrypted.ciphertext.size());

    bool ok = true;
    ok = ok && (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) == 1);
    ok = ok && (EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), encrypted.iv.data()) == 1);
    ok = ok && (EVP_DecryptUpdate(ctx, plaintext.data(), &len,
                                   encrypted.ciphertext.data(),
                                   encrypted.ciphertext.size()) == 1);
    int plaintext_len = len;
    ok = ok && (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                                     (void*)encrypted.tag.data()) == 1);
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintext_len += len;
    plaintext.resize(plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return ok && (ret > 0);
}

std::string ToHex(const std::vector<uint8_t>& data, size_t maxBytes) {
    std::ostringstream ss;
    size_t n = std::min(data.size(), maxBytes);
    for (size_t i = 0; i < n; i++) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)data[i];
    }
    if (data.size() > maxBytes) ss << "...";
    return ss.str();
}

} // namespace kyber6g
''')

# ============================================================
# FILE 4: kyber-6g-sim.cc - MASTER simulation (Steps 2-7)
# ============================================================
with open(os.path.join(BASE, 'kyber-6g-sim.cc'), 'w') as f:
    f.write(r'''/* -*- Mode: C++; c-file-style: "gnu"; indent-tabs-mode:nil; -*- */
// Kyber-6G Project: Complete 5G/6G Post-Quantum Security Simulation
// Steps 2-7: Mobility, Handover, Kyber Key Exchange, AES Encryption,
//            Performance Measurement, and Parameterized Experiments

#include "lib/kyber-crypto.h"

#include "ns3/antenna-module.h"
#include "ns3/applications-module.h"
#include "ns3/config-store-module.h"
#include "ns3/core-module.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/internet-apps-module.h"
#include "ns3/internet-module.h"
#include "ns3/mobility-module.h"
#include "ns3/network-module.h"
#include "ns3/nr-module.h"
#include "ns3/point-to-point-module.h"

#include <fstream>
#include <iomanip>
#include <chrono>

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("Kyber6gSim");

// ===================================================================
// Global state for Kyber key exchange (shared across apps)
// ===================================================================
static kyber6g::KyberKeyPair g_userB_keypair;
static kyber6g::KyberSharedSecret g_userA_sharedSecret;
static kyber6g::KyberSharedSecret g_userB_sharedSecret;
static bool g_keyExchangeComplete = false;
static kyber6g::KyberLevel g_kyberLevel = kyber6g::KyberLevel::Kyber768;
static bool g_useKyber = true;       // false = ECC baseline
static bool g_useEncryption = false;  // true = AES encrypt data
static uint32_t g_kyberPkBytes = 0;
static uint32_t g_kyberCtBytes = 0;
static double g_kyberKeygenTimeUs = 0;
static double g_kyberEncapsTimeUs = 0;
static double g_kyberDecapsTimeUs = 0;

// ===================================================================
// Custom Application: Kyber Key Exchange Initiator (User A)
// Sends: Kyber public key request -> receives ciphertext -> derives key
// ===================================================================
class KyberInitiatorApp : public Application {
public:
    static TypeId GetTypeId() {
        static TypeId tid = TypeId("ns3::KyberInitiatorApp")
            .SetParent<Application>()
            .SetGroupName("Applications")
            .AddConstructor<KyberInitiatorApp>();
        return tid;
    }
    KyberInitiatorApp() : m_socket(nullptr), m_peer(), m_peerPort(5000) {}

    void Setup(Address peerAddr, uint16_t port) {
        m_peer = peerAddr;
        m_peerPort = port;
    }

private:
    void StartApplication() override {
        m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
        m_socket->Bind();
        m_socket->Connect(InetSocketAddress(Ipv4Address::ConvertFrom(m_peer), m_peerPort));
        m_socket->SetRecvCallback(MakeCallback(&KyberInitiatorApp::HandleRead, this));

        // Schedule sending public key
        Simulator::Schedule(MilliSeconds(10), &KyberInitiatorApp::SendPublicKey, this);
    }

    void StopApplication() override {
        if (m_socket) { m_socket->Close(); m_socket = nullptr; }
    }

    void SendPublicKey() {
        // Generate keypair for User B (responder generates keypair, sends PK to initiator)
        // Actually in Kyber KEM: User B generates keypair, sends PK to User A
        // User A encapsulates with PK, sends ciphertext to User B
        // For this simulation: User A requests key exchange by sending a "hello" trigger
        // Then User B responds with public key, User A encapsulates and sends CT back

        NS_LOG_INFO("[UserA] Initiating key exchange...");

        // Send a small trigger packet (simulates key exchange initiation)
        uint8_t trigger = 0x01; // KE_INIT
        Ptr<Packet> p = Create<Packet>(&trigger, 1);
        m_socket->Send(p);
    }

    void HandleRead(Ptr<Socket> socket) {
        Ptr<Packet> packet;
        Address from;
        while ((packet = socket->RecvFrom(from))) {
            uint32_t size = packet->GetSize();
            std::vector<uint8_t> buf(size);
            packet->CopyData(buf.data(), size);

            if (buf[0] == 0x02 && !g_keyExchangeComplete) {
                // Received public key from User B
                std::vector<uint8_t> pk(buf.begin() + 1, buf.end());
                NS_LOG_INFO("[UserA] Received public key (" << pk.size() << " bytes)");
                g_kyberPkBytes = pk.size();

                // Encapsulate
                kyber6g::KyberCiphertext ct;
                auto t1 = std::chrono::high_resolution_clock::now();
                bool ok = kyber6g::KyberEncaps(g_kyberLevel, pk, ct, g_userA_sharedSecret);
                auto t2 = std::chrono::high_resolution_clock::now();
                g_kyberEncapsTimeUs = std::chrono::duration<double, std::micro>(t2 - t1).count();

                if (ok) {
                    NS_LOG_INFO("[UserA] Encapsulated. Ciphertext: " << ct.ciphertext.size()
                                << " bytes. Shared secret: " << kyber6g::ToHex(g_userA_sharedSecret.secret));
                    g_kyberCtBytes = ct.ciphertext.size();

                    // Send ciphertext to User B (prepend 0x03 tag)
                    std::vector<uint8_t> msg;
                    msg.push_back(0x03);
                    msg.insert(msg.end(), ct.ciphertext.begin(), ct.ciphertext.end());
                    Ptr<Packet> ctPkt = Create<Packet>(msg.data(), msg.size());
                    m_socket->Send(ctPkt);
                    NS_LOG_INFO("[UserA] Sent ciphertext to User B");
                }
            }
            else if (buf[0] == 0x04) {
                // Key exchange confirmed by User B
                g_keyExchangeComplete = true;
                NS_LOG_INFO("[UserA] Key exchange COMPLETE! Ready for encrypted communication.");
            }
        }
    }

    Ptr<Socket> m_socket;
    Address m_peer;
    uint16_t m_peerPort;
};

// ===================================================================
// Custom Application: Kyber Key Exchange Responder (User B)
// Receives trigger -> sends public key -> receives ciphertext -> derives key
// ===================================================================
class KyberResponderApp : public Application {
public:
    static TypeId GetTypeId() {
        static TypeId tid = TypeId("ns3::KyberResponderApp")
            .SetParent<Application>()
            .SetGroupName("Applications")
            .AddConstructor<KyberResponderApp>();
        return tid;
    }
    KyberResponderApp() : m_socket(nullptr), m_port(5000) {}

    void Setup(uint16_t port) { m_port = port; }

private:
    void StartApplication() override {
        m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
        m_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), m_port));
        m_socket->SetRecvCallback(MakeCallback(&KyberResponderApp::HandleRead, this));

        // Pre-generate keypair
        auto t1 = std::chrono::high_resolution_clock::now();
        kyber6g::KyberKeygen(g_kyberLevel, g_userB_keypair);
        auto t2 = std::chrono::high_resolution_clock::now();
        g_kyberKeygenTimeUs = std::chrono::duration<double, std::micro>(t2 - t1).count();

        NS_LOG_INFO("[UserB] Keypair generated. PK size: " << g_userB_keypair.publicKey.size()
                    << " SK size: " << g_userB_keypair.secretKey.size());
    }

    void StopApplication() override {
        if (m_socket) { m_socket->Close(); m_socket = nullptr; }
    }

    void HandleRead(Ptr<Socket> socket) {
        Ptr<Packet> packet;
        Address from;
        while ((packet = socket->RecvFrom(from))) {
            uint32_t size = packet->GetSize();
            std::vector<uint8_t> buf(size);
            packet->CopyData(buf.data(), size);

            InetSocketAddress senderAddr = InetSocketAddress::ConvertFrom(from);

            if (buf[0] == 0x01) {
                // Received KE initiation from User A
                NS_LOG_INFO("[UserB] Received KE request. Sending public key...");

                // Send public key (prepend 0x02 tag)
                std::vector<uint8_t> msg;
                msg.push_back(0x02);
                msg.insert(msg.end(), g_userB_keypair.publicKey.begin(),
                           g_userB_keypair.publicKey.end());
                Ptr<Packet> pkPkt = Create<Packet>(msg.data(), msg.size());
                socket->SendTo(pkPkt, 0, from);
            }
            else if (buf[0] == 0x03 && !g_keyExchangeComplete) {
                // Received ciphertext from User A
                std::vector<uint8_t> ct(buf.begin() + 1, buf.end());
                NS_LOG_INFO("[UserB] Received ciphertext (" << ct.size() << " bytes)");

                // Decapsulate
                auto t1 = std::chrono::high_resolution_clock::now();
                bool ok = kyber6g::KyberDecaps(g_kyberLevel, ct,
                                                g_userB_keypair.secretKey,
                                                g_userB_sharedSecret);
                auto t2 = std::chrono::high_resolution_clock::now();
                g_kyberDecapsTimeUs = std::chrono::duration<double, std::micro>(t2 - t1).count();

                if (ok) {
                    NS_LOG_INFO("[UserB] Decapsulated. Shared secret: "
                                << kyber6g::ToHex(g_userB_sharedSecret.secret));

                    // Verify secrets match
                    bool match = (g_userA_sharedSecret.secret == g_userB_sharedSecret.secret);
                    NS_LOG_INFO("[UserB] Secrets match: " << (match ? "YES" : "NO"));

                    // Send confirmation (0x04)
                    uint8_t confirm = 0x04;
                    Ptr<Packet> confPkt = Create<Packet>(&confirm, 1);
                    socket->SendTo(confPkt, 0, from);

                    g_keyExchangeComplete = true;
                    NS_LOG_INFO("[UserB] Key exchange COMPLETE!");
                }
            }
        }
    }

    Ptr<Socket> m_socket;
    uint16_t m_port;
};

// ===================================================================
// Custom Application: Encrypted Data Sender (User A -> User B)
// ===================================================================
class EncryptedSenderApp : public Application {
public:
    static TypeId GetTypeId() {
        static TypeId tid = TypeId("ns3::EncryptedSenderApp")
            .SetParent<Application>()
            .SetGroupName("Applications")
            .AddConstructor<EncryptedSenderApp>();
        return tid;
    }
    EncryptedSenderApp() : m_socket(nullptr), m_running(false),
        m_packetSize(1024), m_interval(Seconds(0.01)), m_sent(0) {}

    void Setup(Address peer, uint16_t port, uint32_t pktSize, Time interval) {
        m_peer = peer; m_port = port; m_packetSize = pktSize; m_interval = interval;
    }

private:
    void StartApplication() override {
        m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
        m_socket->Connect(InetSocketAddress(Ipv4Address::ConvertFrom(m_peer), m_port));
        m_running = true;
        SendPacket();
    }

    void StopApplication() override {
        m_running = false;
        if (m_socket) { m_socket->Close(); m_socket = nullptr; }
    }

    void SendPacket() {
        if (!m_running) return;

        // Create plaintext payload
        std::vector<uint8_t> plaintext(m_packetSize);
        for (uint32_t i = 0; i < m_packetSize; i++)
            plaintext[i] = (uint8_t)(m_sent + i);

        if (g_useEncryption && g_keyExchangeComplete) {
            // AES encrypt the data
            kyber6g::AesEncrypted encrypted;
            if (kyber6g::AesEncrypt(g_userA_sharedSecret.secret, plaintext, encrypted)) {
                // Pack: [iv(12) | tag(16) | ciphertext]
                std::vector<uint8_t> wire;
                wire.insert(wire.end(), encrypted.iv.begin(), encrypted.iv.end());
                wire.insert(wire.end(), encrypted.tag.begin(), encrypted.tag.end());
                wire.insert(wire.end(), encrypted.ciphertext.begin(), encrypted.ciphertext.end());

                Ptr<Packet> p = Create<Packet>(wire.data(), wire.size());
                m_socket->Send(p);
                m_sent++;
            }
        } else {
            // Send plaintext (baseline or pre-key-exchange)
            Ptr<Packet> p = Create<Packet>(plaintext.data(), plaintext.size());
            m_socket->Send(p);
            m_sent++;
        }

        if (m_running)
            Simulator::Schedule(m_interval, &EncryptedSenderApp::SendPacket, this);
    }

    Ptr<Socket> m_socket;
    Address m_peer;
    uint16_t m_port;
    bool m_running;
    uint32_t m_packetSize;
    Time m_interval;
    uint32_t m_sent;
};

// ===================================================================
// Custom Application: Encrypted Data Receiver (User B)
// ===================================================================
class EncryptedReceiverApp : public Application {
public:
    static TypeId GetTypeId() {
        static TypeId tid = TypeId("ns3::EncryptedReceiverApp")
            .SetParent<Application>()
            .SetGroupName("Applications")
            .AddConstructor<EncryptedReceiverApp>();
        return tid;
    }
    EncryptedReceiverApp() : m_socket(nullptr), m_received(0), m_decryptOk(0), m_decryptFail(0) {}

    void Setup(uint16_t port) { m_port = port; }
    uint32_t GetReceived() const { return m_received; }
    uint32_t GetDecryptOk() const { return m_decryptOk; }
    uint32_t GetDecryptFail() const { return m_decryptFail; }

private:
    void StartApplication() override {
        m_socket = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
        m_socket->Bind(InetSocketAddress(Ipv4Address::GetAny(), m_port));
        m_socket->SetRecvCallback(MakeCallback(&EncryptedReceiverApp::HandleRead, this));
    }

    void StopApplication() override {
        if (m_socket) { m_socket->Close(); m_socket = nullptr; }
    }

    void HandleRead(Ptr<Socket> socket) {
        Ptr<Packet> packet;
        Address from;
        while ((packet = socket->RecvFrom(from))) {
            m_received++;
            uint32_t size = packet->GetSize();
            std::vector<uint8_t> buf(size);
            packet->CopyData(buf.data(), size);

            if (g_useEncryption && g_keyExchangeComplete && size > 28) {
                // Decrypt: [iv(12) | tag(16) | ciphertext]
                kyber6g::AesEncrypted encrypted;
                encrypted.iv.assign(buf.begin(), buf.begin() + 12);
                encrypted.tag.assign(buf.begin() + 12, buf.begin() + 28);
                encrypted.ciphertext.assign(buf.begin() + 28, buf.end());

                std::vector<uint8_t> plaintext;
                if (kyber6g::AesDecrypt(g_userB_sharedSecret.secret, encrypted, plaintext)) {
                    m_decryptOk++;
                } else {
                    m_decryptFail++;
                }
            }
        }
    }

    Ptr<Socket> m_socket;
    uint16_t m_port;
    uint32_t m_received;
    uint32_t m_decryptOk;
    uint32_t m_decryptFail;
};

// Register TypeIds
NS_OBJECT_ENSURE_REGISTERED(KyberInitiatorApp);
NS_OBJECT_ENSURE_REGISTERED(KyberResponderApp);
NS_OBJECT_ENSURE_REGISTERED(EncryptedSenderApp);
NS_OBJECT_ENSURE_REGISTERED(EncryptedReceiverApp);

// ===================================================================
// Handover notification callback
// ===================================================================
static uint32_t g_handoverCount = 0;
void NotifyHandoverStartUe(std::string context, uint64_t imsi, uint16_t cellId, uint16_t rnti,
                            uint16_t targetCellId) {
    g_handoverCount++;
    NS_LOG_INFO("** HANDOVER: UE IMSI=" << imsi << " from cell " << cellId
                << " to cell " << targetCellId << " (count=" << g_handoverCount << ")");
}

// ===================================================================
// MAIN SIMULATION
// ===================================================================
int main(int argc, char* argv[])
{
    // --- Parameters ---
    Time simTime = MilliSeconds(3000);
    Time keStartTime = MilliSeconds(200);    // Key exchange start
    Time dataStartTime = MilliSeconds(800);  // Data transfer start
    uint32_t packetSize = 1024;
    uint32_t packetsPerSecond = 100;
    double ueSpeed = 20.0;                   // m/s (~72 km/h)
    uint32_t kyberLevelInt = 1;              // 0=512, 1=768, 2=1024
    bool enableMobility = true;
    bool enableHandover = true;
    bool enableKyber = true;
    bool enableEncryption = true;
    bool enableEccBaseline = false;          // If true, use small ECC-sized packets
    std::string outputPrefix = "kyber6g";
    bool logging = true;

    CommandLine cmd(__FILE__);
    cmd.AddValue("simTime", "Simulation time (ms)", simTime);
    cmd.AddValue("packetSize", "Data packet size (bytes)", packetSize);
    cmd.AddValue("pps", "Packets per second", packetsPerSecond);
    cmd.AddValue("speed", "UE speed (m/s)", ueSpeed);
    cmd.AddValue("kyberLevel", "Kyber level: 0=512, 1=768, 2=1024", kyberLevelInt);
    cmd.AddValue("mobility", "Enable mobility", enableMobility);
    cmd.AddValue("handover", "Enable handover (requires mobility)", enableHandover);
    cmd.AddValue("kyber", "Enable Kyber key exchange", enableKyber);
    cmd.AddValue("encryption", "Enable AES encryption", enableEncryption);
    cmd.AddValue("eccBaseline", "Use ECC baseline (small KE packets)", enableEccBaseline);
    cmd.AddValue("output", "Output file prefix", outputPrefix);
    cmd.AddValue("logging", "Enable logging", logging);
    cmd.Parse(argc, argv);

    // Set global flags
    g_kyberLevel = static_cast<kyber6g::KyberLevel>(kyberLevelInt);
    g_useKyber = enableKyber && !enableEccBaseline;
    g_useEncryption = enableEncryption;

    if (logging) {
        LogComponentEnable("Kyber6gSim", LOG_LEVEL_INFO);
    }

    NS_LOG_INFO("");
    NS_LOG_INFO("╔══════════════════════════════════════════════════════════╗");
    NS_LOG_INFO("║    Kyber-6G: Post-Quantum Secure 5G/6G Simulation      ║");
    NS_LOG_INFO("╚══════════════════════════════════════════════════════════╝");
    NS_LOG_INFO("Mode: " << (enableEccBaseline ? "ECC Baseline" : "Kyber PQC")
                << " | Encryption: " << (enableEncryption ? "AES-256-GCM" : "None")
                << " | Mobility: " << (enableMobility ? "ON" : "OFF")
                << " | Handover: " << (enableHandover ? "ON" : "OFF"));
    NS_LOG_INFO("Kyber Level: " << kyberLevelInt << " | Speed: " << ueSpeed
                << " m/s | Sim: " << simTime.GetMilliSeconds() << "ms");
    NS_LOG_INFO("");

    Config::SetDefault("ns3::LteRlcUm::MaxTxBufferSize", UintegerValue(999999999));

    // ===================================================================
    // CREATE NODES: 2 gNBs + 2 UEs
    // ===================================================================
    NS_LOG_INFO("[1] Creating nodes: 2 gNBs + 2 UEs");
    NodeContainer gnbNodes;
    gnbNodes.Create(2);
    NodeContainer ueNodes;
    ueNodes.Create(2);

    // ===================================================================
    // MOBILITY
    // ===================================================================
    NS_LOG_INFO("[2] Setting mobility...");
    MobilityHelper gnbMobility;
    gnbMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    Ptr<ListPositionAllocator> gnbPos = CreateObject<ListPositionAllocator>();
    gnbPos->Add(Vector(0.0, 0.0, 25.0));      // gNB1 at origin
    gnbPos->Add(Vector(500.0, 0.0, 25.0));    // gNB2 at 500m east
    gnbMobility.SetPositionAllocator(gnbPos);
    gnbMobility.Install(gnbNodes);

    // User B (receiver) - fixed position near gNB1
    MobilityHelper ueBMobility;
    ueBMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    Ptr<ListPositionAllocator> ueBPos = CreateObject<ListPositionAllocator>();
    ueBPos->Add(Vector(30.0, 10.0, 1.5));
    ueBMobility.SetPositionAllocator(ueBPos);
    ueBMobility.Install(ueNodes.Get(1));

    // User A (sender) - mobile, moves from gNB1 toward gNB2
    if (enableMobility) {
        MobilityHelper ueAMobility;
        ueAMobility.SetMobilityModel("ns3::ConstantVelocityMobilityModel");
        Ptr<ListPositionAllocator> ueAPos = CreateObject<ListPositionAllocator>();
        ueAPos->Add(Vector(50.0, 0.0, 1.5));  // Start near gNB1
        ueAMobility.SetPositionAllocator(ueAPos);
        ueAMobility.Install(ueNodes.Get(0));
        // Set velocity: moving east toward gNB2
        ueNodes.Get(0)->GetObject<ConstantVelocityMobilityModel>()->SetVelocity(
            Vector(ueSpeed, 0.0, 0.0));
        NS_LOG_INFO("  User A: mobile at " << ueSpeed << " m/s toward gNB2");
    } else {
        MobilityHelper ueAMobility;
        ueAMobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
        Ptr<ListPositionAllocator> ueAPos = CreateObject<ListPositionAllocator>();
        ueAPos->Add(Vector(50.0, 0.0, 1.5));
        ueAMobility.SetPositionAllocator(ueAPos);
        ueAMobility.Install(ueNodes.Get(0));
        NS_LOG_INFO("  User A: fixed position");
    }

    // ===================================================================
    // NR CONFIGURATION
    // ===================================================================
    NS_LOG_INFO("[3] Configuring 5G NR...");
    Ptr<NrPointToPointEpcHelper> epcHelper = CreateObject<NrPointToPointEpcHelper>();
    Ptr<IdealBeamformingHelper> idealBeamformingHelper = CreateObject<IdealBeamformingHelper>();
    Ptr<NrHelper> nrHelper = CreateObject<NrHelper>();
    nrHelper->SetBeamformingHelper(idealBeamformingHelper);
    nrHelper->SetEpcHelper(epcHelper);

    // Handover algorithm
    if (enableHandover) {
        nrHelper->SetHandoverAlgorithmType("ns3::A3RsrpHandoverAlgorithm");
        nrHelper->SetHandoverAlgorithmAttribute("Hysteresis", DoubleValue(1.0));
        nrHelper->SetHandoverAlgorithmAttribute("TimeToTrigger", TimeValue(MilliSeconds(64)));
    }

    double centralFrequency = 3.5e9;
    double bandwidth = 20e6;
    uint16_t numerology = 1;
    double txPower = 43; // higher power for outdoor macro cells

    CcBwpCreator ccBwpCreator;
    CcBwpCreator::SimpleOperationBandConf bandConf(centralFrequency, bandwidth, 1,
                                                    BandwidthPartInfo::UMa_LoS);
    OperationBandInfo band = ccBwpCreator.CreateOperationBandContiguousCc(bandConf);

    Config::SetDefault("ns3::ThreeGppChannelModel::UpdatePeriod", TimeValue(MilliSeconds(100)));
    nrHelper->SetChannelConditionModelAttribute("UpdatePeriod", TimeValue(MilliSeconds(100)));
    nrHelper->SetPathlossAttribute("ShadowingEnabled", BooleanValue(false));
    nrHelper->InitializeOperationBand(&band);
    BandwidthPartInfoPtrVector allBwps = CcBwpCreator::GetAllBwps({band});

    idealBeamformingHelper->SetAttribute("BeamformingMethod",
        TypeIdValue(DirectPathBeamforming::GetTypeId()));
    epcHelper->SetAttribute("S1uLinkDelay", TimeValue(MilliSeconds(2)));

    nrHelper->SetUeAntennaAttribute("NumRows", UintegerValue(2));
    nrHelper->SetUeAntennaAttribute("NumColumns", UintegerValue(4));
    nrHelper->SetUeAntennaAttribute("AntennaElement",
        PointerValue(CreateObject<IsotropicAntennaModel>()));
    nrHelper->SetGnbAntennaAttribute("NumRows", UintegerValue(4));
    nrHelper->SetGnbAntennaAttribute("NumColumns", UintegerValue(8));
    nrHelper->SetGnbAntennaAttribute("AntennaElement",
        PointerValue(CreateObject<IsotropicAntennaModel>()));

    nrHelper->SetGnbBwpManagerAlgorithmAttribute("NGBR_LOW_LAT_EMBB", UintegerValue(0));
    nrHelper->SetUeBwpManagerAlgorithmAttribute("NGBR_LOW_LAT_EMBB", UintegerValue(0));

    // Install NR
    NetDeviceContainer gnbNetDev = nrHelper->InstallGnbDevice(gnbNodes, allBwps);
    NetDeviceContainer ueNetDev = nrHelper->InstallUeDevice(ueNodes, allBwps);

    int64_t randomStream = 1;
    randomStream += nrHelper->AssignStreams(gnbNetDev, randomStream);
    randomStream += nrHelper->AssignStreams(ueNetDev, randomStream);

    for (uint32_t i = 0; i < gnbNetDev.GetN(); i++) {
        nrHelper->GetGnbPhy(gnbNetDev.Get(i), 0)->SetAttribute("Numerology", UintegerValue(numerology));
        nrHelper->GetGnbPhy(gnbNetDev.Get(i), 0)->SetAttribute("TxPower", DoubleValue(txPower));
    }

    for (auto it = gnbNetDev.Begin(); it != gnbNetDev.End(); ++it)
        DynamicCast<NrGnbNetDevice>(*it)->UpdateConfig();
    for (auto it = ueNetDev.Begin(); it != ueNetDev.End(); ++it)
        DynamicCast<NrUeNetDevice>(*it)->UpdateConfig();

    // X2 interface for handover
    if (enableHandover) {
        nrHelper->AddX2Interface(gnbNodes);
        NS_LOG_INFO("  X2 interface added between gNBs for handover");
    }

    // ===================================================================
    // INTERNET STACK
    // ===================================================================
    NS_LOG_INFO("[4] Installing internet stack...");
    Ptr<Node> pgw = epcHelper->GetPgwNode();
    NodeContainer remoteHostContainer;
    remoteHostContainer.Create(1);
    Ptr<Node> remoteHost = remoteHostContainer.Get(0);
    InternetStackHelper internet;
    internet.Install(remoteHostContainer);

    PointToPointHelper p2ph;
    p2ph.SetDeviceAttribute("DataRate", DataRateValue(DataRate("100Gb/s")));
    p2ph.SetDeviceAttribute("Mtu", UintegerValue(2500));
    p2ph.SetChannelAttribute("Delay", TimeValue(Seconds(0.000)));
    NetDeviceContainer internetDevices = p2ph.Install(pgw, remoteHost);

    Ipv4AddressHelper ipv4h;
    ipv4h.SetBase("1.0.0.0", "255.0.0.0");
    ipv4h.Assign(internetDevices);

    Ipv4StaticRoutingHelper routingHelper;
    routingHelper.GetStaticRouting(remoteHost->GetObject<Ipv4>())
        ->AddNetworkRouteTo(Ipv4Address("7.0.0.0"), Ipv4Mask("255.0.0.0"), 1);

    internet.Install(ueNodes);
    Ipv4InterfaceContainer ueIpIfaces = epcHelper->AssignUeIpv4Address(ueNetDev);

    for (uint32_t j = 0; j < ueNodes.GetN(); ++j) {
        routingHelper.GetStaticRouting(ueNodes.Get(j)->GetObject<Ipv4>())
            ->SetDefaultRoute(epcHelper->GetUeDefaultGatewayAddress(), 1);
    }

    nrHelper->AttachToClosestEnb(ueNetDev, gnbNetDev);

    Ipv4Address userAAddr = ueIpIfaces.GetAddress(0);
    Ipv4Address userBAddr = ueIpIfaces.GetAddress(1);
    NS_LOG_INFO("  User A: " << userAAddr << " | User B: " << userBAddr);

    // Handover trace
    if (enableHandover) {
        Config::Connect("/NodeList/*/DeviceList/*/LteUeRrc/HandoverStart",
                        MakeCallback(&NotifyHandoverStartUe));
    }

    // ===================================================================
    // APPLICATIONS
    // ===================================================================
    NS_LOG_INFO("[5] Installing applications...");

    // --- Kyber Key Exchange ---
    if (enableKyber || enableEccBaseline) {
        Ptr<KyberResponderApp> responder = CreateObject<KyberResponderApp>();
        responder->Setup(5000);
        ueNodes.Get(1)->AddApplication(responder);
        responder->SetStartTime(keStartTime);
        responder->SetStopTime(simTime);

        Ptr<KyberInitiatorApp> initiator = CreateObject<KyberInitiatorApp>();
        initiator->Setup(userBAddr, 5000);
        ueNodes.Get(0)->AddApplication(initiator);
        initiator->SetStartTime(keStartTime + MilliSeconds(50));
        initiator->SetStopTime(simTime);

        NS_LOG_INFO("  Key exchange apps installed (starts at " << keStartTime.GetMilliSeconds() << "ms)");
    }

    // --- Data Transfer (with optional AES encryption) ---
    uint16_t dataPort = 6000;
    Ptr<EncryptedReceiverApp> receiver = CreateObject<EncryptedReceiverApp>();
    receiver->Setup(dataPort);
    ueNodes.Get(1)->AddApplication(receiver);
    receiver->SetStartTime(dataStartTime);
    receiver->SetStopTime(simTime);

    Ptr<EncryptedSenderApp> sender = CreateObject<EncryptedSenderApp>();
    sender->Setup(userBAddr, dataPort, packetSize,
                  Seconds(1.0 / packetsPerSecond));
    ueNodes.Get(0)->AddApplication(sender);
    sender->SetStartTime(dataStartTime);
    sender->SetStopTime(simTime);

    // EPS bearers
    EpsBearer bearer(EpsBearer::NGBR_LOW_LAT_EMBB);
    Ptr<EpcTft> tftA = Create<EpcTft>();
    EpcTft::PacketFilter pfA;
    pfA.direction = EpcTft::UPLINK;
    tftA->Add(pfA);
    nrHelper->ActivateDedicatedEpsBearer(ueNetDev.Get(0), bearer, tftA);

    Ptr<EpcTft> tftB = Create<EpcTft>();
    EpcTft::PacketFilter pfB;
    pfB.direction = EpcTft::DOWNLINK;
    tftB->Add(pfB);
    nrHelper->ActivateDedicatedEpsBearer(ueNetDev.Get(1), bearer, tftB);

    NS_LOG_INFO("  Data apps installed (starts at " << dataStartTime.GetMilliSeconds() << "ms)");

    // ===================================================================
    // FLOW MONITOR
    // ===================================================================
    FlowMonitorHelper flowHelper;
    NodeContainer allEndpoints;
    allEndpoints.Add(ueNodes);
    allEndpoints.Add(remoteHost);
    Ptr<FlowMonitor> monitor = flowHelper.Install(allEndpoints);

    // ===================================================================
    // RUN
    // ===================================================================
    NS_LOG_INFO("[6] Running simulation for " << simTime.GetMilliSeconds() << "ms...");
    NS_LOG_INFO("═══════════════════════════════════════════════════════════");

    Simulator::Stop(simTime);
    Simulator::Run();

    // ===================================================================
    // RESULTS
    // ===================================================================
    monitor->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier =
        DynamicCast<Ipv4FlowClassifier>(flowHelper.GetClassifier());
    FlowMonitor::FlowStatsContainer stats = monitor->GetFlowStats();
    double flowDuration = (simTime - dataStartTime).GetSeconds();

    // Collect metrics
    double totalThroughput = 0, totalDelay = 0, totalJitter = 0;
    uint32_t totalTx = 0, totalRx = 0, flowCount = 0;

    std::cout << "\n========================================================" << std::endl;
    std::cout << " Kyber-6G Simulation Results" << std::endl;
    std::cout << "========================================================" << std::endl;
    std::cout << " Mode: " << (enableEccBaseline ? "ECC Baseline" : "Kyber PQC") << std::endl;
    std::cout << " Encryption: " << (enableEncryption ? "AES-256-GCM" : "None") << std::endl;
    std::cout << " Mobility: " << (enableMobility ? "ON" : "OFF")
              << " | Speed: " << ueSpeed << " m/s" << std::endl;
    std::cout << " Handovers: " << g_handoverCount << std::endl;
    std::cout << "--------------------------------------------------------" << std::endl;

    for (auto i = stats.begin(); i != stats.end(); ++i) {
        Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(i->first);
        std::string proto = (t.protocol == 17) ? "UDP" : "TCP";
        std::cout << "Flow " << i->first << ": " << t.sourceAddress << ":"
                  << t.sourcePort << " --> " << t.destinationAddress << ":"
                  << t.destinationPort << " [" << proto << "]" << std::endl;
        std::cout << "  Tx: " << i->second.txPackets << " pkts ("
                  << i->second.txBytes << " B)" << std::endl;
        std::cout << "  Rx: " << i->second.rxPackets << " pkts ("
                  << i->second.rxBytes << " B)" << std::endl;

        totalTx += i->second.txPackets;
        totalRx += i->second.rxPackets;

        if (i->second.rxPackets > 0) {
            double tput = i->second.rxBytes * 8.0 / flowDuration / 1e6;
            double delay = 1000.0 * i->second.delaySum.GetSeconds() / i->second.rxPackets;
            double jitter = 1000.0 * i->second.jitterSum.GetSeconds() / i->second.rxPackets;
            double loss = (i->second.txPackets - i->second.rxPackets) * 100.0 / i->second.txPackets;
            std::cout << "  Throughput: " << tput << " Mbps" << std::endl;
            std::cout << "  Delay: " << delay << " ms | Jitter: " << jitter
                      << " ms | Loss: " << loss << "%" << std::endl;
            totalThroughput += tput;
            totalDelay += delay;
            totalJitter += jitter;
            flowCount++;
        }
        std::cout << std::endl;
    }

    // Crypto stats
    if (enableKyber && !enableEccBaseline) {
        std::cout << "--- Kyber Crypto Stats ---" << std::endl;
        std::cout << "  Public key size:  " << g_kyberPkBytes << " bytes" << std::endl;
        std::cout << "  Ciphertext size:  " << g_kyberCtBytes << " bytes" << std::endl;
        std::cout << "  Keygen time:      " << g_kyberKeygenTimeUs << " us" << std::endl;
        std::cout << "  Encaps time:      " << g_kyberEncapsTimeUs << " us" << std::endl;
        std::cout << "  Decaps time:      " << g_kyberDecapsTimeUs << " us" << std::endl;
        std::cout << "  Key exchange:     " << (g_keyExchangeComplete ? "SUCCESS" : "FAILED") << std::endl;
    }

    if (enableEncryption && receiver) {
        std::cout << "--- Encryption Stats ---" << std::endl;
        std::cout << "  Received:    " << receiver->GetReceived() << " packets" << std::endl;
        std::cout << "  Decrypt OK:  " << receiver->GetDecryptOk() << std::endl;
        std::cout << "  Decrypt Fail:" << receiver->GetDecryptFail() << std::endl;
    }

    std::cout << "--- Summary ---" << std::endl;
    std::cout << "  Total Tx: " << totalTx << " | Total Rx: " << totalRx << std::endl;
    if (flowCount > 0) {
        std::cout << "  Avg Throughput: " << totalThroughput / flowCount << " Mbps" << std::endl;
        std::cout << "  Avg Delay: " << totalDelay / flowCount << " ms" << std::endl;
        std::cout << "  Avg Jitter: " << totalJitter / flowCount << " ms" << std::endl;
    }
    std::cout << "  Handovers: " << g_handoverCount << std::endl;
    std::cout << "========================================================\n" << std::endl;

    // ===================================================================
    // WRITE CSV OUTPUT
    // ===================================================================
    std::string csvFile = outputPrefix + "_results.csv";
    std::ofstream csv(csvFile, std::ios::app);
    // Header (write once)
    {
        std::ifstream check(csvFile);
        check.seekg(0, std::ios::end);
        if (check.tellg() <= 1) {
            csv << "mode,kyber_level,encryption,mobility,speed_ms,handover,"
                << "sim_time_ms,pkt_size,pps,total_tx,total_rx,avg_throughput_mbps,"
                << "avg_delay_ms,avg_jitter_ms,packet_loss_pct,handover_count,"
                << "pk_size_bytes,ct_size_bytes,keygen_us,encaps_us,decaps_us,"
                << "ke_success,decrypt_ok,decrypt_fail" << std::endl;
        }
    }

    double avgLoss = (totalTx > 0) ? (totalTx - totalRx) * 100.0 / totalTx : 0;
    csv << (enableEccBaseline ? "ECC" : "Kyber") << ","
        << kyberLevelInt << ","
        << (enableEncryption ? "AES256" : "None") << ","
        << (enableMobility ? "ON" : "OFF") << ","
        << ueSpeed << ","
        << (enableHandover ? "ON" : "OFF") << ","
        << simTime.GetMilliSeconds() << ","
        << packetSize << ","
        << packetsPerSecond << ","
        << totalTx << "," << totalRx << ","
        << (flowCount > 0 ? totalThroughput / flowCount : 0) << ","
        << (flowCount > 0 ? totalDelay / flowCount : 0) << ","
        << (flowCount > 0 ? totalJitter / flowCount : 0) << ","
        << avgLoss << ","
        << g_handoverCount << ","
        << g_kyberPkBytes << "," << g_kyberCtBytes << ","
        << g_kyberKeygenTimeUs << "," << g_kyberEncapsTimeUs << "," << g_kyberDecapsTimeUs << ","
        << (g_keyExchangeComplete ? 1 : 0) << ","
        << (receiver ? receiver->GetDecryptOk() : 0) << ","
        << (receiver ? receiver->GetDecryptFail() : 0) << std::endl;
    csv.close();
    NS_LOG_INFO("Results appended to " << csvFile);

    Simulator::Destroy();
    return EXIT_SUCCESS;
}
''')

print(f"Created all project files in {BASE}")
print("Files created:")
for root, dirs, files in os.walk(BASE):
    for f in files:
        path = os.path.join(root, f)
        size = os.path.getsize(path)
        print(f"  {os.path.relpath(path, BASE):40s} ({size:,} bytes)")
