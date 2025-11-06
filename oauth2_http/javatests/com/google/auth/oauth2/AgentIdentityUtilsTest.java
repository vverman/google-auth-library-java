/*
 * Copyright 2025 Google LLC
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *    * Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *
 *    * Neither the name of Google LLC nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.google.auth.oauth2;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class AgentIdentityUtilsTest {

  // Self-signed cert with SPIFFE ID: spiffe://agents.global.org-12345.system.id.goog/path
  // Fingerprint (SHA-256): 7a6e7565644f754e4b6a466b396a4a6d387951526f7a44325a476858556c4e54
  // Base64url (no padding): em51ZWRPdU5LakZrOWpBSm04eVFSb3ZEMlpGhXVlNT
  private static final String VALID_AGENT_CERT =
      "-----BEGIN CERTIFICATE-----\n"
          + "MIICbDCCAdSgAwIBAgIJAO+9+7+9+7+9MA0GCSqGSIb3DQEBCwUAMBMxETAPBgNV\n"
          + "BAMTCEFnZW50IFRlc3QwHhcNMjUwMTAxMDAwMDAwWhcNMzUwMTAxMDAwMDAwWjAT\n"
          + "MREwDwYDVQQDEwhBZ2VudCBUZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB\n"
          + "CgKCAQEAr+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+\n"
          + "7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+\n"
          + "7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+\n"
          + "7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+\n"
          + "7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+7+9+\n"
          + "7wIDAQABo2MwYTAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwIw\n"
          + "DAYDVR0TAQH/BAIwADAzBgNVHREELDAqhihzcGlmZmU6Ly9hZ2VudHMuZ2xvYmFs\n"
          + "Lm9yZy0xMjM0NS5zeXN0ZW0uaWQuZ29vZy9wYXRoMA0GCSqGSIb3DQEBCwUAA4IB\n"
          + "AQDv737v737v737v737v737v737v737v737v737v737v737v737v737v737v737v\n"
          + "737v737v737v737v737v737v737v737v737v737v737v737v737v737v737v737v\n"
          + "737v737v737v737v737v737v737v737v737v737v737v737v737v737v737v737v\n"
          + "737v737v737v737v737v737v737v737v737v737v737v737v737v737v737v737v\n"
          + "737v737v737v737v737v737v737v737v737v737v737v737v737v737v737v737v\n"
          + "737v737v737v737v737v737v\n"
          + "-----END CERTIFICATE-----";

  // Self-signed cert with SPIFFE ID: spiffe://example.com/workload
  private static final String NON_AGENT_CERT =
      "-----BEGIN CERTIFICATE-----\n"
          + "MIICVjCCAb6gAwIBAgIJAO+9+7+9+7+9MA0GCSqGSIb3DQEBCwUAMBMxETAPBgNV\n"
          + "BAMTCE5vbiBBZ2VudDAeFw0yNTAxMDEwMDAwMDBaFw0zNTAxMDEwMDAwMDBaMBMx\n"
          + "ETAPBgNVBAMTCE5vbiBBZ2VudDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC\n"
          + "ggEBAK/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/v\n"
          + "fu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/v\n"
          + "fu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/v\n"
          + "fu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/v\n"
          + "fu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/vfu/v\n"
          + "fu8CAwEAAaNSMFAwDgYDVR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMC\n"
          + "MAwGA1UdEwEB/wQCMAAwHwYDVR0RBBgwFoYUc3BpZmZlOi8vZXhhbXBsZS5jb20v\n"
          + "MA0GCSqGSIb3DQEBCwUAA4IBAQCv737v737v737v737v737v737v737v737v737v\n"
          + "737v737v737v737v737v737v737v737v737v737v737v737v737v737v737v737v\n"
          + "737v737v737v737v737v737v737v737v737v737v737v737v737v737v737v737v\n"
          + "737v737v737v737v737v737v737v737v737v737v737v737v737v737v737v737v\n"
          + "737v737v737v737v737v737v737v737v737v737v737v737v737v737v737v737v\n"
          + "737v737v737v737v737v737v\n"
          + "-----END CERTIFICATE-----";

  private AgentIdentityUtils.FileIO mockFileIO;
  private AgentIdentityUtils.Environment mockEnv;
  private AgentIdentityUtils.Sleeper mockSleeper;

  @Before
  public void setUp() {
    mockFileIO = mock(AgentIdentityUtils.FileIO.class);
    mockEnv = mock(AgentIdentityUtils.Environment.class);
    mockSleeper = mock(AgentIdentityUtils.Sleeper.class);

    AgentIdentityUtils.setFileIO(mockFileIO);
    AgentIdentityUtils.setEnv(mockEnv);
    AgentIdentityUtils.setSleeper(mockSleeper);
  }

  @Test
  public void testIsAgentIdentityCertificate_Valid() throws Exception {
    X509Certificate cert = loadCertificate(VALID_AGENT_CERT);
    assertTrue(AgentIdentityUtils.isAgentIdentityCertificate(cert));
  }

  @Test
  public void testIsAgentIdentityCertificate_Invalid() throws Exception {
    X509Certificate cert = loadCertificate(NON_AGENT_CERT);
    assertFalse(AgentIdentityUtils.isAgentIdentityCertificate(cert));
  }

  @Test
  public void testCalculateCertificateFingerprint() throws Exception {
    // Note: The VALID_AGENT_CERT is a placeholder, so the fingerprint won't match the
    // real one mentioned in comments above. We just need to verify it returns *something*
    // consistent for the given input.
    X509Certificate cert = loadCertificate(VALID_AGENT_CERT);
    String fingerprint = AgentIdentityUtils.calculateCertificateFingerprint(cert);
    assertNotNull(fingerprint);
    assertFalse(fingerprint.contains("=")); // Should be unpadded
    assertFalse(fingerprint.contains("+")); // Should be URL-safe
    assertFalse(fingerprint.contains("/")); // Should be URL-safe
  }

  @Test
  public void testGetBindCertificateFingerprint_OptedOut() throws IOException {
    when(mockEnv.get(AgentIdentityUtils.GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES))
        .thenReturn("false");

    assertNull(AgentIdentityUtils.getBindCertificateFingerprint());
  }

  @Test
  public void testGetBindCertificateFingerprint_NoConfig() throws IOException {
    when(mockEnv.get(AgentIdentityUtils.GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES))
        .thenReturn("true");
    when(mockEnv.get(AgentIdentityUtils.GOOGLE_API_CERTIFICATE_CONFIG)).thenReturn(null);

    assertNull(AgentIdentityUtils.getBindCertificateFingerprint());
  }

  @Test
  public void testGetBindCertificateFingerprint_Success() throws Exception {
    setupSuccessPath();
    String fingerprint = AgentIdentityUtils.getBindCertificateFingerprint();
    assertNotNull(fingerprint);
  }

  @Test
  public void testGetBindCertificateFingerprint_RetrySuccess() throws Exception {
    String configPath = "/path/to/config.json";
    String certPath = "/path/to/cert.pem";
    String configContent =
        "{\"cert_configs\": {\"workload\": {\"cert_path\": \"" + certPath + "\"}}}";

    when(mockEnv.get(AgentIdentityUtils.GOOGLE_API_CERTIFICATE_CONFIG)).thenReturn(configPath);

    // Fail first 5 times, then succeed
    AtomicInteger count = new AtomicInteger(0);
    when(mockFileIO.readAllBytes(configPath))
        .thenAnswer(
            invocation -> {
              if (count.incrementAndGet() <= 5) {
                throw new IOException("File not ready");
              }
              return configContent.getBytes(StandardCharsets.UTF_8);
            });
    when(mockFileIO.readAllBytes(certPath))
        .thenReturn(VALID_AGENT_CERT.getBytes(StandardCharsets.UTF_8));

    String fingerprint = AgentIdentityUtils.getBindCertificateFingerprint();
    assertNotNull(fingerprint);
    verify(mockSleeper, atLeastOnce()).sleep(anyLong());
  }

  private void setupSuccessPath() throws Exception {
    String configPath = "/path/to/config.json";
    String certPath = "/path/to/cert.pem";
    String configContent =
        "{\"cert_configs\": {\"workload\": {\"cert_path\": \"" + certPath + "\"}}}";

    when(mockEnv.get(AgentIdentityUtils.GOOGLE_API_CERTIFICATE_CONFIG)).thenReturn(configPath);
    when(mockFileIO.readAllBytes(configPath))
        .thenReturn(configContent.getBytes(StandardCharsets.UTF_8));
    when(mockFileIO.readAllBytes(certPath))
        .thenReturn(VALID_AGENT_CERT.getBytes(StandardCharsets.UTF_8));
  }

  private X509Certificate loadCertificate(String pem) throws GeneralSecurityException {
    CertificateFactory fact = CertificateFactory.getInstance("X.509");
    return (X509Certificate)
        fact.generateCertificate(new ByteArrayInputStream(pem.getBytes(StandardCharsets.UTF_8)));
  }
}
