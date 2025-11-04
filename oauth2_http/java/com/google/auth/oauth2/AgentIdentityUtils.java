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

import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonObjectParser;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Strings;
import com.google.common.collect.ImmutableList;
import com.google.common.io.BaseEncoding;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Pattern;
import javax.annotation.Nullable;

/**
 * Internal utility class for handling Agent Identity certificates.
 *
 * <p>This class is responsible for detecting Agent Identity certificates, calculating their
 * fingerprints, and managing the configuration loading with retries to handle startup timing
 * issues.
 */
final class AgentIdentityUtils {

  private static final Logger LOGGER = Logger.getLogger(AgentIdentityUtils.class.getName());

  static final String GOOGLE_API_CERTIFICATE_CONFIG = "GOOGLE_API_CERTIFICATE_CONFIG";
  static final String GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES =
      "GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES";

  private static final List<Pattern> AGENT_IDENTITY_SPIFFE_TRUST_DOMAIN_PATTERNS =
      ImmutableList.of(
          Pattern.compile("^agents\\.global\\.org-\\d+\\.system\\.id\\.goog$"),
          Pattern.compile("^agents\\.global\\.proj-\\d+\\.system\\.id\\.goog$"));

  // Polling configuration
  private static final int TOTAL_TIMEOUT_MS = 30000;
  private static final int FAST_POLL_DURATION_MS = 5000;
  private static final int FAST_POLL_INTERVAL_MS = 100;
  private static final int SLOW_POLL_INTERVAL_MS = 500;

  private static final int SAN_URI_TYPE = 6;

  // Dependencies for testing
  private static FileIO fileIO = new FileIO();
  private static Environment env = new Environment();
  private static Sleeper sleeper = new Sleeper();

  private AgentIdentityUtils() {}

  /**
   * Gets the certificate fingerprint to bind to the access token if an Agent Identity is detected
   * and not opted out.
   *
   * @return The base64url encoded SHA-256 fingerprint of the certificate, or null if binding should
   *     not occur.
   * @throws IOException If there is an error reading the configuration or certificate after
   *     retries.
   */
  @Nullable
  static String getBindCertificateFingerprint() throws IOException {
    if (isOptOutEnabled()) {
      return null;
    }

    String configPath = env.get(GOOGLE_API_CERTIFICATE_CONFIG);
    if (Strings.isNullOrEmpty(configPath)) {
      return null;
    }

    X509Certificate cert = loadAgentIdentityCertificate(configPath);

    if (cert != null && isAgentIdentityCertificate(cert)) {
      return calculateCertificateFingerprint(cert);
    }

    return null;
  }

  private static boolean isOptOutEnabled() {
    String optOut = env.get(GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES);
    return "false".equalsIgnoreCase(optOut);
  }

  /**
   * Loads the Agent Identity certificate from the path specified in the config file. Implements a
   * blocking retry mechanism to handle startup timing issues.
   */
  private static X509Certificate loadAgentIdentityCertificate(String configPath)
      throws IOException {
    long startTime = System.currentTimeMillis();
    boolean warned = false;

    while (true) {
      try {
        String certPath = getCertPathFromConfig(configPath);
        if (certPath != null) {
          // Attempt to read the certificate file
          byte[] certBytes = fileIO.readAllBytes(certPath);
          return parseCertificate(certBytes);
        }
      } catch (IOException | GeneralSecurityException e) {
        // Log warning only once on the first failure, but keep retrying until timeout
        if (!warned) {
          LOGGER.log(
              Level.WARNING,
              "Certificate config file or certificate not found/valid at {0} (from {1} environment variable). "
                  + "Retrying for up to {2} seconds. Error: {3}",
              new Object[] {
                configPath, GOOGLE_API_CERTIFICATE_CONFIG, TOTAL_TIMEOUT_MS / 1000, e.getMessage()
              });
          warned = true;
        }
      }

      long elapsedTime = System.currentTimeMillis() - startTime;
      if (elapsedTime >= TOTAL_TIMEOUT_MS) {
        throw new IOException(
            "Certificate config or certificate file not found after multiple retries. "
                + "Token binding protection is failing. You can turn off this protection by setting "
                + GOOGLE_API_PREVENT_AGENT_TOKEN_SHARING_FOR_GCP_SERVICES
                + " to false to fall back to unbound tokens.");
      }

      try {
        long sleepTime =
            (elapsedTime < FAST_POLL_DURATION_MS) ? FAST_POLL_INTERVAL_MS : SLOW_POLL_INTERVAL_MS;
        sleeper.sleep(sleepTime);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new IOException("Interrupted while waiting for certificate config", e);
      }
    }
  }

  @VisibleForTesting
  @SuppressWarnings("unchecked")
  static String getCertPathFromConfig(String configPath) throws IOException {
    try (InputStream stream = new ByteArrayInputStream(fileIO.readAllBytes(configPath))) {
      JsonObjectParser parser = new JsonObjectParser(OAuth2Utils.JSON_FACTORY);
      GenericJson config = parser.parseAndClose(stream, StandardCharsets.UTF_8, GenericJson.class);

      Map<String, Object> certConfigs = (Map<String, Object>) config.get("cert_configs");
      if (certConfigs != null) {
        Map<String, Object> workload = (Map<String, Object>) certConfigs.get("workload");
        if (workload != null) {
          return (String) workload.get("cert_path");
        }
      }
    }
    return null;
  }

  @VisibleForTesting
  static X509Certificate parseCertificate(byte[] certBytes) throws GeneralSecurityException {
    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
    return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certBytes));
  }

  @VisibleForTesting
  static boolean isAgentIdentityCertificate(X509Certificate cert) {
    try {
      Collection<List<?>> sanEntries = cert.getSubjectAlternativeNames();
      if (sanEntries == null) {
        return false;
      }

      for (List<?> entry : sanEntries) {
        // entry matches [type, value]. Type 6 is URI.
        if (entry.size() == 2 && (Integer) entry.get(0) == SAN_URI_TYPE) {
          String uriString = (String) entry.get(1);
          if (uriString.startsWith("spiffe://")) {
            if (matchesAgentIdentityTrustDomain(uriString)) {
              return true;
            }
          }
        }
      }
    } catch (CertificateException | URISyntaxException e) {
      LOGGER.log(Level.FINE, "Error parsing Subject Alternative Name for Agent Identity check", e);
    }
    return false;
  }

  private static boolean matchesAgentIdentityTrustDomain(String spiffeUri)
      throws URISyntaxException {
    URI uri = new URI(spiffeUri);
    String trustDomain = uri.getHost();
    if (trustDomain != null) {
      for (Pattern pattern : AGENT_IDENTITY_SPIFFE_TRUST_DOMAIN_PATTERNS) {
        if (pattern.matcher(trustDomain).matches()) {
          return true;
        }
      }
    }
    return false;
  }

  @VisibleForTesting
  static String calculateCertificateFingerprint(X509Certificate cert) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] hash = digest.digest(cert.getEncoded());
      return BaseEncoding.base64Url().omitPadding().encode(hash);
    } catch (GeneralSecurityException e) {
      throw new RuntimeException("Failed to calculate certificate fingerprint", e);
    }
  }

  // Injectable dependencies for testing
  static class FileIO {
    byte[] readAllBytes(String path) throws IOException {
      return Files.readAllBytes(Paths.get(path));
    }
  }

  static class Environment {
    String get(String name) {
      return System.getenv(name);
    }
  }

  static class Sleeper {
    void sleep(long millis) throws InterruptedException {
      Thread.sleep(millis);
    }
  }

  @VisibleForTesting
  static void setFileIO(FileIO io) {
    fileIO = io;
  }

  @VisibleForTesting
  static void setEnv(Environment e) {
    env = e;
  }

  @VisibleForTesting
  static void setSleeper(Sleeper s) {
    sleeper = s;
  }
}
