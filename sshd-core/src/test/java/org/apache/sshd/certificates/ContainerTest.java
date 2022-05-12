package org.apache.sshd.certificates;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.InspectContainerResponse;
import org.apache.sshd.certificate.OpenSshCertificateBuilder;
import org.apache.sshd.common.config.keys.OpenSshCertificate;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.config.keys.writer.openssh.OpenSSHKeyPairResourceWriter;
import org.apache.sshd.common.keyprovider.FileKeyPairProvider;
import org.apache.sshd.common.util.GenericUtils;
import org.apache.sshd.common.util.io.IoUtils;
import org.apache.sshd.util.test.CommonTestSupportUtils;
import org.apache.sshd.util.test.ContainerTestCase;
import org.junit.Assert;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.startupcheck.OneShotStartupCheckStrategy;
import org.testcontainers.containers.startupcheck.StartupCheckStrategy;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.utility.DockerStatus;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collections;

@Category(ContainerTestCase.class)
public class ContainerTest {



  protected PublicKey readPublicKeyFromResource(String resource) throws Exception {
    try (InputStream clientPublicKeyInputStream
           = Thread.currentThread().getContextClassLoader().getResourceAsStream(resource)) {
      final byte[] clientPublicKeyBytes = IoUtils.toByteArray(clientPublicKeyInputStream);
      final String clientPublicKeyLine
        = GenericUtils.replaceWhitespaceAndTrim(new String(clientPublicKeyBytes, StandardCharsets.UTF_8));
      final PublicKeyEntry clientPublicKeyEntry = PublicKeyEntry.parsePublicKeyEntry(clientPublicKeyLine);
      return clientPublicKeyEntry.resolvePublicKey(null, null, null);
    }
  }


  protected String getClientPublicKeyResource() {
    return getClientPrivateKeyResource() + PublicKeyEntry.PUBKEY_FILE_SUFFIX;
  }

  protected String getClientPrivateKeyResource() {
    return "org/apache/sshd/client/opensshcerts/user/user01_rsa_sha2_256_4096";
  }

  protected String getCAPrivateKeyResource() {
    return "org/apache/sshd/client/opensshcerts/ca/ca_rsa2_256";
  }


  @Test
  public void parseGeneratedCertWithSshKeygen() throws Exception {

    // generate OpenSSH Certificate

    final PublicKey clientPublicKey = readPublicKeyFromResource(getClientPublicKeyResource());

    final String caName = getCAPrivateKeyResource();
    final FileKeyPairProvider keyPairProvider
      = CommonTestSupportUtils.createTestKeyPairProvider(caName);

    final KeyPair caKeypair = keyPairProvider.loadKeys(null).iterator().next();

    String signatureAlgorithm = null;
    int i = caName.indexOf("rsa2_");
    if (i > 0) {
      signatureAlgorithm = "rsa-sha2-" + caName.substring(i + 5);
    }

    final OpenSshCertificate signedCert = OpenSshCertificateBuilder.userCertificate()
      .serial(0L)
      .publicKey(clientPublicKey)
      .id("user01")
      .principals(Collections.singletonList("user01"))
      .extensions(Arrays.asList(
        new OpenSshCertificate.CertificateOption("permit-X11-forwarding"),
        new OpenSshCertificate.CertificateOption("permit-agent-forwarding"),
        new OpenSshCertificate.CertificateOption("permit-port-forwarding"),
        new OpenSshCertificate.CertificateOption("permit-pty"),
        new OpenSshCertificate.CertificateOption("permit-user-rc")))
      .sign(caKeypair, signatureAlgorithm);

    // encode to ssh public key format
    final OpenSSHKeyPairResourceWriter writer = new OpenSSHKeyPairResourceWriter();
    final ByteArrayOutputStream baos = new ByteArrayOutputStream();
    writer.writePublicKey(signedCert, "user01", baos);
    final String encodedCertData = new String(baos.toByteArray(), StandardCharsets.UTF_8);

    //
    // Create a Docker Image + Container which has ssh-keygen available and the OpenSSH certificate in a file at /cert
    //
    // The container will run:
    //
    // ssh-keygen -L -f /path/to/cert
    //
    // and we ssh-keygen to successfully inspect the cert file without error (check exit code is 0)
    //

    // testcontainers will auto reap this container 10s after JVM exit
    GenericContainer<?> container = new GenericContainer<>(
      new ImageFromDockerfile("openssh_ssh-keygen_test4", true)
        .withFileFromClasspath("Dockerfile", "org/apache/sshd/client/opensshcerts/docker_ssh-keygen/Dockerfile")
        .withFileFromString("/cert", encodedCertData)
    )
      .withStartupCheckStrategy(new HasStoppedStartupCheckStrategy())
      .withCommand("ssh-keygen", "-L", "-f", "/cert");
    container.start();

    final Long code = container.getContainerInfo().getState().getExitCodeLong();
    final String logs = container.getLogs();

    Assert.assertEquals(Long.valueOf(0L), code);

  }

  @Test
  public void generateCertWithSshKeygen() {

    GenericContainer<?> container = new GenericContainer<>(
      new ImageFromDockerfile("openssh_ssh-keygen_test", true)
        .withFileFromClasspath("Dockerfile", "org/apache/sshd/client/opensshcerts/docker_ssh-keygen/Dockerfile")
    )
      .withStartupCheckStrategy(new HasStoppedStartupCheckStrategy())
      .withCommand("ssh-keygen", "-t", "rsa", "-b", "2048", "-f", "/root/.ssh/id_rsa", "-N", "\"\"");
    container.start();

    final Long code = container.getContainerInfo().getState().getExitCodeLong();
    final String logs = container.getLogs();

    final String privateKey = container.copyFileFromContainer("/root/.ssh/id_rsa", (stream) -> {
      final byte[] bytes = IoUtils.toByteArray(stream);
      final String str = new String(bytes, StandardCharsets.UTF_8);
      return str;
    });

    Assert.assertEquals(Long.valueOf(0L), code);

  }

  /**
   * Like {@link OneShotStartupCheckStrategy}, except it doesn't assert the exit code value.
   *
   * This is useful to write unit tests which manages the full container lifecycle without throwing an exception
   * while container exit is waited on
   */
  public static class HasStoppedStartupCheckStrategy extends StartupCheckStrategy {

    @Override
    public StartupStatus checkStartupState(DockerClient dockerClient, String containerId) {
      InspectContainerResponse.ContainerState state = getCurrentState(dockerClient, containerId);

      if (!DockerStatus.isContainerStopped(state)) {
        return StartupStatus.NOT_YET_KNOWN;
      }

      if (DockerStatus.isContainerStopped(state)) {
        return StartupStatus.SUCCESSFUL;
      } else {
        return StartupStatus.FAILED;
      }
    }
  }

}
