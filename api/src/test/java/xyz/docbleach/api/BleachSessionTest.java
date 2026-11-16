package xyz.docbleach.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import org.junit.jupiter.api.Test;
import xyz.docbleach.api.bleach.CompositeBleach;

class BleachSessionTest {

  @Test
  void temporaryResourcesArePrivateAndCleanedUpOnClose() throws Exception {
    BleachSession session = new BleachSession(new CompositeBleach());

    Path tempDirectory = session.getTempDirectory();
    assertTrue(Files.isDirectory(tempDirectory));
    assertTrue(tempDirectory.getFileName().toString().startsWith("docbleach-session-"));

    Path tempFile = session.createTempFile("docbleach-test-", ".bin");
    Files.write(tempFile, "sensitive content".getBytes(StandardCharsets.UTF_8));
    assertEquals(tempDirectory, tempFile.getParent());

    if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
      assertEquals(
          PosixFilePermissions.fromString("rwx------"),
          Files.getPosixFilePermissions(tempDirectory));
      assertEquals(
          PosixFilePermissions.fromString("rw-------"),
          Files.getPosixFilePermissions(tempFile));
    }

    session.close();
    assertFalse(Files.exists(tempFile));
    assertFalse(Files.exists(tempDirectory));

    // Closing an already closed session is a no-op
    session.close();
  }

  @Test
  void eachSessionHasItsOwnTemporaryDirectory() throws Exception {
    try (BleachSession first = new BleachSession(new CompositeBleach());
        BleachSession second = new BleachSession(new CompositeBleach())) {
      assertFalse(first.getTempDirectory().equals(second.getTempDirectory()));
      assertFalse(
          first.createTempFile("docbleach-test-", ".bin")
              .equals(second.createTempFile("docbleach-test-", ".bin")));
    }
  }
}
