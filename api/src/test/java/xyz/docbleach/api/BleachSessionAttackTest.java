package xyz.docbleach.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.PosixFileAttributeView;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import xyz.docbleach.api.bleach.Bleach;
import xyz.docbleach.api.exception.BleachException;
import xyz.docbleach.api.exception.SessionCancelledException;

/**
 * Attack group: a tenant cancelling its session must not leave plaintext attachments behind,
 * and a cancelled session must never be revived by retries or read by subsequent sessions.
 */
class BleachSessionAttackTest {

  private static final byte[] TENANT_SECRET =
      "previous tenant plaintext attachment".getBytes(StandardCharsets.UTF_8);

  private static final Bleach NOOP_BLEACH =
      new Bleach() {
        @Override
        public boolean handlesMagic(InputStream stream) {
          return true;
        }

        @Override
        public String getName() {
          return "No-op Bleach";
        }

        @Override
        public void sanitize(
            InputStream inputStream, OutputStream outputStream, BleachSession session) {
          // Nothing to do
        }
      };

  @Test
  void cancelDestroysPlaintextAttachments() throws Exception {
    BleachSession session = new BleachSession(NOOP_BLEACH);
    Path sessionDir = session.getTemporaryDirectory();
    File attachment = session.createTempFile("attachment", ".bin");
    Files.write(attachment.toPath(), TENANT_SECRET);

    session.cancel();

    assertFalse(attachment.exists(), "Plaintext attachment must be destroyed on cancel");
    assertFalse(Files.exists(sessionDir), "The session's temporary directory must be destroyed");
  }

  @Test
  void cancelledSessionCannotBeReusedOrRetried() throws Exception {
    BleachSession session = new BleachSession(NOOP_BLEACH);
    Path sessionDir = session.getTemporaryDirectory();
    session.cancel();

    assertTrue(session.isCancelled());
    assertThrows(
        SessionCancelledException.class,
        () -> session.sanitize(new ByteArrayInputStream(TENANT_SECRET), new ByteArrayOutputStream()));
    assertThrows(SessionCancelledException.class, session::getTemporaryDirectory);
    assertThrows(SessionCancelledException.class, () -> session.createTempFile("retry", ".bin"));
    assertFalse(Files.exists(sessionDir), "Retries must not resurrect the session's resources");
  }

  @Test
  void cancelIsTerminalAndIdempotent() throws Exception {
    BleachSession session = new BleachSession(NOOP_BLEACH);
    Path sessionDir = session.getTemporaryDirectory();

    session.cancel();
    session.cancel();
    session.close();

    assertTrue(session.isCancelled());
    assertFalse(Files.exists(sessionDir));
  }

  @Test
  void subsequentSessionCannotReadPreviousTenantFiles() throws Exception {
    BleachSession previousTenant = new BleachSession(NOOP_BLEACH);
    Path previousDir = previousTenant.getTemporaryDirectory();
    File previousAttachment = previousTenant.createTempFile("attachment", ".bin");
    Files.write(previousAttachment.toPath(), TENANT_SECRET);

    // The attacker cancels the previous tenant's session
    previousTenant.cancel();

    BleachSession nextTenant = new BleachSession(NOOP_BLEACH);
    Path nextDir = nextTenant.getTemporaryDirectory();

    assertNotEquals(previousDir, nextDir, "Each session must own an exclusive directory");
    assertFalse(Files.exists(previousDir), "The cancelled tenant's directory must be gone");
    assertFalse(previousAttachment.exists(), "The previous tenant's plaintext must be unreadable");
    try (java.util.stream.Stream<Path> entries = Files.list(nextDir)) {
      assertEquals(0, entries.count(), "The next session starts with a clean directory");
    }

    nextTenant.close();
  }

  @Test
  void temporaryResourcesAreOwnerOnly() throws Exception {
    BleachSession session = new BleachSession(NOOP_BLEACH);
    Path sessionDir = session.getTemporaryDirectory();
    assumeTrue(
        Files.getFileAttributeView(sessionDir, PosixFileAttributeView.class) != null,
        "POSIX permissions are not supported on this filesystem");

    Set<PosixFilePermission> dirPermissions = Files.getPosixFilePermissions(sessionDir);
    assertEquals(
        PosixFilePermissions.fromString("rwx------"),
        dirPermissions,
        "The session directory must not be readable by other tenants");

    File attachment = session.createTempFile("attachment", ".bin");
    Set<PosixFilePermission> filePermissions =
        Files.getPosixFilePermissions(attachment.toPath());
    assertEquals(
        PosixFilePermissions.fromString("rw-------"),
        filePermissions,
        "Session temporary files must not be readable by other tenants");

    session.close();
  }

  @Test
  void cancelIsAtomicAgainstConcurrentResourceCreation() throws Exception {
    BleachSession session = new BleachSession(NOOP_BLEACH);
    Path sessionDir = session.getTemporaryDirectory();
    CountDownLatch ready = new CountDownLatch(1);
    List<Thread> workers = new ArrayList<>();

    for (int i = 0; i < 4; i++) {
      Thread worker =
          new Thread(
              () -> {
                try {
                  ready.await();
                  while (!session.isCancelled()) {
                    session.createTempFile("attachment", ".bin");
                  }
                } catch (SessionCancelledException expected) {
                  // Cancellation won: the worker can no longer create resources
                } catch (Exception e) {
                  throw new AssertionError(e);
                }
              });
      workers.add(worker);
      worker.start();
    }

    ready.countDown();
    Thread.sleep(50);
    session.cancel();

    for (Thread worker : workers) {
      worker.join(TimeUnit.SECONDS.toMillis(10));
    }

    assertFalse(Files.exists(sessionDir), "Cleanup must be atomic: no file may survive cancel");
    assertThrows(SessionCancelledException.class, () -> session.createTempFile("late", ".bin"));
    assertFalse(Files.exists(sessionDir), "Late retries must not resurrect the directory");
  }
}
