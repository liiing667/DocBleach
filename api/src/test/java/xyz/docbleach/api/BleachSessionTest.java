package xyz.docbleach.api;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import org.junit.jupiter.api.Test;
import xyz.docbleach.api.bleach.Bleach;
import xyz.docbleach.api.bleach.CompositeBleach;
import xyz.docbleach.api.exception.BleachException;
import xyz.docbleach.api.exception.RecursionBleachException;
import xyz.docbleach.api.threat.Threat;
import xyz.docbleach.api.threat.ThreatAction;
import xyz.docbleach.api.threat.ThreatSeverity;
import xyz.docbleach.api.threat.ThreatType;
import xyz.docbleach.api.util.StreamUtils;

/**
 * Compatibility group: legitimate documents and the existing sanitation behavior must keep
 * working with the session-scoped resources, cancellation and retry support.
 */
class BleachSessionTest {

  private static final byte[] LEGITIMATE_CONTENT =
      "A perfectly legitimate document, with forms and links.".getBytes(StandardCharsets.UTF_8);

  private static ByteArrayInputStream legitimateStream() {
    return new ByteArrayInputStream(LEGITIMATE_CONTENT);
  }

  @Test
  void unhandledContentIsLeftUntouched() throws BleachException {
    BleachSession session = new BleachSession(new CopyBleach(false));
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    session.sanitize(legitimateStream(), out);

    assertEquals(0, out.size(), "A bleach that does not handle the file must not write anything");
    assertEquals(0, session.threatCount());
  }

  @Test
  void compositeBleachCopiesUnhandledContentUnchanged() throws BleachException {
    BleachSession session = new BleachSession(new CopyBleach(false));
    CompositeBleach composite = new CompositeBleach(new CopyBleach(false));
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    composite.sanitize(legitimateStream(), out, session);

    assertArrayEquals(LEGITIMATE_CONTENT, out.toByteArray());
    assertEquals(0, session.threatCount());
  }

  @Test
  void handledContentKeepsExistingSanitizeOutput() throws BleachException {
    BleachSession session = new BleachSession(new CopyBleach(true));
    ByteArrayOutputStream out = new ByteArrayOutputStream();

    session.sanitize(legitimateStream(), out);

    assertArrayEquals(LEGITIMATE_CONTENT, out.toByteArray());
  }

  @Test
  void threatsAreRecordedAndAttributedToTheirOwnSession() throws BleachException {
    Threat threat =
        Threat.builder()
            .type(ThreatType.ACTIVE_CONTENT)
            .severity(ThreatSeverity.HIGH)
            .action(ThreatAction.REMOVE)
            .location("test")
            .details("test")
            .build();
    BleachSession first = new BleachSession(new ThreatRecordingBleach(threat));
    BleachSession second = new BleachSession(new ThreatRecordingBleach(null));

    first.sanitize(legitimateStream(), new ByteArrayOutputStream());
    second.sanitize(legitimateStream(), new ByteArrayOutputStream());

    assertEquals(1, first.threatCount());
    assertTrue(first.getThreats().contains(threat));
    assertEquals(0, second.threatCount(), "Evidence must not leak into another session");
  }

  @Test
  void sanitizeCanBeRetriedAfterAFailure() throws BleachException {
    FlakyBleach bleach = new FlakyBleach();
    BleachSession session = new BleachSession(bleach);

    assertThrows(
        BleachException.class,
        () -> session.sanitize(legitimateStream(), new ByteArrayOutputStream()));

    ByteArrayOutputStream retriedOutput = new ByteArrayOutputStream();
    session.sanitize(legitimateStream(), retriedOutput);

    assertArrayEquals(LEGITIMATE_CONTENT, retriedOutput.toByteArray());
    assertEquals(2, bleach.attempts, "The retry must go through the bleach again");
  }

  @Test
  void temporaryFilesAreUsableWithinTheirSession() throws BleachException, IOException {
    BleachSession session = new BleachSession(new CopyBleach(true));

    File tempFile = session.createTempFile("attachment", ".bin");
    Files.write(tempFile.toPath(), LEGITIMATE_CONTENT);

    assertEquals(session.getTemporaryDirectory(), tempFile.getParentFile().toPath());
    assertArrayEquals(LEGITIMATE_CONTENT, Files.readAllBytes(tempFile.toPath()));

    session.close();
  }

  @Test
  void recursionGuardStillWorks() {
    BleachSession session = new BleachSession(new RecursingBleach());

    assertThrows(
        RecursionBleachException.class,
        () -> session.sanitize(legitimateStream(), new ByteArrayOutputStream()));
  }

  private static class CopyBleach implements Bleach {

    private final boolean handles;

    CopyBleach(boolean handles) {
      this.handles = handles;
    }

    @Override
    public boolean handlesMagic(InputStream stream) {
      return handles;
    }

    @Override
    public String getName() {
      return "Copy Bleach";
    }

    @Override
    public void sanitize(InputStream inputStream, OutputStream outputStream, BleachSession session)
        throws BleachException {
      try {
        StreamUtils.copy(inputStream, outputStream);
      } catch (IOException e) {
        throw new BleachException(e);
      }
    }
  }

  private static class ThreatRecordingBleach extends CopyBleach {

    private final Threat threat;

    ThreatRecordingBleach(Threat threat) {
      super(true);
      this.threat = threat;
    }

    @Override
    public void sanitize(InputStream inputStream, OutputStream outputStream, BleachSession session)
        throws BleachException {
      if (threat != null) {
        session.recordThreat(threat);
      }
      super.sanitize(inputStream, outputStream, session);
    }
  }

  private static class FlakyBleach extends CopyBleach {

    private int attempts = 0;

    FlakyBleach() {
      super(true);
    }

    @Override
    public void sanitize(InputStream inputStream, OutputStream outputStream, BleachSession session)
        throws BleachException {
      attempts++;
      if (attempts == 1) {
        throw new BleachException("Transient failure");
      }
      super.sanitize(inputStream, outputStream, session);
    }
  }

  private static class RecursingBleach extends CopyBleach {

    RecursingBleach() {
      super(true);
    }

    @Override
    public void sanitize(InputStream inputStream, OutputStream outputStream, BleachSession session)
        throws BleachException {
      session.sanitize(inputStream, outputStream);
    }
  }
}
