package xyz.docbleach.module.rtf;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import xyz.docbleach.api.BleachSession;
import xyz.docbleach.api.bleach.CompositeBleach;
import xyz.docbleach.api.budget.ResourceBudget;
import xyz.docbleach.api.budget.ResourceBudgetExceededException;
import xyz.docbleach.api.threat.ThreatType;

class RTFBleachBudgetTest {

  private static final byte[] RTF_HEADER = "{\\rtf1".getBytes(StandardCharsets.UTF_8);

  private static BleachSession session(ResourceBudget budget) {
    return new BleachSession(new CompositeBleach(new RTFBleach()), budget);
  }

  @Test
  void safeRtfIsSanitizedWithoutRegression() throws Exception {
    byte[] input = "{\\rtf1 plain text}".getBytes(StandardCharsets.UTF_8);
    java.util.List<xyz.docbleach.api.threat.Threat> threats = new java.util.ArrayList<>();
    BleachSession session =
        session(
            new ResourceBudget(
                ResourceBudget.DEFAULT_MAX_BYTES,
                ResourceBudget.DEFAULT_MAX_ENTRIES,
                ResourceBudget.DEFAULT_MAX_DEPTH,
                ResourceBudget.DEFAULT_TIME_LIMIT_MILLIS,
                threats::add));
    ByteArrayOutputStream output = new ByteArrayOutputStream();

    session.sanitize(new ByteArrayInputStream(input), output);

    assertArrayEquals(input, output.toByteArray());
    assertTrue(
        threats.stream().noneMatch(threat -> threat.type() == ThreatType.RESOURCE_LIMIT));
  }

  @Test
  void rtfLargerThanByteBudgetFailsSafelyAndRecordsTheLayer() {
    byte[] body = new byte[4096];
    java.util.Arrays.fill(body, (byte) 'a');
    byte[] input = concat(RTF_HEADER, body);
    java.util.List<xyz.docbleach.api.threat.Threat> threats = new java.util.ArrayList<>();
    ResourceBudget budget =
        new ResourceBudget(
            128,
            ResourceBudget.DEFAULT_MAX_ENTRIES,
            ResourceBudget.DEFAULT_MAX_DEPTH,
            ResourceBudget.DEFAULT_TIME_LIMIT_MILLIS,
            threats::add);
    BleachSession session = session(budget);

    ResourceBudgetExceededException exception =
        assertThrows(
            ResourceBudgetExceededException.class,
            () ->
                session.sanitize(
                    new ByteArrayInputStream(input), new ByteArrayOutputStream()));

    assertEquals(ResourceBudget.Limit.TOTAL_BYTES, exception.getLimit());
    assertTrue(exception.getLocation().contains("rtf"), exception.getLocation());
    assertEquals(
        1,
        threats.stream()
            .filter(threat -> threat.type() == ThreatType.RESOURCE_LIMIT)
            .count());
  }

  private static byte[] concat(byte[] first, byte[] second) {
    byte[] result = new byte[first.length + second.length];
    System.arraycopy(first, 0, result, 0, first.length);
    System.arraycopy(second, 0, result, first.length, second.length);
    return result;
  }
}
