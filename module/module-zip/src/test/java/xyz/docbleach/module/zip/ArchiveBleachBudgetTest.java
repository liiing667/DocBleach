package xyz.docbleach.module.zip;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.Test;
import xyz.docbleach.api.BleachSession;
import xyz.docbleach.api.bleach.CompositeBleach;
import xyz.docbleach.api.budget.ResourceBudget;
import xyz.docbleach.api.budget.ResourceBudgetExceededException;
import xyz.docbleach.api.threat.ThreatType;

class ArchiveBleachBudgetTest {

  private static BleachSession sessionWithBudget(ResourceBudget budget) {
    ArchiveBleach archiveBleach = new ArchiveBleach();
    return new BleachSession(new CompositeBleach(archiveBleach), budget);
  }

  private static byte[] zipWithEntry(String name, byte[] content) throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (ZipOutputStream zip = new ZipOutputStream(baos)) {
      zip.putNextEntry(new ZipEntry(name));
      zip.write(content);
      zip.closeEntry();
    }
    return baos.toByteArray();
  }

  private static byte[] nestedZip(int levels, byte[] leafContent) throws IOException {
    byte[] current = leafContent;
    for (int level = levels; level > 0; level--) {
      current = zipWithEntry("nested-" + level + ".zip", current);
    }
    return current;
  }

  private static byte[] readSingleEntry(byte[] zip) throws IOException {
    try (ZipInputStream zipIn = new ZipInputStream(new ByteArrayInputStream(zip))) {
      ZipEntry entry = zipIn.getNextEntry();
      ByteArrayOutputStream content = new ByteArrayOutputStream();
      byte[] buffer = new byte[1024];
      int read;
      while ((read = zipIn.read(buffer)) != -1) {
        content.write(buffer, 0, read);
      }
      return content.toByteArray();
    }
  }

  @Test
  void safeSmallArchiveIsSanitizedWithoutRegression() throws Exception {
    BleachSession session = sessionWithBudget(new ResourceBudget());
    byte[] input = zipWithEntry("safe.txt", "hello world".getBytes());
    ByteArrayOutputStream output = new ByteArrayOutputStream();

    session.sanitize(new ByteArrayInputStream(input), output);

    assertArrayEquals("hello world".getBytes(), readSingleEntry(output.toByteArray()));
    assertTrue(
        session.getThreats().stream().noneMatch(threat -> threat.type() == ThreatType.RESOURCE_LIMIT),
        "a legit archive must not trip the resource budget");
  }

  @Test
  void compressionBombTripsTheChainWideByteBudget() throws Exception {
    // A highly compressible payload: a few KB of zeros inflate past a tiny byte budget.
    byte[] bombPayload = new byte[64 * 1024];
    byte[] input = zipWithEntry("bomb.bin", bombPayload);
    java.util.List<xyz.docbleach.api.threat.Threat> threats = new java.util.ArrayList<>();
    ResourceBudget budget =
        new ResourceBudget(1024, 10_000, 10, 60_000L, threats::add);
    BleachSession session = sessionWithBudget(budget);

    ResourceBudgetExceededException exception =
        assertThrows(
            ResourceBudgetExceededException.class,
            () ->
                session.sanitize(
                    new ByteArrayInputStream(input), new ByteArrayOutputStream()));

    assertEquals(ResourceBudget.Limit.TOTAL_BYTES, exception.getLimit());
    assertTrue(exception.getLocation().contains("zip-entry:bomb.bin"), exception.getLocation());
    assertEquals(
        1,
        threats.stream()
            .filter(threat -> threat.type() == ThreatType.RESOURCE_LIMIT)
            .count());
  }

  @Test
  void deeplyNestedArchivesTripTheDepthBudget() throws Exception {
    byte[] input = nestedZip(12, "leaf".getBytes());
    java.util.List<xyz.docbleach.api.threat.Threat> threats = new java.util.ArrayList<>();
    ResourceBudget budget =
        new ResourceBudget(
            ResourceBudget.DEFAULT_MAX_BYTES,
            ResourceBudget.DEFAULT_MAX_ENTRIES,
            ResourceBudget.DEFAULT_MAX_DEPTH,
            ResourceBudget.DEFAULT_TIME_LIMIT_MILLIS,
            threats::add);
    BleachSession session = sessionWithBudget(budget);

    ResourceBudgetExceededException exception =
        assertThrows(
            ResourceBudgetExceededException.class,
            () ->
                session.sanitize(
                    new ByteArrayInputStream(input), new ByteArrayOutputStream()));

    assertEquals(ResourceBudget.Limit.DEPTH, exception.getLimit());
    assertTrue(exception.getLocation().contains("nested-"), exception.getLocation());
    assertEquals(
        1,
        threats.stream()
            .filter(threat -> threat.type() == ThreatType.RESOURCE_LIMIT)
            .count());
    assertEquals(0, budget.getDepth(), "the layer stack must be restored after the failure");
  }
}
