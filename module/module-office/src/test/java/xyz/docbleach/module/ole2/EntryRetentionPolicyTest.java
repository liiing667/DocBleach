package xyz.docbleach.module.ole2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Collections;
import java.util.concurrent.atomic.AtomicInteger;
import org.apache.poi.poifs.filesystem.DirectoryEntry;
import org.apache.poi.poifs.filesystem.Entry;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import xyz.docbleach.api.BleachSession;
import xyz.docbleach.api.BleachTestBase;

class EntryRetentionPolicyTest {

  private BleachSession session;

  @BeforeEach
  void setUp() {
    session = mock(BleachSession.class);
  }

  @Test
  void sharesVerdictsAcrossRemovalPaths() throws IOException {
    POIFSFileSystem fs = new POIFSFileSystem();
    DirectoryEntry root = fs.getRoot();
    DirectoryEntry vba = root.createDirectory("VBA");
    vba.createDocument("Project", new ByteArrayInputStream(new byte[]{1}));
    root.createDocument("\u0001CompObj", new ByteArrayInputStream(new byte[]{1}));
    root.createDocument("WordDocument", new ByteArrayInputStream(new byte[]{1}));

    EntryRetentionPolicy policy = new EntryRetentionPolicy(session);

    // Macros and objects are rejected by the same policy
    Entry vbaEntry = root.getEntry("VBA");
    assertFalse(policy.isKept(vbaEntry), "The VBA storage is removed");
    assertTrue(policy.wasRemoved("VBA"));

    Entry compObj = root.getEntry("\u0001CompObj");
    assertFalse(policy.isKept(compObj), "The CompObj document is removed");
    assertTrue(policy.wasRemoved("\u0001CompObj"));

    Entry wordDocument = root.getEntry("WordDocument");
    assertTrue(policy.isKept(wordDocument), "Regular entries are kept");
    assertFalse(policy.wasRemoved("WordDocument"));

    BleachTestBase.assertThreatsFound(session, 2);

    // A nested entry of a removed storage is unreachable, a kept entry stays reachable
    Entry nested = ((DirectoryEntry) vbaEntry).getEntry("Project");
    assertFalse(policy.isReachable(nested), "Children of removed storages are unreachable");
    assertTrue(policy.isReachable(wordDocument), "Kept entries remain reachable");
  }

  @Test
  void computesVerdictsOnlyOnce() {
    AtomicInteger evaluations = new AtomicInteger();
    EntryFilter countingFilter =
        new EntryFilter(session) {
          @Override
          public boolean test(Entry entry) {
            evaluations.incrementAndGet();
            return true;
          }
        };
    EntryRetentionPolicy policy =
        new EntryRetentionPolicy(Collections.singletonList(countingFilter));

    Entry entry = mock(Entry.class);
    assertTrue(policy.isKept(entry));
    assertTrue(policy.isKept(entry));
    assertTrue(policy.isReachable(entry));

    assertEquals(1, evaluations.get(), "The verdict is computed once and then shared");
  }
}
