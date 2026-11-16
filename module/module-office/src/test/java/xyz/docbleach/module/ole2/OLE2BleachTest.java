package xyz.docbleach.module.ole2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import org.apache.poi.poifs.filesystem.DirectoryEntry;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import xyz.docbleach.api.BleachSession;
import xyz.docbleach.api.BleachTestBase;
import xyz.docbleach.api.exception.BleachException;
import xyz.docbleach.module.ole2.Ole2BleachException.Category;

class OLE2BleachTest extends BleachTestBase {

  private OLE2Bleach instance;

  @BeforeEach
  void setUp() {
    instance = spy(new OLE2Bleach());
  }

  @Test
  void handlesMagic() throws IOException {
    Charset charset = Charset.defaultCharset();
    // Check that empty does not trigger an error
    InputStream invalidInputStream = new ByteArrayInputStream("".getBytes(charset));
    assertFalse(instance.handlesMagic(invalidInputStream));

    // Check that this bleach is sane
    invalidInputStream = new ByteArrayInputStream("Anything".getBytes(charset));
    assertFalse(instance.handlesMagic(invalidInputStream));
  }

  @Test
  void removesThreatsAndKeepsReachableEntries() throws Exception {
    ByteArrayOutputStream input = new ByteArrayOutputStream();
    try (POIFSFileSystem fs = new POIFSFileSystem()) {
      DirectoryEntry root = fs.getRoot();
      DirectoryEntry vba = root.createDirectory("VBA");
      vba.createDocument("dir", new ByteArrayInputStream(new byte[]{1}));
      root.createDirectory("ObjectPool");
      root.createDocument("WordDocument", new ByteArrayInputStream(new byte[]{1, 2, 3, 4, 5}));
      DirectoryEntry keep = root.createDirectory("Keep");
      keep.createDocument("inner", new ByteArrayInputStream(new byte[]{9}));
      fs.writeFilesystem(input);
    }

    BleachSession session = new BleachSession(instance);
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    instance.sanitize(new ByteArrayInputStream(input.toByteArray()), output, session);

    assertTrue(output.size() > 0, "A sanitized file is produced");
    try (POIFSFileSystem cleaned =
        new POIFSFileSystem(new ByteArrayInputStream(output.toByteArray()))) {
      DirectoryEntry root = cleaned.getRoot();
      assertFalse(root.hasEntry("VBA"), "Macro storages are removed");
      assertFalse(root.hasEntry("ObjectPool"), "Object pools are removed");
      assertTrue(root.hasEntry("WordDocument"), "Regular documents are kept");
      assertTrue(root.hasEntry("Keep"), "Regular storages are kept");
      assertTrue(
          ((DirectoryEntry) root.getEntry("Keep")).hasEntry("inner"),
          "Nested reachable entries are kept");
    }
    assertEquals(2, session.threatCount(), "The VBA storage and the ObjectPool were removed");
  }

  @Test
  void throwsClassifiedExceptionOnCorruptInput() {
    // OLE2 magic, but the file is truncated: it cannot be read as an OLE2 container
    byte[] truncated = new byte[100];
    System.arraycopy(
        new byte[]{(byte) 0xD0, (byte) 0xCF, 0x11, (byte) 0xE0, (byte) 0xA1, (byte) 0xB1, 0x1A,
            (byte) 0xE1},
        0,
        truncated,
        0,
        8);

    BleachSession session = mock(BleachSession.class);
    ByteArrayOutputStream output = new ByteArrayOutputStream();

    Ole2BleachException exception =
        assertThrows(
            Ole2BleachException.class,
            () -> instance.sanitize(new ByteArrayInputStream(truncated), output, session));
    assertEquals(Category.INPUT_READ, exception.getCategory());
    assertEquals(0, output.size(), "No partial output is left behind");
  }

  @Test
  void throwsClassifiedExceptionOnNestedSanitizeFailure() throws Exception {
    ByteArrayOutputStream input = new ByteArrayOutputStream();
    try (POIFSFileSystem fs = new POIFSFileSystem()) {
      fs.getRoot()
          .createDocument("WordDocument", new ByteArrayInputStream(new byte[]{1, 2, 3, 4, 5}));
      fs.writeFilesystem(input);
    }

    BleachSession session = mock(BleachSession.class);
    doThrow(new BleachException("boom"))
        .when(session)
        .sanitize(any(InputStream.class), any(OutputStream.class));
    ByteArrayOutputStream output = new ByteArrayOutputStream();

    Ole2BleachException exception =
        assertThrows(
            Ole2BleachException.class,
            () ->
                instance.sanitize(
                    new ByteArrayInputStream(input.toByteArray()), output, session));
    assertEquals(Category.CONTENT_SANITIZE, exception.getCategory());
    assertEquals(0, output.size(), "No partial output is left behind");
  }
}
