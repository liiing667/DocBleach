package xyz.docbleach.module.ole2;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Iterator;
import org.apache.poi.hpsf.ClassID;
import org.apache.poi.poifs.filesystem.DirectoryEntry;
import org.apache.poi.poifs.filesystem.DocumentEntry;
import org.apache.poi.poifs.filesystem.DocumentInputStream;
import org.apache.poi.poifs.filesystem.Entry;
import org.apache.poi.poifs.filesystem.FileMagic;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import xyz.docbleach.api.BleachSession;
import xyz.docbleach.api.bleach.Bleach;
import xyz.docbleach.api.exception.BleachException;
import xyz.docbleach.module.ole2.Ole2BleachException.Category;

/**
 * Sanitizes an OLE2 file (.doc, .xls, .ppt) by copying its elements into a new OLE2 container.
 * Information to be modified (template, ...) are changed on the fly, and entries to be removed are
 * just not copied over. The retention decisions are centralized in a single {@link
 * EntryRetentionPolicy}, shared by every removal path, and any failure aborts the sanitation with
 * a classified exception before anything is written to the output stream.
 */
public class OLE2Bleach implements Bleach {

  private static final Logger LOGGER = LoggerFactory.getLogger(OLE2Bleach.class);

  @Override
  public boolean handlesMagic(InputStream stream) {
    try {
      return stream.available() > 4 && FileMagic.valueOf(stream) == FileMagic.OLE2;
    } catch (Exception e) {
      LOGGER.warn("An exception occured", e);
      return false;
    }
  }

  @Override
  public String getName() {
    return "OLE2 Bleach";
  }

  @Override
  public void sanitize(InputStream inputStream, OutputStream outputStream, BleachSession session)
      throws BleachException {
    try (POIFSFileSystem fsIn = openInput(inputStream);
        POIFSFileSystem fs = new POIFSFileSystem()) {
      // @TODO: Filter based on Storage Class ID - see issue #23
      EntryRetentionPolicy policy = new EntryRetentionPolicy(session);
      sanitize(session, policy, fsIn, fs);

      // The sanitized file is built in memory first: if anything fails, a classified exception
      // is thrown and no partial output is left behind.
      ByteArrayOutputStream buffer = new ByteArrayOutputStream();
      writeSanitizedFilesystem(fs, buffer, policy);
      buffer.writeTo(outputStream);
    } catch (IOException | IndexOutOfBoundsException e) {
      throw new Ole2BleachException(Category.INPUT_READ, e);
    }
  }

  private POIFSFileSystem openInput(InputStream inputStream) throws Ole2BleachException {
    try {
      return new POIFSFileSystem(inputStream);
    } catch (IOException | RuntimeException e) {
      throw new Ole2BleachException(Category.INPUT_READ, e);
    }
  }

  private void writeSanitizedFilesystem(
      POIFSFileSystem fs, OutputStream out, EntryRetentionPolicy policy)
      throws Ole2BleachException {
    if (ClassID.EXCEL97.equals(fs.getRoot().getStorageClsid())) {
      try {
        ExcelRecordCleaner.cleanupAndSaveExcel97(fs, out, policy);
      } catch (IOException | RuntimeException e) {
        throw new Ole2BleachException(Category.RECORD_CLEANUP, e);
      }
      return;
    }

    try {
      fs.writeFilesystem(out);
    } catch (IOException | RuntimeException e) {
      throw new Ole2BleachException(Category.OUTPUT_WRITE, e);
    }
  }

  protected void sanitize(
      BleachSession session, EntryRetentionPolicy policy, POIFSFileSystem fsIn, POIFSFileSystem fs)
      throws Ole2BleachException {
    DirectoryEntry rootIn = fsIn.getRoot();
    DirectoryEntry rootOut = fs.getRoot();

    // https://blogs.msdn.microsoft.com/heaths/2006/02/27/identifying-windows-installer-file-types/
    rootOut.setStorageClsid(rootIn.getStorageClsid());

    sanitize(session, policy, rootIn, rootOut);
  }

  protected void sanitize(
      BleachSession session,
      EntryRetentionPolicy policy,
      DirectoryEntry rootIn,
      DirectoryEntry rootOut)
      throws Ole2BleachException {
    LOGGER.debug("Entries before: {}", rootIn.getEntryNames());

    Iterator<Entry> entries = rootIn.getEntries();
    while (entries.hasNext()) {
      Entry entry = entries.next();
      if (!policy.isKept(entry)) {
        continue;
      }
      copyNodesRecursively(session, policy, entry, rootOut);
    }
    LOGGER.debug("Entries after: {}", rootOut.getEntryNames());
  }

  protected void copyNodesRecursively(
      BleachSession session, EntryRetentionPolicy policy, Entry entry, DirectoryEntry target)
      throws Ole2BleachException {
    LOGGER.trace("copyNodesRecursively: {}, parent: {}", entry.getName(), entry.getParent());
    if (!entry.isDirectoryEntry()) {
      DocumentEntry dentry = (DocumentEntry) entry;
      try (DocumentInputStream dstream = new DocumentInputStream(dentry)) {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        session.sanitize(dstream, os);
        ByteArrayInputStream bais = new ByteArrayInputStream(os.toByteArray());
        target.createDocument(dentry.getName(), bais);
      } catch (BleachException e) {
        throw new Ole2BleachException(
            Category.CONTENT_SANITIZE, "Failed to sanitize the entry " + entry.getName(), e);
      } catch (IOException e) {
        throw new Ole2BleachException(
            Category.ENTRY_COPY, "Failed to copy the entry " + entry.getName(), e);
      }
      return;
    }

    DirectoryEntry dirEntry = (DirectoryEntry) entry;
    try {
      DirectoryEntry newTarget = target.createDirectory(entry.getName());
      newTarget.setStorageClsid(dirEntry.getStorageClsid());
      sanitize(session, policy, dirEntry, newTarget);
    } catch (IOException e) {
      throw new Ole2BleachException(
          Category.ENTRY_COPY, "Failed to copy the storage " + entry.getName(), e);
    }
  }
}
