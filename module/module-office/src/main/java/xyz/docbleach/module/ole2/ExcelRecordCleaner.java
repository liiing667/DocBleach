package xyz.docbleach.module.ole2;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Collection;
import java.util.HashSet;
import org.apache.poi.hssf.model.InternalWorkbook;
import org.apache.poi.hssf.record.Record;
import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.poifs.filesystem.POIFSFileSystem;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.ss.usermodel.WorkbookFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ExcelRecordCleaner {

  private static final Logger LOGGER = LoggerFactory.getLogger(ExcelRecordCleaner.class);
  /**
   * ObProj's record SID. From Microsoft's documentation: > The existence of the ObProj record
   * specifies that there is a VBA project in the file. > This project is located in the VBA storage
   * stream.
   */
  private static final short OB_PROJ_SID = 0xD3;

  /**
   * Removes the records pointing to storages that the retention policy removed (eg. the ObProj
   * record, which references the VBA storage), then writes the workbook. The policy is the single
   * source of truth: a record is only dropped when its target is no longer part of the sanitized
   * file.
   */
  protected static void cleanupAndSaveExcel97(
      POIFSFileSystem fs, OutputStream outputStream, EntryRetentionPolicy policy)
      throws IOException {
    Workbook wb = WorkbookFactory.create(fs);

    if (wb instanceof HSSFWorkbook) {
      HSSFWorkbook hwb = (HSSFWorkbook) wb;
      InternalWorkbook internal = hwb.getInternalWorkbook();
      if (internal != null && isVbaStorageRemoved(fs, policy)) {
        LOGGER.trace("# of Records: {}", internal.getNumRecords());
        removeObProjRecord(internal.getRecords());
        LOGGER.trace("# of Records: {}", internal.getNumRecords());
      }
    }

    wb.write(outputStream);
  }

  /**
   * The ObProj record points to the VBA storage: it must be removed when the policy rejected this
   * storage, or when the sanitized file no longer contains it.
   */
  private static boolean isVbaStorageRemoved(POIFSFileSystem fs, EntryRetentionPolicy policy) {
    return policy.wasRemoved(MacroRemover.VBA_ENTRY)
        || !fs.getRoot().hasEntry(MacroRemover.VBA_ENTRY);
  }

  protected static void removeObProjRecord(Collection<Record> records) {
    new HashSet<>(records)
        .forEach(
            record -> {
              if (!isObProj(record)) {
                return;
              }
              records.remove(record);
              LOGGER.debug("Found and removed ObProj record: {}", record);
            });
  }

  protected static boolean isObProj(Record record) {
    return record.getSid() == OB_PROJ_SID;
  }
}
