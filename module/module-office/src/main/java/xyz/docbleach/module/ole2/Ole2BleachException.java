package xyz.docbleach.module.ole2;

import xyz.docbleach.api.exception.BleachException;

/**
 * Classifiable exception raised when the OLE2 sanitation fails. The category identifies the
 * failing stage, so callers can react without parsing the exception message. When this exception
 * is thrown, no partial output has been written to the target stream.
 */
public class Ole2BleachException extends BleachException {

  /** The sanitation stage that failed. */
  public enum Category {
    /** The input could not be read as an OLE2 container. */
    INPUT_READ,
    /** An entry could not be copied into the sanitized container. */
    ENTRY_COPY,
    /** The nested sanitation of an entry's content failed. */
    CONTENT_SANITIZE,
    /** The Excel 97 record cleanup failed. */
    RECORD_CLEANUP,
    /** The sanitized container could not be written. */
    OUTPUT_WRITE
  }

  private final Category category;

  public Ole2BleachException(Category category, Throwable cause) {
    super(cause);
    this.category = category;
  }

  public Ole2BleachException(Category category, String message, Throwable cause) {
    super(message, cause);
    this.category = category;
  }

  public Category getCategory() {
    return category;
  }
}
