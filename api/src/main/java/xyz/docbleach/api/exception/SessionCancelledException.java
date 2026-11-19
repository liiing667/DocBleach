package xyz.docbleach.api.exception;

/**
 * Exception thrown when an operation is attempted on a cancelled {@link
 * xyz.docbleach.api.BleachSession}. A cancelled session is terminal: its private resources have
 * been destroyed and must never be resurrected.
 */
public class SessionCancelledException extends BleachException {

  public SessionCancelledException() {
    super("This bleach session has been cancelled and its resources have been destroyed.");
  }
}
