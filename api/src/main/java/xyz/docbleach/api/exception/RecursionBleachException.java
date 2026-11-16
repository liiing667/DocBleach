package xyz.docbleach.api.exception;

/**
 * Exception thrown when a recursion is prevented, to protect from Zip Bombs for instance.
 *
 * @deprecated Recursion depth is now enforced, together with decompressed size, entry count and
 *     processing time, by the chain-wide {@link xyz.docbleach.api.budget.ResourceBudget}, which
 *     throws {@link xyz.docbleach.api.budget.ResourceBudgetExceededException}. This class is kept
 *     for backward compatibility only.
 */
@Deprecated
public class RecursionBleachException extends BleachException {

  /**
   * @param depth The depth of the recursion
   */
  public RecursionBleachException(int depth) {
    super("Recursion exploit? There are already " + depth + " sanitation tasks.");
  }
}
