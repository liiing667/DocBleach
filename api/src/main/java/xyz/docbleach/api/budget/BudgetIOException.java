package xyz.docbleach.api.budget;

import java.io.IOException;

/**
 * IOException carrying a {@link ResourceBudgetExceededException}. It lets budget-aware input
 * streams abort a read while the exception can still be unwrapped and rethrown as a regular
 * {@link xyz.docbleach.api.exception.BleachException} by the bleach in charge of the stream.
 */
public class BudgetIOException extends IOException {

  private final transient ResourceBudgetExceededException budgetException;

  public BudgetIOException(ResourceBudgetExceededException budgetException) {
    super(budgetException.getMessage(), budgetException);
    this.budgetException = budgetException;
  }

  public ResourceBudgetExceededException getBudgetException() {
    return budgetException;
  }

  /**
   * Rethrows the cause of an IOException raised while reading a budget-aware stream when it is a
   * budget violation, does nothing otherwise.
   */
  public static void rethrowIfBudget(IOException exception)
      throws ResourceBudgetExceededException {
    if (exception instanceof BudgetIOException) {
      throw ((BudgetIOException) exception).getBudgetException();
    }
    Throwable cause = exception.getCause();
    if (cause instanceof BudgetIOException) {
      throw ((BudgetIOException) cause).getBudgetException();
    }
  }

  /**
   * Unwraps a budget violation hidden in a runtime exception, for instance when it crossed a
   * visitor lambda as a {@link BudgetAbortException}.
   */
  public static void rethrowIfBudget(RuntimeException exception)
      throws ResourceBudgetExceededException {
    if (exception instanceof BudgetAbortException) {
      throw ((BudgetAbortException) exception).getBudgetException();
    }
    Throwable cause = exception.getCause();
    if (cause instanceof BudgetAbortException) {
      throw ((BudgetAbortException) cause).getBudgetException();
    }
  }
}
