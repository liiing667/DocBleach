package xyz.docbleach.api.budget;

/**
 * Unchecked carrier for a {@link ResourceBudgetExceededException}.
 *
 * <p>Some recursion points (visitor lambdas, {@link java.util.stream.Stream} pipelines, ...)
 * cannot propagate checked exceptions. The budget violation is wrapped in this runtime exception
 * to cross those boundaries and unwrapped by the bleach owning the sanitation call.
 */
public class BudgetAbortException extends RuntimeException {

  private final transient ResourceBudgetExceededException budgetException;

  public BudgetAbortException(ResourceBudgetExceededException budgetException) {
    super(budgetException.getMessage(), budgetException);
    this.budgetException = budgetException;
  }

  public ResourceBudgetExceededException getBudgetException() {
    return budgetException;
  }
}
