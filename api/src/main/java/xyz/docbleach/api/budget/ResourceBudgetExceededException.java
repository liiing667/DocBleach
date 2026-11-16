package xyz.docbleach.api.budget;

import xyz.docbleach.api.exception.BleachException;

/**
 * Thrown when the shared {@link ResourceBudget} of a sanitation chain is exhausted. This is a
 * fatal error: the current sanitation is aborted instead of letting a compression bomb or a deeply
 * nested document exhaust the host's memory or CPU.
 */
public class ResourceBudgetExceededException extends BleachException {

  private final transient ResourceBudget.Limit limit;
  private final long limitValue;
  private final long actualValue;
  private final String location;

  ResourceBudgetExceededException(
      ResourceBudget.Limit limit, long limitValue, long actualValue, String location) {
    super(
        "Resource budget exhausted ("
            + limit
            + "): "
            + actualValue
            + " reached, limit is "
            + limitValue
            + (location == null || location.isEmpty() ? "" : ", at " + location));
    this.limit = limit;
    this.actualValue = actualValue;
    this.limitValue = limitValue;
    this.location = location;
  }

  public ResourceBudget.Limit getLimit() {
    return limit;
  }

  public long getLimitValue() {
    return limitValue;
  }

  public long getActualValue() {
    return actualValue;
  }

  /**
   * @return the chain layer (container and entry) that triggered the violation, may be empty
   */
  public String getLocation() {
    return location;
  }
}
