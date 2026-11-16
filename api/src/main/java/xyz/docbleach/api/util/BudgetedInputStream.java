package xyz.docbleach.api.util;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import xyz.docbleach.api.budget.BudgetIOException;
import xyz.docbleach.api.budget.ResourceBudget;
import xyz.docbleach.api.budget.ResourceBudgetExceededException;

/**
 * InputStream that feeds every byte read into the shared {@link ResourceBudget} of the sanitation
 * chain. It makes libraries parsing the stream (PDFBox, POI, ...) respect the chain-wide byte and
 * time limits without each caller having to count bytes itself.
 */
public class BudgetedInputStream extends FilterInputStream {

  private final ResourceBudget budget;

  public BudgetedInputStream(InputStream in, ResourceBudget budget) {
    super(in);
    this.budget = budget;
  }

  @Override
  public int read() throws IOException {
    int value = super.read();
    if (value != -1) {
      account(1);
    }
    return value;
  }

  @Override
  public int read(byte[] buffer) throws IOException {
    return read(buffer, 0, buffer.length);
  }

  @Override
  public int read(byte[] buffer, int offset, int length) throws IOException {
    int read = super.read(buffer, offset, length);
    if (read > 0) {
      account(read);
    }
    return read;
  }

  private void account(int bytes) throws BudgetIOException {
    try {
      budget.accountBytes(bytes);
    } catch (ResourceBudgetExceededException e) {
      throw new BudgetIOException(e);
    }
  }
}
