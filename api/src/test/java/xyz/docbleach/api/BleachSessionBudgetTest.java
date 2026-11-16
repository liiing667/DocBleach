package xyz.docbleach.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import org.junit.jupiter.api.Test;
import xyz.docbleach.api.bleach.Bleach;
import xyz.docbleach.api.budget.ResourceBudget;
import xyz.docbleach.api.budget.ResourceBudgetExceededException;

class BleachSessionBudgetTest {

  private static class RecursiveBleach implements Bleach {

    private final int maxDepth;

    private RecursiveBleach(int maxDepth) {
      this.maxDepth = maxDepth;
    }

    @Override
    public boolean handlesMagic(java.io.InputStream stream) {
      return true;
    }

    @Override
    public String getName() {
      return "recursive";
    }

    @Override
    public void sanitize(
        java.io.InputStream inputStream,
        java.io.OutputStream outputStream,
        BleachSession session)
        throws xyz.docbleach.api.exception.BleachException {
      session.pushBudgetLayer("recursive");
      try {
        if (session.getBudget().getDepth() >= maxDepth) {
          return;
        }
        session.sanitize(new ByteArrayInputStream(new byte[0]), new ByteArrayOutputStream());
      } finally {
        session.popBudgetLayer();
      }
    }
  }

  @Test
  void sharesOneBudgetAcrossTheWholeChain() throws Exception {
    ResourceBudget budget = new ResourceBudget();
    BleachSession session = new BleachSession(new RecursiveBleach(3), budget);

    session.sanitize(new ByteArrayInputStream(new byte[0]), new ByteArrayOutputStream());

    assertEquals(0, budget.getDepth());
  }

  @Test
  void abortsAndRecordsThreatWhenDepthBudgetIsExhausted() {
    ResourceBudget budget =
        new ResourceBudget(
            ResourceBudget.DEFAULT_MAX_BYTES,
            ResourceBudget.DEFAULT_MAX_ENTRIES,
            2,
            ResourceBudget.DEFAULT_TIME_LIMIT_MILLIS,
            null);
    BleachSession session = new BleachSession(new RecursiveBleach(10), budget);

    assertThrows(
        ResourceBudgetExceededException.class,
        () ->
            session.sanitize(
                new ByteArrayInputStream(new byte[0]), new ByteArrayOutputStream()));
    assertEquals(0, budget.getDepth());
  }

  @Test
  void delegatesByteAccountingToTheSharedBudget() throws Exception {
    ResourceBudget budget = new ResourceBudget();
    BleachSession session = new BleachSession(new RecursiveBleach(1), budget);

    session.accountBudgetedBytes(1234);

    assertEquals(1234L, budget.getTotalBytes());
    assertSame(budget, session.getBudget());
  }
}
