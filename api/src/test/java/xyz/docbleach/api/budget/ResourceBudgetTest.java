package xyz.docbleach.api.budget;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import xyz.docbleach.api.threat.Threat;
import xyz.docbleach.api.threat.ThreatType;
import xyz.docbleach.api.util.BudgetedInputStream;

class ResourceBudgetTest {

  @Test
  void accumulatesBytesAcrossTheWholeChain() throws Exception {
    List<Threat> threats = new ArrayList<>();
    ResourceBudget budget =
        new ResourceBudget(100, 100, 10, 60_000L, threats::add);

    budget.accountBytes(60);
    budget.accountBytes(30);

    assertEquals(90L, budget.getTotalBytes());
    assertTrue(threats.isEmpty());
  }

  @Test
  void failsWhenCumulativeBytesExceedTheBudget() throws Exception {
    List<Threat> threats = new ArrayList<>();
    ResourceBudget budget = new ResourceBudget(100, 100, 10, 60_000L, threats::add);
    budget.accountBytes(60);

    ResourceBudgetExceededException exception =
        assertThrows(ResourceBudgetExceededException.class, () -> budget.accountBytes(50));

    assertEquals(ResourceBudget.Limit.TOTAL_BYTES, exception.getLimit());
    assertEquals(1, threats.size());
    assertEquals(ThreatType.RESOURCE_LIMIT, threats.get(0).type());
    assertEquals(110L, exception.getActualValue());
  }

  @Test
  void failsWhenEntryCountExceedsTheBudget() throws Exception {
    List<Threat> threats = new ArrayList<>();
    ResourceBudget budget = new ResourceBudget(10_000, 2, 10, 60_000L, threats::add);

    budget.accountEntry();
    budget.accountEntry();
    ResourceBudgetExceededException exception =
        assertThrows(ResourceBudgetExceededException.class, budget::accountEntry);

    assertEquals(ResourceBudget.Limit.ENTRY_COUNT, exception.getLimit());
    assertEquals(1, threats.size());
  }

  @Test
  void failsWhenDepthExceedsTheBudgetAndRestoresOnPop() throws Exception {
    List<Threat> threats = new ArrayList<>();
    ResourceBudget budget = new ResourceBudget(10_000, 100, 2, 60_000L, threats::add);

    budget.pushLayer("root");
    budget.pushLayer("zip");
    ResourceBudgetExceededException exception =
        assertThrows(
            ResourceBudgetExceededException.class,
            () -> budget.pushLayer("zip-entry:bomb"));

    assertEquals(ResourceBudget.Limit.DEPTH, exception.getLimit());
    assertEquals("root > zip > zip-entry:bomb", exception.getLocation());
    assertEquals(1, threats.size());

    // The rejected layer must not remain on the stack.
    budget.popLayer();
    budget.popLayer();
    assertEquals(0, budget.getDepth());
  }

  @Test
  void failsWhenTimeLimitIsReached() throws Exception {
    List<Threat> threats = new ArrayList<>();
    ResourceBudget budget = new ResourceBudget(10_000, 100, 10, 0L, threats::add);

    ResourceBudgetExceededException exception =
        assertThrows(ResourceBudgetExceededException.class, budget::checkTime);

    assertEquals(ResourceBudget.Limit.TIME, exception.getLimit());
    assertEquals(1, threats.size());
  }

  @Test
  void reportsTheCurrentLayerPath() throws Exception {
    ResourceBudget budget = new ResourceBudget();
    budget.pushLayer("pdf");
    budget.pushLayer("pdf-embedded:invoice.zip");

    assertEquals("pdf > pdf-embedded:invoice.zip", budget.currentLocation());

    budget.popLayer();
    assertEquals("pdf", budget.currentLocation());
  }

  @Test
  void budgetedInputStreamCountsBytesAndAborts() throws Exception {
    List<Threat> threats = new ArrayList<>();
    ResourceBudget budget = new ResourceBudget(4, 100, 10, 60_000L, threats::add);
    BudgetedInputStream stream =
        new BudgetedInputStream(
            new java.io.ByteArrayInputStream(new byte[]{1, 2, 3, 4, 5, 6, 7, 8}), budget);

    byte[] buffer = new byte[8];
    BudgetIOException exception =
        assertThrows(BudgetIOException.class, () -> stream.read(buffer));

    assertEquals(ResourceBudget.Limit.TOTAL_BYTES, exception.getBudgetException().getLimit());
    assertEquals(1, threats.size());
  }
}
