package xyz.docbleach.module.pdf;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class SanitizationBudgetTest {

  @Test
  void objectClaimsAreCountedAndBounded() {
    SanitizationBudget budget = new SanitizationBudget();

    assertTrue(budget.claimObject(0));
    assertTrue(budget.claimObject(3));
    assertEquals(2, budget.getTraversedObjects());
    assertEquals(3, budget.getMaxDepthReached());

    assertFalse(budget.claimObject(201));
    assertTrue(budget.isExhausted());
    assertFalse(budget.claimObject(0));
  }

  @Test
  void embeddedFileClaimsShareTheSameBudget() {
    SanitizationBudget budget = new SanitizationBudget();

    for (int i = 0; i < 1000; i++) {
      assertTrue(budget.claimEmbeddedFile());
    }
    assertFalse(budget.claimEmbeddedFile());
    assertTrue(budget.isExhausted());
    assertEquals(1000, budget.getEmbeddedFiles());
  }

  @Test
  void exhaustedObjectBudgetStopsEmbeddedFileClaims() {
    SanitizationBudget budget = new SanitizationBudget();

    budget.claimObject(201);

    assertTrue(budget.isExhausted());
    assertFalse(budget.claimEmbeddedFile());
  }
}
