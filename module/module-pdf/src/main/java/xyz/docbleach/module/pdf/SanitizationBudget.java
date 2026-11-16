package xyz.docbleach.module.pdf;

/**
 * Shared budget for every part of a PDF sanitation run: the generic COS object traversal, the
 * action decisions and the recursive embedded file handling all consume the same counters, so a
 * malicious document cannot exhaust the sanitizer by hiding payloads behind indirect objects or
 * nested files.
 */
class SanitizationBudget {

  private static final int MAX_TRAVERSED_OBJECTS = 100_000;
  private static final int MAX_TRAVERSAL_DEPTH = 200;
  private static final int MAX_EMBEDDED_FILES = 1_000;

  private int traversedObjects;
  private int maxDepthReached;
  private int embeddedFiles;
  private boolean exhausted;

  boolean claimObject(int depth) {
    if (exhausted
        || depth > MAX_TRAVERSAL_DEPTH
        || traversedObjects >= MAX_TRAVERSED_OBJECTS) {
      exhausted = true;
      return false;
    }
    traversedObjects++;
    if (depth > maxDepthReached) {
      maxDepthReached = depth;
    }
    return true;
  }

  boolean claimEmbeddedFile() {
    if (exhausted || embeddedFiles >= MAX_EMBEDDED_FILES) {
      exhausted = true;
      return false;
    }
    embeddedFiles++;
    return true;
  }

  boolean isExhausted() {
    return exhausted;
  }

  int getTraversedObjects() {
    return traversedObjects;
  }

  int getMaxDepthReached() {
    return maxDepthReached;
  }

  int getEmbeddedFiles() {
    return embeddedFiles;
  }
}
