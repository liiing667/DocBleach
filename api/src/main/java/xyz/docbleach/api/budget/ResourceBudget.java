package xyz.docbleach.api.budget;

import java.util.ArrayDeque;
import java.util.Deque;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import xyz.docbleach.api.threat.Threat;
import xyz.docbleach.api.threat.ThreatAction;
import xyz.docbleach.api.threat.ThreatSeverity;
import xyz.docbleach.api.threat.ThreatType;

/**
 * Shared resource budget of a whole sanitation chain.
 *
 * <p>A single instance is carried by the {@link xyz.docbleach.api.BleachSession} and shared by
 * every nested bleach (ZIP entries, OLE2 streams, PDF embedded files, ...). Where the historical
 * code only limited the depth of the recursion, this budget accumulates the cost of every layer so
 * that compression bombs and multi-level embeddings cannot multiply the memory and CPU usage of
 * the chain.
 *
 * <p>Four limits are enforced across the whole chain:
 *
 * <ul>
 *   <li>total decompressed bytes read from every layer,
 *   <li>total number of container entries processed,
 *   <li>maximum nesting depth of the sanitation tasks,
 *   <li>wall-clock time spent sanitizing the root document.
 * </ul>
 *
 * Every violation records a {@link Threat} locating the offending layer before throwing a {@link
 * ResourceBudgetExceededException}, so the failure is safe and the threat report explains where it
 * happened.
 */
public class ResourceBudget {

  private static final Logger LOGGER = LoggerFactory.getLogger(ResourceBudget.class);

  public static final long DEFAULT_MAX_BYTES = 100L * 1024 * 1024;
  public static final int DEFAULT_MAX_ENTRIES = 10_000;
  public static final int DEFAULT_MAX_DEPTH = 10;
  public static final long DEFAULT_TIME_LIMIT_MILLIS = 60_000L;

  public enum Limit {
    TOTAL_BYTES,
    ENTRY_COUNT,
    DEPTH,
    TIME
  }

  private final long maxBytes;
  private final int maxEntries;
  private final int maxDepth;
  private final long timeLimitMillis;

  private long totalBytes;
  private int entryCount;
  private int depth;
  private final long startNanos = System.nanoTime();

  private final Deque<String> layers = new ArrayDeque<>();
  private final ThreatRecorder threatRecorder;

  public interface ThreatRecorder {
    void record(Threat threat);
  }

  public ResourceBudget() {
    this(
        DEFAULT_MAX_BYTES,
        DEFAULT_MAX_ENTRIES,
        DEFAULT_MAX_DEPTH,
        DEFAULT_TIME_LIMIT_MILLIS,
        null);
  }

  public ResourceBudget(ThreatRecorder threatRecorder) {
    this(
        DEFAULT_MAX_BYTES,
        DEFAULT_MAX_ENTRIES,
        DEFAULT_MAX_DEPTH,
        DEFAULT_TIME_LIMIT_MILLIS,
        threatRecorder);
  }

  public ResourceBudget(
      long maxBytes,
      int maxEntries,
      int maxDepth,
      long timeLimitMillis,
      ThreatRecorder threatRecorder) {
    this.maxBytes = maxBytes;
    this.maxEntries = maxEntries;
    this.maxDepth = maxDepth;
    this.timeLimitMillis = timeLimitMillis;
    this.threatRecorder = threatRecorder;
  }

  public long getMaxBytes() {
    return maxBytes;
  }

  public int getMaxEntries() {
    return maxEntries;
  }

  public int getMaxDepth() {
    return maxDepth;
  }

  public long getTimeLimitMillis() {
    return timeLimitMillis;
  }

  public long getTotalBytes() {
    return totalBytes;
  }

  public int getEntryCount() {
    return entryCount;
  }

  public int getDepth() {
    return depth;
  }

  public long getElapsedMillis() {
    return (System.nanoTime() - startNanos) / 1_000_000L;
  }

  /**
   * Pushes a layer on the chain path and enforces the nesting depth limit.
   *
   * @param layer a human readable name of the layer (container or entry name)
   * @throws ResourceBudgetExceededException if the depth limit is reached
   */
  public void pushLayer(String layer) throws ResourceBudgetExceededException {
    String layerName = layer == null ? "?" : layer;
    depth++;
    if (depth > maxDepth) {
      int offendingDepth = depth;
      depth--;
      layers.addLast(layerName);
      fail(Limit.DEPTH, maxDepth, offendingDepth);
    }
    layers.addLast(layerName);
    checkTime();
  }

  public void popLayer() {
    if (!layers.isEmpty()) {
      layers.removeLast();
    }
    if (depth > 0) {
      depth--;
    }
  }

  /**
   * @return the path of the layers currently being processed, from the root document to the
   *     current entry
   */
  public String currentLocation() {
    return String.join(" > ", layers);
  }

  /**
   * Accounts decompressed bytes produced by any layer of the chain.
   *
   * @param bytes number of newly read decompressed bytes
   * @throws ResourceBudgetExceededException if the cumulative byte limit is reached
   */
  public void accountBytes(long bytes) throws ResourceBudgetExceededException {
    if (bytes <= 0) {
      return;
    }
    totalBytes += bytes;
    if (totalBytes > maxBytes) {
      fail(Limit.TOTAL_BYTES, maxBytes, totalBytes);
    }
    checkTime();
  }

  /**
   * Accounts a container entry (ZIP entry, OLE2 node, PDF embedded file) processed by the chain.
   *
   * @throws ResourceBudgetExceededException if the cumulative entry limit is reached
   */
  public void accountEntry() throws ResourceBudgetExceededException {
    entryCount++;
    if (entryCount > maxEntries) {
      fail(Limit.ENTRY_COUNT, maxEntries, entryCount);
    }
    checkTime();
  }

  /**
   * Enforces the wall-clock time limit of the chain. Bleaches call it between heavy operations,
   * and budget-aware streams call it while reading data.
   *
   * @throws ResourceBudgetExceededException if the time limit is reached
   */
  public void checkTime() throws ResourceBudgetExceededException {
    long elapsed = getElapsedMillis();
    if (timeLimitMillis >= 0 && elapsed >= timeLimitMillis) {
      fail(Limit.TIME, timeLimitMillis, elapsed);
    }
  }

  private void fail(Limit limit, long limitValue, long actualValue)
      throws ResourceBudgetExceededException {
    String location = currentLocation();
    ResourceBudgetExceededException exception =
        new ResourceBudgetExceededException(limit, limitValue, actualValue, location);
    LOGGER.error("Resource budget exhausted: {}", exception.getMessage());
    recordThreat(exception);
    throw exception;
  }

  private void recordThreat(ResourceBudgetExceededException exception) {
    if (threatRecorder == null) {
      return;
    }
    Threat threat =
        Threat.builder()
            .type(ThreatType.RESOURCE_LIMIT)
            .severity(ThreatSeverity.EXTREME)
            .action(ThreatAction.NOTHING)
            .location(exception.getLocation().isEmpty() ? "root" : exception.getLocation())
            .details(exception.getMessage())
            .build();
    threatRecorder.record(threat);
  }
}
