package xyz.docbleach.module.ole2;

import java.util.Arrays;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.apache.poi.poifs.filesystem.Entry;
import xyz.docbleach.api.BleachSession;

/**
 * Single source of truth for the OLE2 entry retention decisions. Every removal path (macros,
 * compound objects, summary information) is evaluated through this policy, and each verdict is
 * computed once then cached, so a given entry always gets the same outcome whatever the traversal
 * order or the nesting level is.
 */
public class EntryRetentionPolicy {

  private final List<EntryFilter> filters;
  private final Map<Entry, Boolean> verdicts = new IdentityHashMap<>();
  private final Set<String> removedEntryNames = new HashSet<>();

  public EntryRetentionPolicy(BleachSession session) {
    this(
        Arrays.asList(
            new MacroRemover(session),
            new ObjectRemover(session),
            new SummaryInformationSanitiser(session)));
  }

  EntryRetentionPolicy(List<EntryFilter> filters) {
    this.filters = filters;
  }

  /**
   * Returns true if the entry itself must be kept. The verdict is computed on the first call and
   * then cached: every removal path shares the very same decision.
   */
  public boolean isKept(Entry entry) {
    Boolean verdict = verdicts.get(entry);
    if (verdict == null) {
      verdict = computeVerdict(entry);
      verdicts.put(entry, verdict);
    }
    return verdict;
  }

  /**
   * Returns true if the entry is kept and reachable from the root, ie. none of its ancestors has
   * been removed. A nested storage pointing to a removed node is unreachable and must not be
   * copied over.
   */
  public boolean isReachable(Entry entry) {
    Entry current = entry;
    while (current != null) {
      if (!isKept(current)) {
        return false;
      }
      Entry parent = current.getParent();
      current = parent == current ? null : parent;
    }
    return true;
  }

  /**
   * Returns true if an entry with this name has been rejected by the policy. Other cleanup paths
   * (eg. the Excel record cleaner) use it to stay consistent with the entry-level removals.
   */
  public boolean wasRemoved(String entryName) {
    return removedEntryNames.contains(normalize(entryName));
  }

  private boolean computeVerdict(Entry entry) {
    for (EntryFilter filter : filters) {
      if (!filter.test(entry)) {
        removedEntryNames.add(normalize(entry.getName()));
        return false;
      }
    }
    return true;
  }

  private static String normalize(String entryName) {
    return entryName.toLowerCase(Locale.ROOT);
  }
}
