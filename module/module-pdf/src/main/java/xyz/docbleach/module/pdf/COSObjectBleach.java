package xyz.docbleach.module.pdf;

import java.util.Collection;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSBoolean;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSNull;
import org.apache.pdfbox.cos.COSNumber;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.cos.COSString;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Backstop traversal of every indirect object of the PDF.
 *
 * <p>The high level bleaches handle the well known entry points (catalog, pages, forms,
 * annotations, name tree). This crawl guarantees that an entry hidden in any other dictionary or
 * array is still found: it dereferences indirect objects, detects reference cycles and shares the
 * session-wide {@link SanitizationBudget} with action decisions and embedded file recursion.
 */
class COSObjectBleach {

  private static final Logger LOGGER = LoggerFactory.getLogger(COSObjectBleach.class);

  private final PdfBleachSession pdfBleachSession;
  private final PDActionBleach actionBleach;
  private final PDEmbeddedFileBleach embeddedFileBleach;
  private final Set<COSBase> visited =
      Collections.newSetFromMap(new IdentityHashMap<COSBase, Boolean>());

  COSObjectBleach(
      PdfBleachSession pdfBleachSession,
      PDActionBleach actionBleach,
      PDEmbeddedFileBleach embeddedFileBleach) {
    this.pdfBleachSession = pdfBleachSession;
    this.actionBleach = actionBleach;
    this.embeddedFileBleach = embeddedFileBleach;
  }

  void sanitizeObjects(Collection<COSObject> objects) {
    LOGGER.trace("Checking all objects...");
    for (COSObject object : objects) {
      if (pdfBleachSession.getBudget().isExhausted()) {
        LOGGER.warn("Object traversal stopped, sanitization budget is exhausted");
        return;
      }
      crawl(object, 0);
    }
  }

  private void crawl(COSBase base, int depth) {
    if (base == null || pdfBleachSession.getBudget().isExhausted()) {
      return;
    }

    if (!pdfBleachSession.getBudget().claimObject(depth)) {
      return;
    }

    if (base instanceof COSObject) {
      crawl(((COSObject) base).getObject(), depth + 1);
      return;
    }

    if (base instanceof COSName
        || base instanceof COSString
        || base instanceof COSStream
        || base instanceof COSNull
        || base instanceof COSNumber
        || base instanceof COSBoolean) {
      return;
    }

    if (!visited.add(base)) {
      return;
    }

    if (base instanceof COSDictionary) {
      crawlDictionary((COSDictionary) base, depth);
    } else if (base instanceof COSArray) {
      crawlArray((COSArray) base, depth);
    } else {
      LOGGER.error("Unknown COS type: {}", base);
    }
  }

  private void crawlDictionary(COSDictionary dictionary, int depth) {
    Iterator<Map.Entry<COSName, COSBase>> iterator = dictionary.entrySet().iterator();
    while (iterator.hasNext()) {
      if (pdfBleachSession.getBudget().isExhausted()) {
        return;
      }
      Map.Entry<COSName, COSBase> entry = iterator.next();
      COSName key = entry.getKey();
      COSBase value = entry.getValue();

      if (COSName.JS.equals(key) || COSName.JAVA_SCRIPT.equals(key)) {
        iterator.remove();
        LOGGER.debug("Found and removed Javascript code");
        if (actionBleach.isActionDictionary(dictionary)) {
          pdfBleachSession.markActionThreatReported(dictionary);
        }
        pdfBleachSession.recordJavascriptThreat("COS object", "JS Code");
        continue;
      }

      COSBase dereferenced = dereference(value);

      if (COSName.AA.equals(key)) {
        if (dereferenced instanceof COSDictionary) {
          actionBleach.sanitizeAdditionalActionsDictionary(
              (COSDictionary) dereferenced, "Additional Actions");
        } else if (dereferenced instanceof COSArray) {
          actionBleach.sanitizeActionArray((COSArray) dereferenced, "Additional Actions");
        } else {
          crawl(value, depth + 1);
          continue;
        }
        if (dereferenced instanceof COSArray && ((COSArray) dereferenced).size() == 0) {
          iterator.remove();
        } else if (dereferenced instanceof COSDictionary
            && ((COSDictionary) dereferenced).size() == 0) {
          iterator.remove();
        }
        continue;
      }

      if (dereferenced instanceof COSDictionary) {
        COSDictionary nestedDictionary = (COSDictionary) dereferenced;
        if (actionBleach.isActionDictionary(nestedDictionary)) {
          actionBleach.sanitizeNextIfPresent(nestedDictionary, "COS object");
          if (actionBleach.isDangerous(nestedDictionary)) {
            iterator.remove();
            LOGGER.debug("Found and removed dangerous action dictionary");
            recordActionThreat(nestedDictionary);
          }
          continue;
        }
        if (embeddedFileBleach.isFileSpecification(nestedDictionary)) {
          embeddedFileBleach.sanitizeFileSpecification(nestedDictionary);
          continue;
        }
      }

      crawl(value, depth + 1);
    }
  }

  private void crawlArray(COSArray array, int depth) {
    for (int index = array.size() - 1; index >= 0; index--) {
      if (pdfBleachSession.getBudget().isExhausted()) {
        return;
      }
      COSBase item = array.getObject(index);
      COSBase dereferenced = dereference(item);
      if (dereferenced instanceof COSDictionary
          && actionBleach.isActionDictionary((COSDictionary) dereferenced)) {
        COSDictionary actionDictionary = (COSDictionary) dereferenced;
        actionBleach.sanitizeNextIfPresent(actionDictionary, "COS object");
        if (actionBleach.isDangerous(actionDictionary)) {
          array.remove(index);
          LOGGER.debug("Found and removed dangerous action dictionary");
          recordActionThreat(actionDictionary);
        }
        continue;
      }
      crawl(item, depth + 1);
    }
  }

  private void recordActionThreat(COSDictionary actionDictionary) {
    pdfBleachSession.recordBackstopActionThreat("COS object", actionDictionary);
  }

  private COSBase dereference(COSBase base) {
    if (base instanceof COSObject) {
      return ((COSObject) base).getObject();
    }
    return base;
  }
}
