package xyz.docbleach.module.pdf;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.pdmodel.interactive.action.PDAction;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionFactory;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionURI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Single place deciding whether an action is dangerous. Only active content that executes code,
 * launches programs or exfiltrates form data is removed: plain links (URI/GoTo), destinations and
 * harmless form actions such as ResetForm keep working. The same policy is shared by the catalog,
 * annotation, outline and generic COS traversal bleaches.
 */
class PDActionBleach {

  private static final Logger LOGGER = LoggerFactory.getLogger(PDActionBleach.class);

  private static final Set<String> DANGEROUS_SUBTYPES =
      new HashSet<>(
          Arrays.asList(
              "JavaScript",
              "Launch",
              "SubmitForm",
              "ImportData",
              "Rendition",
              "Sound",
              "Movie"));

  private final PdfBleachSession pdfBleachSession;

  PDActionBleach(PdfBleachSession pdfBleachSession) {
    this.pdfBleachSession = pdfBleachSession;
  }

  boolean isActionDictionary(COSDictionary dictionary) {
    return isActionSubtype(dictionary.getNameAsString(COSName.S));
  }

  private boolean isActionSubtype(String subtype) {
    if (subtype == null) {
      return false;
    }
    return DANGEROUS_SUBTYPES.contains(subtype)
        || "URI".equals(subtype)
        || "GoTo".equals(subtype)
        || "RemoteGoTo".equals(subtype)
        || "Named".equals(subtype)
        || "ResetForm".equals(subtype)
        || "Hide".equals(subtype)
        || "Thread".equals(subtype)
        || "EmbeddedGoTo".equals(subtype)
        || "GoTo3DView".equals(subtype)
        || "Trans".equals(subtype);
  }

  boolean isDangerous(PDAction action) {
    return isDangerous(action.getCOSObject());
  }

  boolean isDangerous(COSDictionary actionDictionary) {
    String subtype = actionDictionary.getNameAsString(COSName.S);
    if (DANGEROUS_SUBTYPES.contains(subtype)) {
      return true;
    }
    if ("URI".equals(subtype)) {
      return isFileUri(actionDictionary);
    }
    return false;
  }

  private boolean isFileUri(COSDictionary actionDictionary) {
    PDAction action = PDActionFactory.createAction(actionDictionary);
    if (!(action instanceof PDActionURI)) {
      return false;
    }
    String uri = ((PDActionURI) action).getURI();
    return uri != null && uri.toLowerCase().startsWith("file:");
  }

  /**
   * Sanitizes an action and every action chained through its Next entry. Dangerous actions are
   * removed from the chain while innocuous ones are preserved.
   *
   * @return the action to keep in place, or null if it was dangerous
   */
  PDAction sanitizeAction(PDAction action, String location) {
    if (action == null) {
      return null;
    }
    sanitizeNextActions(action, location);
    if (isDangerous(action)) {
      LOGGER.debug("Found&removed dangerous action (was {})", action);
      pdfBleachSession.recordActionThreat(location, action);
      return null;
    }
    return action;
  }

  private void sanitizeNextActions(PDAction action, String location) {
    COSDictionary actionDictionary = action.getCOSObject();
    COSBase next = actionDictionary.getDictionaryObject(COSName.NEXT);
    if (next == null) {
      return;
    }
    if (next instanceof COSArray) {
      sanitizeActionArray((COSArray) next, location);
      if (((COSArray) next).size() == 0) {
        actionDictionary.removeItem(COSName.NEXT);
      }
    } else if (next instanceof COSDictionary) {
      COSDictionary nextDictionary = (COSDictionary) next;
      if (isActionDictionary(nextDictionary)) {
        sanitizeNextIfPresent(nextDictionary, location);
        if (isDangerous(nextDictionary)) {
          actionDictionary.removeItem(COSName.NEXT);
          recordDictionaryThreat(location, nextDictionary);
        }
      }
    }
  }

  /**
   * Walks an additional-actions dictionary (AA) and removes only the dangerous entries, keeping
   * legitimate event handlers such as a ResetForm intact.
   */
  void sanitizeAdditionalActionsDictionary(COSDictionary additionalActions, String location) {
    if (additionalActions == null) {
      return;
    }
    for (COSName key : new ArrayList<>(additionalActions.keySet())) {
      COSBase value = unwrap(additionalActions.getDictionaryObject(key));
      if (value instanceof COSDictionary) {
        COSDictionary actionDictionary = (COSDictionary) value;
        if (isActionDictionary(actionDictionary) && isDangerous(actionDictionary)) {
          additionalActions.removeItem(key);
          recordDictionaryThreat(location, actionDictionary);
          continue;
        }
        sanitizeNextIfPresent(actionDictionary, location);
      } else if (value instanceof COSArray) {
        sanitizeActionArray((COSArray) value, location);
      }
    }
  }

  void sanitizeActionArray(COSArray actions, String location) {
    for (int index = actions.size() - 1; index >= 0; index--) {
      COSBase item = unwrap(actions.getObject(index));
      if (item instanceof COSDictionary) {
        COSDictionary actionDictionary = (COSDictionary) item;
        if (isActionDictionary(actionDictionary)) {
          sanitizeNextIfPresent(actionDictionary, location);
          if (isDangerous(actionDictionary)) {
            actions.remove(index);
            recordDictionaryThreat(location, actionDictionary);
          }
        }
      }
    }
  }

  void sanitizeNextIfPresent(COSDictionary actionDictionary, String location) {
    COSBase next = actionDictionary.getDictionaryObject(COSName.NEXT);
    if (next == null) {
      return;
    }
    next = unwrap(next);
    if (next instanceof COSArray) {
      sanitizeActionArray((COSArray) next, location);
    } else if (next instanceof COSDictionary && isActionDictionary((COSDictionary) next)) {
      COSDictionary nextDictionary = (COSDictionary) next;
      if (isDangerous(nextDictionary)) {
        actionDictionary.removeItem(COSName.NEXT);
        recordDictionaryThreat(location, nextDictionary);
      }
    }
  }

  private void recordDictionaryThreat(String location, COSDictionary actionDictionary) {
    String subtype = actionDictionary.getNameAsString(COSName.S);
    pdfBleachSession.recordActionThreat(location, actionDictionary);
  }

  private COSBase unwrap(COSBase base) {
    if (base instanceof COSObject) {
      return ((COSObject) base).getObject();
    }
    return base;
  }
}
