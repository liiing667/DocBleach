package xyz.docbleach.module.pdf;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static xyz.docbleach.api.BleachTestBase.assertThreatsFound;

import java.io.IOException;
import java.util.Collections;
import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionGoTo;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionJavaScript;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionLaunch;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionResetForm;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionURI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import xyz.docbleach.api.BleachSession;

class COSObjectBleachTest {

  private BleachSession session;
  private PdfBleachSession pdfBleachSession;
  private COSObjectBleach instance;

  @BeforeEach
  void setUp() {
    session = mock(BleachSession.class);
    pdfBleachSession = new PdfBleachSession(session);
    instance =
        new COSObjectBleach(
            pdfBleachSession,
            pdfBleachSession.getActionBleach(),
            pdfBleachSession.getEmbeddedFileBleach());
  }

  @Test
  void javascriptHiddenBehindIndirectionIsRemoved() throws IOException {
    PDActionJavaScript javaScript = new PDActionJavaScript();
    COSObject indirectAction = new COSObject(javaScript.getCOSObject());
    COSDictionary holder = new COSDictionary();
    holder.setItem(COSName.A, indirectAction);
    COSObject root = new COSObject(holder);

    instance.sanitizeObjects(Collections.singletonList(root));

    assertThreatsFound(session, 1);
    assertFalse(holder.containsKey(COSName.A));
  }

  @Test
  void dangerousActionInArrayIsRemovedButInnocuousOneIsKept() throws IOException {
    COSArray actions = new COSArray();
    actions.add(new PDActionLaunch().getCOSObject());
    actions.add(new PDActionResetForm().getCOSObject());
    COSObject root = new COSObject(actions);

    instance.sanitizeObjects(Collections.singletonList(root));

    assertThreatsFound(session, 1);
    assertTrue(actions.size() == 1);
  }

  @Test
  void plainUriLinksArePreserved() throws IOException {
    PDActionURI uri = new PDActionURI();
    uri.setURI("https://example.org");
    COSObject root = new COSObject(uri.getCOSObject());

    instance.sanitizeObjects(Collections.singletonList(root));

    assertThreatsFound(session, 0);
    assertNotNull(root.getObject());
  }

  @Test
  void referenceCyclesDoNotLoopForever() throws IOException {
    COSDictionary first = new COSDictionary();
    COSDictionary second = new COSDictionary();
    first.setItem(COSName.getPDFName("Next"), new COSObject(second));
    second.setItem(COSName.getPDFName("Previous"), new COSObject(first));

    instance.sanitizeObjects(Collections.singletonList(new COSObject(first)));

    assertThreatsFound(session, 0);
  }

  @Test
  void rawJavaScriptEntriesAreStripped() throws IOException {
    COSDictionary dictionary = new COSDictionary();
    dictionary.setString(COSName.JS, "app.alert('pwned')");
    dictionary.setName(COSName.getPDFName("JavaScript"), "app.alert('pwned')");

    instance.sanitizeObjects(Collections.singletonList(new COSObject(dictionary)));

    assertThreatsFound(session, 2);
    assertFalse(dictionary.containsKey(COSName.JS));
    assertFalse(dictionary.containsKey(COSName.getPDFName("JavaScript")));
  }

  @Test
  void dangerousActionHiddenInNextChainIsRemoved() throws IOException {
    PDActionGoTo safeAction = new PDActionGoTo();
    COSArray nextChain = new COSArray();
    nextChain.add(new COSObject(new PDActionLaunch().getCOSObject()));
    safeAction.getCOSObject().setItem(COSName.NEXT, nextChain);

    COSObject root = new COSObject(safeAction.getCOSObject());

    instance.sanitizeObjects(Collections.singletonList(root));

    assertThreatsFound(session, 1);
    assertTrue(nextChain.size() == 0);
  }
}
