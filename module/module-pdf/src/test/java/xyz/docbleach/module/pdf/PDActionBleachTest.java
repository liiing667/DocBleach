package xyz.docbleach.module.pdf;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static xyz.docbleach.api.BleachTestBase.assertThreatsFound;

import java.util.Arrays;
import org.apache.pdfbox.pdmodel.interactive.action.PDAction;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionGoTo;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionImportData;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionJavaScript;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionLaunch;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionResetForm;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionSubmitForm;
import org.apache.pdfbox.pdmodel.interactive.action.PDActionURI;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import xyz.docbleach.api.BleachSession;

class PDActionBleachTest {

  private BleachSession session;
  private PDActionBleach instance;

  @BeforeEach
  void setUp() {
    session = mock(BleachSession.class);
    instance = new PDActionBleach(new PdfBleachSession(session));
  }

  @Test
  void dangerousSubtypesAreDetected() {
    assertTrue(instance.isDangerous(new PDActionJavaScript()));
    assertTrue(instance.isDangerous(new PDActionLaunch()));
    assertTrue(instance.isDangerous(new PDActionSubmitForm()));
    assertTrue(instance.isDangerous(new PDActionImportData()));
  }

  @Test
  void innocuousActionsAreKept() {
    assertFalse(instance.isDangerous(new PDActionGoTo()));
    assertFalse(instance.isDangerous(new PDActionResetForm()));

    PDActionURI httpsUri = new PDActionURI();
    httpsUri.setURI("https://example.org");
    assertFalse(instance.isDangerous(httpsUri));

    PDActionURI fileUri = new PDActionURI();
    fileUri.setURI("FILE:///C:/Windows/evil.exe");
    assertTrue(instance.isDangerous(fileUri));
  }

  @Test
  void sanitizeActionRemovesOnlyDangerousOnes() {
    assertNull(instance.sanitizeAction(new PDActionJavaScript(), "Test"));
    assertThreatsFound(session, 1);
    reset(session);

    PDActionResetForm resetForm = new PDActionResetForm();
    assertNotNull(instance.sanitizeAction(resetForm, "Test"));
    assertThreatsFound(session, 0);
  }

  @Test
  void sanitizeActionCleansTheNextChain() {
    PDActionResetForm first = new PDActionResetForm();
    PDActionLaunch dangerousNext = new PDActionLaunch();
    PDActionGoTo safeNext = new PDActionGoTo();
    first.setNext(Arrays.asList(dangerousNext, safeNext));

    PDAction kept = instance.sanitizeAction(first, "Test");

    assertNotNull(kept);
    assertThreatsFound(session, 1);
    assertTrue(kept.getNext().size() == 1);
  }
}
