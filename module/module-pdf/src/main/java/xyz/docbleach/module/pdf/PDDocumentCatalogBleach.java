package xyz.docbleach.module.pdf;

import java.io.IOException;
import java.util.Iterator;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.PDPage;
import org.apache.pdfbox.pdmodel.PDPageTree;
import org.apache.pdfbox.pdmodel.common.PDDestinationOrAction;
import org.apache.pdfbox.pdmodel.interactive.action.PDAction;
import org.apache.pdfbox.pdmodel.interactive.action.PDDocumentCatalogAdditionalActions;
import org.apache.pdfbox.pdmodel.interactive.action.PDFormFieldAdditionalActions;
import org.apache.pdfbox.pdmodel.interactive.action.PDPageAdditionalActions;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.form.PDAcroForm;
import org.apache.pdfbox.pdmodel.interactive.form.PDField;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class PDDocumentCatalogBleach {

  private static final Logger LOGGER = LoggerFactory.getLogger(PDDocumentCatalogBleach.class);
  private final PDActionBleach actionBleach;
  private final PDAnnotationBleach annotationBleach;

  PDDocumentCatalogBleach(PdfBleachSession pdfBleachSession) {
    this.actionBleach = pdfBleachSession.getActionBleach();
    this.annotationBleach = new PDAnnotationBleach(pdfBleachSession);
  }

  private void sanitizeAcroFormActions(PDAcroForm acroForm) {
    if (acroForm == null) {
      LOGGER.debug("No AcroForms found");
      return;
    }
    LOGGER.trace("Checking AcroForm Actions");

    Iterator<PDField> fields = acroForm.getFieldIterator();
    fields.forEachRemaining(this::sanitizeField);
  }

  private void sanitizeField(PDField field) {
    // Sanitize annotations
    field.getWidgets().forEach(annotationBleach::sanitizeAnnotation);

    // Sanitize field actions
    PDFormFieldAdditionalActions fieldActions = field.getActions();
    if (fieldActions == null) {
      return;
    }
    sanitizeFieldAdditionalActions(fieldActions);
  }

  private void sanitizePage(PDPage page) throws IOException {
    for (PDAnnotation annotation : page.getAnnotations()) {
      annotationBleach.sanitizeAnnotation(annotation);
    }
    sanitizePageActions(page.getActions());
  }

  private void sanitizePageActions(PDPageTree pages) throws IOException {
    LOGGER.trace("Checking Pages Actions");
    for (PDPage page : pages) {
      sanitizePage(page);
    }
  }

  void sanitizePageActions(PDPageAdditionalActions pageActions) {
    if (pageActions == null) {
      return;
    }
    actionBleach.sanitizeAdditionalActionsDictionary(
        pageActions.getCOSObject(), "Page Actions");
  }

  void sanitizeOpenAction(PDDocumentCatalog docCatalog) throws IOException {
    LOGGER.trace("Checking OpenAction...");
    PDDestinationOrAction openAction = docCatalog.getOpenAction();

    if (openAction == null) {
      return;
    }

    if (openAction instanceof PDAction) {
      PDAction action = (PDAction) openAction;
      if (actionBleach.sanitizeAction(action, "Document Catalog") == null) {
        docCatalog.setOpenAction(null);
      }
      return;
    }

    LOGGER.trace("Keeping innocuous OpenAction destination ({})", openAction);
  }

  void sanitizeDocumentActions(PDDocumentCatalogAdditionalActions documentActions) {
    if (documentActions == null) {
      return;
    }
    LOGGER.trace("Checking additional actions...");
    actionBleach.sanitizeAdditionalActionsDictionary(
        documentActions.getCOSObject(), "DocumentCatalogAdditionalActions");
  }

  void sanitizeFieldAdditionalActions(PDFormFieldAdditionalActions fieldActions) {
    if (fieldActions == null) {
      return;
    }
    actionBleach.sanitizeAdditionalActionsDictionary(
        fieldActions.getCOSObject(), "FormAdditionalActions");
  }

  void sanitize(PDDocumentCatalog docCatalog) throws IOException {
    sanitizeOpenAction(docCatalog);
    sanitizeDocumentActions(docCatalog.getActions());
    sanitizePageActions(docCatalog.getPages());
    sanitizeAcroFormActions(docCatalog.getAcroForm());
  }
}
