package xyz.docbleach.module.pdf;

import java.io.IOException;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.interactive.action.PDAnnotationAdditionalActions;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotation;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationFileAttachment;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationLink;
import org.apache.pdfbox.pdmodel.interactive.annotation.PDAnnotationWidget;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

class PDAnnotationBleach {

  private static final Logger LOGGER = LoggerFactory.getLogger(PDAnnotationBleach.class);
  private final PdfBleachSession pdfBleachSession;
  private final PDActionBleach actionBleach;

  PDAnnotationBleach(PdfBleachSession pdfBleachSession) {
    this.pdfBleachSession = pdfBleachSession;
    this.actionBleach = pdfBleachSession.getActionBleach();
  }

  void sanitizeLinkAnnotation(PDAnnotationLink annotationLink) {
    if (annotationLink.getAction() == null) {
      return;
    }
    if (actionBleach.sanitizeAction(annotationLink.getAction(), "Annotation") == null) {
      LOGGER.debug(
          "Found&removed dangerous annotation link action, was {}", annotationLink.getAction());
      annotationLink.setAction(null);
      return;
    }
    LOGGER.trace("Keeping innocuous annotation link action ({})", annotationLink.getAction());
  }

  void sanitizeWidgetAnnotation(PDAnnotationWidget annotationWidget) {
    if (annotationWidget.getAction() != null) {
      if (actionBleach.sanitizeAction(annotationWidget.getAction(), "Annotation") == null) {
        LOGGER.debug(
            "Found&Removed dangerous action on annotation widget, was {}",
            annotationWidget.getAction());
        annotationWidget.setAction(null);
      }
    }
    sanitizeAnnotationActions(annotationWidget.getActions());
  }

  void sanitizeFileAttachmentAnnotation(PDAnnotationFileAttachment annotation) {
    try {
      if (annotation.getFile() == null) {
        return;
      }
    } catch (IOException e) {
      LOGGER.warn("Unable to read file attachment annotation", e);
      return;
    }
    COSDictionary fileSpec =
        annotation.getCOSObject().getCOSDictionary(COSName.getPDFName("FS"));
    if (fileSpec != null) {
      pdfBleachSession.getEmbeddedFileBleach().sanitizeFileSpecification(fileSpec);
    }
  }

  void sanitizeAnnotationActions(PDAnnotationAdditionalActions annotationAdditionalActions) {
    if (annotationAdditionalActions == null) {
      return;
    }
    actionBleach.sanitizeAdditionalActionsDictionary(
        annotationAdditionalActions.getCOSObject(), "Annotation");
  }

  void sanitizeAnnotation(PDAnnotation annotation) {
    if (annotation instanceof PDAnnotationLink) {
      sanitizeLinkAnnotation((PDAnnotationLink) annotation);
    }

    if (annotation instanceof PDAnnotationWidget) {
      sanitizeWidgetAnnotation((PDAnnotationWidget) annotation);
    }

    if (annotation instanceof PDAnnotationFileAttachment) {
      sanitizeFileAttachmentAnnotation((PDAnnotationFileAttachment) annotation);
    }
  }
}
