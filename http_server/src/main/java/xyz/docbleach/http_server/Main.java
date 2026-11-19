package xyz.docbleach.http_server;

import io.vertx.core.AbstractVerticle;
import io.vertx.core.AsyncResult;
import io.vertx.core.Promise;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.ext.web.FileUpload;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import xyz.docbleach.api.BleachSession;
import xyz.docbleach.api.bleach.DefaultBleach;
import xyz.docbleach.api.exception.BleachException;

public class Main extends AbstractVerticle {

  private static final Logger LOGGER = LoggerFactory.getLogger(Main.class);
  private static final long BODY_LIMIT = 1024 * 1024 * 150; // Size limit: 150MB

  private static int getPortNumber() {
    int port = 8080;
    String PORT = System.getenv("PORT");
    if (PORT != null && !PORT.isEmpty()) {
      try {
        port = Integer.valueOf(PORT);
      } catch (NumberFormatException e) {
        LOGGER.error("Invalid PORT defined in environment, falling back to 8080.");
      }
    }
    return port;
  }

  public void start() {
    HttpServer server = vertx.createHttpServer();
    Router router = Router.router(vertx);
    router.route().handler(BodyHandler.create().setBodyLimit(BODY_LIMIT));

    router
        .post("/sanitize")
        .handler(
            routingContext -> {
              Set<FileUpload> uploads = routingContext.fileUploads();
              if (uploads.isEmpty()) {
                routingContext.fail(404);
                return;
              }

              for (FileUpload upload : uploads) {
                LOGGER.info("FileName: {}", upload.fileName());
                if (!"file".equals(upload.name())) {
                  removeFiles(new File(upload.uploadedFileName()));
                  continue;
                }
                // @TODO: split into multiple methods

                LOGGER.info("UploadedFileName: {}", upload.fileName());

                vertx.executeBlocking(
                    (Handler<Promise<SanitizationResult>>)
                        promise -> {
                      BleachSession session = new BleachSession(new DefaultBleach());
                      try {
                        promise.complete(
                            new SanitizationResult(
                                session, sanitize(upload.uploadedFileName(), session)));
                      } catch (IOException | BleachException e) {
                        session.cancel();
                        removeFiles(new File(upload.uploadedFileName()));
                        LOGGER.error("Error", e);
                        promise.fail(e);
                      }
                    },
                    res -> {
                      if (!res.succeeded()) {
                        routingContext.fail(res.cause());
                        return;
                      }

                      final SanitizationResult result = res.result();
                      sendFile(
                          routingContext,
                          upload.fileName(),
                          result.getFile(),
                          __ -> {
                            removeFiles(new File(upload.uploadedFileName()));
                            // Closing the session atomically destroys its private temporary
                            // directory, including the sanitized file we just sent.
                            result.getSession().close();
                          });
                    });

                return;
              }
              // No "file" was found, we abort.
              routingContext.fail(404);
            });

    router
        .route()
        .handler(
            routingContext -> {
              HttpServerResponse response = routingContext.response();
              response.putHeader("content-type", "text/plain");
              response.end("Hello from the light DocBleach Server!");
            });

    server.requestHandler(router).listen(getPortNumber());
  }

  private void sendFile(
      RoutingContext routingContext,
      String fileName,
      File saneFile,
      Handler<AsyncResult<Void>> completionHandler) {
    HttpServerResponse response = routingContext.response();
    response.putHeader("Content-Description", "File Transfer");
    response.putHeader("Content-Type", "application/octet-stream");
    response.putHeader(
        "Content-Disposition", "attachment; filename=" + fileName); // @TODO: don't trust this name?
    response.putHeader("Content-Transfer-Encoding", "binary");
    response.putHeader("Expires", "0");
    response.putHeader("Pragma", "Public");
    response.putHeader("Cache-Control", "must-revalidate, post-check=0, pre-check=0");
    response.putHeader("Content-Length", "" + saneFile.length());

    response.sendFile(saneFile.getAbsolutePath(), completionHandler);
  }

  private void removeFiles(File... files) {
    vertx.executeBlocking(
        promise -> {
          for (File f : files) {
            if (!f.delete()) {
              LOGGER.warn("Could not delete file{} ", f.getAbsolutePath());
            }
          }
        },
        __ -> {
        });
  }

  private File sanitize(String uploadedFileName, BleachSession session)
      throws IOException, BleachException {
    File file = new File(uploadedFileName);

    try (InputStream is = new BufferedInputStream(new FileInputStream(file))) {
      File fstream = session.createTempFile("docbleach_", ".tmp");
      try (FileOutputStream os = new FileOutputStream(fstream)) {
        session.sanitize(is, os);
        LOGGER.info(
            "Sanitation for '{}': {} potential threats removed",
            uploadedFileName,
            session.threatCount());
      }
      return fstream;
    }
  }

  private static final class SanitizationResult {

    private final BleachSession session;
    private final File file;

    private SanitizationResult(BleachSession session, File file) {
      this.session = session;
      this.file = file;
    }

    private BleachSession getSession() {
      return session;
    }

    private File getFile() {
      return file;
    }
  }
}
