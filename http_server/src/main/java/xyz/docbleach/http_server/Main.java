package xyz.docbleach.http_server;

import io.vertx.core.AbstractVerticle;
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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
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
    BodyHandler bodyHandler = BodyHandler.create().setBodyLimit(BODY_LIMIT);
    String uploadsDirectory = createPrivateUploadsDirectory();
    if (uploadsDirectory != null) {
      bodyHandler.setUploadsDirectory(uploadsDirectory);
    }
    router.route().handler(bodyHandler);

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
                    (Handler<Promise<SanitizeResult>>)
                        promise -> {
                      BleachSession session = new BleachSession(new DefaultBleach());
                      try {
                        promise.complete(sanitize(session, upload.uploadedFileName()));
                      } catch (Exception e) {
                        LOGGER.error("Error", e);
                        session.close();
                        promise.fail(e);
                      }
                    },
                    res -> {
                      File uploadedFile = new File(upload.uploadedFileName());
                      if (!res.succeeded()) {
                        removeFiles(uploadedFile);
                        routingContext.fail(res.cause());
                        return;
                      }

                      final SanitizeResult result = res.result();
                      AtomicBoolean cleaned = new AtomicBoolean();
                      Runnable cleanup =
                          () -> {
                            if (cleaned.compareAndSet(false, true)) {
                              result.session.close();
                              removeFiles(uploadedFile);
                            }
                          };
                      // If the client disconnects or the request times out, make sure the
                      // temporary resources are still removed.
                      routingContext.response().closeHandler(__ -> cleanup.run());
                      sendFile(routingContext, upload.fileName(), result.saneFile, cleanup);
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
      RoutingContext routingContext, String fileName, File saneFile, Runnable onSent) {
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

    response.sendFile(saneFile.getAbsolutePath(), __ -> onSent.run());
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

  private SanitizeResult sanitize(BleachSession session, String uploadedFileName)
      throws IOException, BleachException {
    File file = new File(uploadedFileName);

    try (InputStream is = new BufferedInputStream(new FileInputStream(file))) {
      Path fstream = session.createTempFile("docbleach_", "");
      try (OutputStream os = Files.newOutputStream(fstream)) {
        session.sanitize(is, os);
        LOGGER.info(
            "Sanitation for '{}': {} potential threats removed",
            uploadedFileName,
            session.threatCount());
      }
      return new SanitizeResult(session, fstream.toFile());
    }
  }

  /**
   * Creates the directory receiving the uploaded files, only accessible by the current user so
   * other tenants cannot read another tenant's documents.
   */
  private static String createPrivateUploadsDirectory() {
    try {
      try {
        return Files.createTempDirectory(
                "docbleach-uploads-",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            .toString();
      } catch (UnsupportedOperationException e) {
        // Non-POSIX file system: the default permissions are the best we can get
        return Files.createTempDirectory("docbleach-uploads-").toString();
      }
    } catch (IOException e) {
      LOGGER.warn("Could not create a private uploads directory, using the default one", e);
      return null;
    }
  }

  private static final class SanitizeResult {

    private final BleachSession session;
    private final File saneFile;

    private SanitizeResult(BleachSession session, File saneFile) {
      this.session = session;
      this.saneFile = saneFile;
    }
  }
}
