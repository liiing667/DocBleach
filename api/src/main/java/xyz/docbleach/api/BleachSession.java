package xyz.docbleach.api;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.stream.Stream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import xyz.docbleach.api.bleach.Bleach;
import xyz.docbleach.api.exception.BleachException;
import xyz.docbleach.api.exception.RecursionBleachException;
import xyz.docbleach.api.threat.Threat;

/**
 * A Bleach Session handles the data a bleach needs to store: list of the threats removed, for
 * instance May be used in the future to store configuration (file's password, for instance) or
 * callbacks
 */
public class BleachSession implements Serializable, AutoCloseable {

  private static final Logger LOGGER = LoggerFactory.getLogger(BleachSession.class);
  private static final int MAX_ONGOING_TASKS = 10;
  private final transient Bleach bleach;
  private final Collection<Threat> threats = new ArrayList<>();
  /**
   * Private temporary directory, only accessible by the current user. Every temporary resource
   * used by this session lives inside it, and it is deleted when the session is closed.
   */
  private transient Path tempDirectory;
  /**
   * Counts ongoing tasks, to prevent fork bombs when handling zip archives for instance)
   */
  private int ongoingTasks = 0;

  public BleachSession(Bleach bleach) {
    this.bleach = bleach;
  }

  /**
   * The BleachSession is able to record threats encountered by the bleach.
   *
   * @param threat The removed threat object, containing the threat type and more information
   */
  public void recordThreat(Threat threat) {
    if (threat == null) {
      return;
    }
    LOGGER.trace("Threat recorded: " + threat);
    threats.add(threat);
  }

  public Collection<Threat> getThreats() {
    return threats;
  }

  public int threatCount() {
    return threats.size();
  }

  /**
   * @return The bleach used in this session
   */
  public Bleach getBleach() {
    return bleach;
  }

  public void sanitize(InputStream is, OutputStream os) throws BleachException {
    try {
      if (ongoingTasks++ >= MAX_ONGOING_TASKS) {
        throw new RecursionBleachException(ongoingTasks);
      }
      if (!bleach.handlesMagic(is)) {
        return;
      }
      bleach.sanitize(is, os, this);
    } finally {
      ongoingTasks--;
    }
  }

  /**
   * Returns this session's private temporary directory, creating it on first use. The directory
   * is only readable/writable by the current user, so other tenants cannot list or read the
   * files stored inside.
   *
   * @return the session's private temporary directory
   */
  public synchronized Path getTempDirectory() throws BleachException {
    if (tempDirectory == null) {
      tempDirectory = createPrivateTempDirectory();
    }
    return tempDirectory;
  }

  /**
   * Creates a temporary file inside this session's private directory. The file is unique to this
   * call, so retries never write to a path used by a previous attempt, and it is removed when
   * the session is closed.
   */
  public Path createTempFile(String prefix, String suffix) throws BleachException {
    try {
      return Files.createTempFile(getTempDirectory(), prefix, suffix);
    } catch (IOException e) {
      throw new BleachException(e);
    }
  }

  private static Path createPrivateTempDirectory() throws BleachException {
    try {
      try {
        return Files.createTempDirectory(
            "docbleach-session-",
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
      } catch (UnsupportedOperationException e) {
        // Non-POSIX file system: the default permissions are the best we can get
        return Files.createTempDirectory("docbleach-session-");
      }
    } catch (IOException e) {
      throw new BleachException(e);
    }
  }

  /**
   * Deletes this session's temporary directory and everything it contains. Meant to be called
   * once the session is over, whatever the outcome was; calling it more than once is harmless.
   */
  @Override
  public synchronized void close() {
    if (tempDirectory == null) {
      return;
    }
    Path directory = tempDirectory;
    tempDirectory = null;
    deleteRecursively(directory);
  }

  private static void deleteRecursively(Path root) {
    try (Stream<Path> walk = Files.walk(root)) {
      walk.sorted(Comparator.reverseOrder())
          .forEach(
              path -> {
                try {
                  Files.deleteIfExists(path);
                } catch (IOException e) {
                  LOGGER.warn("Could not delete temporary file {}", path, e);
                }
              });
    } catch (IOException e) {
      LOGGER.warn("Could not clean temporary directory {}", root, e);
    }
  }
}
