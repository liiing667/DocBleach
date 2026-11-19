package xyz.docbleach.api;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Collection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import xyz.docbleach.api.bleach.Bleach;
import xyz.docbleach.api.exception.BleachException;
import xyz.docbleach.api.exception.RecursionBleachException;
import xyz.docbleach.api.exception.SessionCancelledException;
import xyz.docbleach.api.threat.Threat;

/**
 * A Bleach Session handles the data a bleach needs to store: list of the threats removed, for
 * instance May be used in the future to store configuration (file's password, for instance) or
 * callbacks
 *
 * <p>The session is the security boundary of a sanitation: it exclusively owns a private
 * temporary directory, created on demand, where bleaches may store intermediate (plaintext)
 * files. Cancelling the session is terminal and atomically destroys these resources, so a
 * cancelled session's data can never leak into a subsequent session. A failed {@link
 * #sanitize(InputStream, OutputStream)} call may be retried on the same live session; each
 * attempt keeps using this session's private resources.
 */
public class BleachSession implements Serializable, AutoCloseable {

  private static final Logger LOGGER = LoggerFactory.getLogger(BleachSession.class);
  private static final int MAX_ONGOING_TASKS = 10;
  private static final String TEMP_DIR_PREFIX = "docbleach-session-";
  private static final FileAttribute<?>[] PRIVATE_DIR_ATTRIBUTES = posixAttributes("rwx------");
  private static final FileAttribute<?>[] PRIVATE_FILE_ATTRIBUTES = posixAttributes("rw-------");

  private final transient Bleach bleach;
  private final Collection<Threat> threats = new ArrayList<>();
  /**
   * Counts ongoing tasks, to prevent fork bombs when handling zip archives for instance)
   */
  private int ongoingTasks = 0;

  /**
   * Guards the session's lifecycle (temporary directory and cancellation), so cleanup is atomic
   * with regards to concurrent resource creation.
   */
  private transient Object lifecycleLock = new Object();

  private transient Path temporaryDirectory;
  private transient boolean cancelled = false;

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

  /**
   * Returns this session's private temporary directory, creating it on first use. The directory
   * is exclusive to this session (owner-only permissions when the filesystem supports it) and is
   * destroyed by {@link #cancel()}.
   *
   * @return the session-private temporary directory
   * @throws SessionCancelledException if the session has been cancelled
   * @throws BleachException if the directory cannot be created
   */
  public Path getTemporaryDirectory() throws BleachException {
    synchronized (lifecycleLock) {
      ensureActive();
      if (temporaryDirectory == null) {
        try {
          temporaryDirectory = createPrivateTempDirectory();
        } catch (IOException e) {
          throw new BleachException(e);
        }
      }
      return temporaryDirectory;
    }
  }

  /**
   * Creates a uniquely-named, owner-only temporary file inside this session's private temporary
   * directory. Retrying a failed sanitation therefore never reuses a previous attempt's file.
   *
   * @param prefix the file name's prefix, at least 3 characters long
   * @param suffix the file name's suffix, may be null
   * @return the newly created temporary file
   * @throws SessionCancelledException if the session has been cancelled
   * @throws BleachException if the file cannot be created
   */
  public File createTempFile(String prefix, String suffix) throws BleachException {
    synchronized (lifecycleLock) {
      Path directory = getTemporaryDirectory();
      try {
        return Files.createTempFile(directory, prefix, suffix, PRIVATE_FILE_ATTRIBUTES).toFile();
      } catch (IOException e) {
        throw new BleachException(e);
      }
    }
  }

  /**
   * Cancels this session and atomically destroys its private resources. Cancellation is
   * terminal: any further use of the session fails with {@link SessionCancelledException}, and
   * the session's temporary files can never be read back by this or any subsequent session.
   */
  public void cancel() {
    Path directoryToDelete;
    synchronized (lifecycleLock) {
      if (cancelled) {
        return;
      }
      cancelled = true;
      directoryToDelete = temporaryDirectory;
      temporaryDirectory = null;
    }
    deleteTree(directoryToDelete);
  }

  /**
   * @return true once this session has been cancelled
   */
  public boolean isCancelled() {
    synchronized (lifecycleLock) {
      return cancelled;
    }
  }

  /**
   * Closing a session cancels it, destroying its private resources.
   */
  @Override
  public void close() {
    cancel();
  }

  public void sanitize(InputStream is, OutputStream os) throws BleachException {
    ensureActive();
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

  private void ensureActive() throws SessionCancelledException {
    synchronized (lifecycleLock) {
      if (cancelled) {
        throw new SessionCancelledException();
      }
    }
  }

  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    lifecycleLock = new Object();
  }

  private static Path createPrivateTempDirectory() throws IOException {
    try {
      return Files.createTempDirectory(TEMP_DIR_PREFIX, PRIVATE_DIR_ATTRIBUTES);
    } catch (UnsupportedOperationException e) {
      // Non-POSIX filesystem: the directory is still uniquely named per session
      return Files.createTempDirectory(TEMP_DIR_PREFIX);
    }
  }

  private static FileAttribute<?>[] posixAttributes(String permissions) {
    try {
      return new FileAttribute<?>[]{
          PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString(permissions))
      };
    } catch (UnsupportedOperationException e) {
      return new FileAttribute<?>[0];
    }
  }

  private static void deleteTree(Path root) {
    if (root == null) {
      return;
    }
    try {
      Files.walkFileTree(
          root,
          new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs)
                throws IOException {
              Files.deleteIfExists(file);
              return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult postVisitDirectory(Path dir, IOException exc)
                throws IOException {
              Files.deleteIfExists(dir);
              return FileVisitResult.CONTINUE;
            }
          });
    } catch (IOException e) {
      LOGGER.warn("Could not fully delete the session's temporary directory {}", root, e);
    }
  }
}
