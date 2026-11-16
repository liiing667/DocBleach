package xyz.docbleach.api;

import java.io.InputStream;
import java.io.OutputStream;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import xyz.docbleach.api.budget.ResourceBudget;
import xyz.docbleach.api.budget.ResourceBudgetExceededException;
import xyz.docbleach.api.bleach.Bleach;
import xyz.docbleach.api.exception.BleachException;
import xyz.docbleach.api.threat.Threat;
import xyz.docbleach.api.util.StreamUtils;

/**
 * A Bleach Session handles the data a bleach needs to store: list of the threats removed, for
 * instance May be used in the future to store configuration (file's password, for instance) or
 * callbacks
 */
public class BleachSession implements Serializable {

  private static final Logger LOGGER = LoggerFactory.getLogger(BleachSession.class);
  private final transient Bleach bleach;
  private final Collection<Threat> threats = new ArrayList<>();
  /**
   * Shared resource budget of the whole sanitation chain. Transient: a budget is only meaningful
   * for the lifetime of a sanitation, and its counters / layer stack are not serializable state.
   */
  private final transient ResourceBudget budget;

  public BleachSession(Bleach bleach) {
    this.bleach = bleach;
    this.budget = new ResourceBudget(this::recordThreat);
  }

  public BleachSession(Bleach bleach, ResourceBudget budget) {
    this.bleach = bleach;
    this.budget = budget;
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
   * @return the resource budget shared by every bleach of this session's sanitation chain
   */
  public ResourceBudget getBudget() {
    return budget;
  }

  public void pushBudgetLayer(String layer) throws ResourceBudgetExceededException {
    budget.pushLayer(layer);
  }

  public void popBudgetLayer() {
    budget.popLayer();
  }

  public void accountBudgetedBytes(long bytes) throws ResourceBudgetExceededException {
    budget.accountBytes(bytes);
  }

  public void accountBudgetedEntry() throws ResourceBudgetExceededException {
    budget.accountEntry();
  }

  public void checkBudgetTime() throws ResourceBudgetExceededException {
    budget.checkTime();
  }

  public void sanitize(InputStream is, OutputStream os) throws BleachException {
    if (!bleach.handlesMagic(is)) {
      // No bleach can handle this content: pass it through untouched instead of dropping it,
      // otherwise ordinary entries of nested containers would silently come out empty.
      try {
        StreamUtils.copy(is, os);
      } catch (java.io.IOException e) {
        throw new BleachException(e);
      }
      return;
    }
    bleach.sanitize(is, os, this);
  }
}
