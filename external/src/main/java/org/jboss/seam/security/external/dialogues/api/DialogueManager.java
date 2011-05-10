package org.jboss.seam.security.external.dialogues.api;

/**
 * Manager for the dialogue scope. For background about the dialogue scope, see
 * {@link DialogueScoped}.
 *
 * @author Marcel Kolsteren
 */
public interface DialogueManager {
    /**
     * Starts a new dialogue. Results in a {@link RuntimeException} if
     * {@link #isAttached} is true.
     */
    void beginDialogue();

    /**
     * Ends the current dialogue. Results in a {@link RuntimeException} if
     * {@link #isAttached} is false.
     */
    void endDialogue();

    /**
     * Checks whether a dialogue exists with the given id.
     *
     * @param dialogueId the id
     * @return true if a dialogue with that id exists
     */
    boolean isExistingDialogue(String dialogueId);

    /**
     * Checks whether the current thread is attached to a dialogue (i.e. whether
     * a dialogue is currently active)
     *
     * @return true if the current thread is attached to a dialogue
     */
    boolean isAttached();

    /**
     * Attaches the current thread to the given dialogue. Results in a
     * {@link RuntimeException} if the thread is already attached to a dialogue,
     * i.e. if {@link #isAttached} is true.
     *
     * @param dialogueId
     */
    void attachDialogue(String dialogueId);

    /**
     * Detaches the current thread from the dialogue. Results in a
     * {@link RuntimeException} if {@link #isAttached} is false.
     */
    void detachDialogue();
}
