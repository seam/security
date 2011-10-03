package org.jboss.seam.security.external.dialogues;

import javax.enterprise.event.Observes;
import javax.enterprise.inject.Instance;
import javax.inject.Inject;
import javax.servlet.ServletContext;

import org.jboss.seam.security.external.dialogues.api.DialogueManager;
import org.jboss.solder.servlet.event.Destroyed;
import org.jboss.solder.servlet.event.Initialized;

/**
 * @author Marcel Kolsteren
 */
public class DialogueManagerBean implements DialogueManager {
    @Inject
    private DialogueContextExtension dialogueContextExtension;

    @Inject
    private Instance<DialogueBean> dialogue;

    public void servletInitialized(@Observes @Initialized final ServletContext context) {
        dialogueContextExtension.getDialogueContext().initialize(context);
    }

    public void servletDestroyed(@Observes @Destroyed final ServletContext context) {
        dialogueContextExtension.getDialogueContext().destroy();
    }

    public void beginDialogue() {
        String dialogueId = dialogueContextExtension.getDialogueContext().create();
        dialogue.get().setId(dialogueId);
    }

    public void endDialogue() {
        dialogueContextExtension.getDialogueContext().remove();
    }

    public void attachDialogue(String requestId) {
        dialogueContextExtension.getDialogueContext().attach(requestId);
    }

    public void detachDialogue() {
        if (dialogue.get().isFinished()) {
            endDialogue();
        } else {
            dialogueContextExtension.getDialogueContext().detach();
        }
    }

    public boolean isExistingDialogue(String dialogueId) {
        return dialogueContextExtension.getDialogueContext().isExistingDialogue(dialogueId);
    }

    public boolean isAttached() {
        return dialogueContextExtension.getDialogueContext().isAttached();
    }
}
