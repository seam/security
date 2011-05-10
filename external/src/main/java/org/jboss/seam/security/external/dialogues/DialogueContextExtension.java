package org.jboss.seam.security.external.dialogues;

import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.AfterBeanDiscovery;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.Extension;

/**
 * @author Marcel Kolsteren
 */
public class DialogueContextExtension implements Extension {
    private DialogueContext dialogueContext;

    public void afterBeanDiscovery(@Observes AfterBeanDiscovery event, BeanManager manager) {
        dialogueContext = new DialogueContext();
        event.addContext(dialogueContext);
    }

    public DialogueContext getDialogueContext() {
        return dialogueContext;
    }

}
