package org.jboss.seam.security.external.dialogues;

import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.BeanManager;
import javax.servlet.ServletContext;

import org.jboss.seam.security.external.dialogues.api.Dialogue;
import org.jboss.seam.security.external.dialogues.api.DialogueManager;
import org.jboss.solder.beanManager.BeanManagerLocator;

/**
 * Provides dialogue beans to classes that are not able to inject.
 *
 * @author Marcel Kolsteren
 */
public class DialogueBeanProvider {
    public static Dialogue dialogue(ServletContext servletContext) {
        BeanManager beanManager = new BeanManagerLocator().getBeanManager();
        Bean<?> bean = beanManager.resolve(beanManager.getBeans(Dialogue.class));
        return (Dialogue) beanManager.getReference(bean, Dialogue.class, beanManager.createCreationalContext(bean));
    }

    public static DialogueManager dialogueManager(ServletContext servletContext) {
        BeanManager beanManager = new BeanManagerLocator().getBeanManager();
        Bean<?> bean = beanManager.resolve(beanManager.getBeans(DialogueManager.class));
        return (DialogueManager) beanManager.getReference(bean, DialogueManager.class, beanManager.createCreationalContext(bean));
    }
}
