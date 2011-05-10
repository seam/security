package org.jboss.seam.security.external.dialogues;

import javax.inject.Inject;
import javax.interceptor.AroundInvoke;
import javax.interceptor.Interceptor;
import javax.interceptor.InvocationContext;

import org.jboss.seam.security.external.dialogues.api.DialogueManager;
import org.jboss.seam.security.external.dialogues.api.Dialogued;

/**
 * @author Marcel Kolsteren
 */
@Dialogued
@Interceptor
public class DialoguedInterceptor {
    @Inject
    private DialogueManager manager;

    @AroundInvoke
    public Object intercept(InvocationContext ctx) throws Exception {
        boolean joined;
        Object result;
        boolean join = ctx.getMethod().getAnnotation(Dialogued.class).join();

        if (!join || !manager.isAttached()) {
            manager.beginDialogue();
            joined = false;
        } else {
            joined = true;
        }

        try {
            result = ctx.proceed();
        } catch (Exception e) {
            if (!joined) {
                manager.detachDialogue();
            }
            throw (e);
        }

        if (!joined) {
            manager.detachDialogue();
        }

        return result;
    }
}
