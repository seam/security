package org.jboss.seam.security.external.dialogues.api;

import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import javax.enterprise.context.NormalScope;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.METHOD;
import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

/**
 * <p>
 * Scope for a dialogue (flow) between the application and an external identity
 * provider or consumer.
 * </p>
 * <p/>
 * <p>
 * The protocols for sharing identity information (e.g. SAMLv2, OpenID) have
 * quite complex dialogues, that often rely on the user agent (browser) relaying
 * messages between the identity consumer and the identity producer. When the
 * application calls an API method of Seam's SAML or OpenID submodule, the
 * application will often temporary loose control over the browser. After a
 * number of redirects, the external authentication module uses the SPI to
 * inform the application about the outcome. At that moment, the application
 * re-gains control over the browser. This round trip is modeled as a
 * "dialogue", and the dialogue CDI scope is used to manage state that is bound
 * to the dialogue. Not only the identity sharing module uses it to maintain
 * state, also the application: it can save stuff in dialogue scope before the
 * API is called, and read the stuff back in when it is called back through the
 * SPI. For example, when the user opens a page that requires authentication,
 * the view can be stored in the dialogue scope before calling login() on the
 * API. When the SPI reports back that the login succeeded, the same dialogue
 * will be active, so that the application can easily inject the saved view and
 * redirect the user to it.
 * </p>
 * <p/>
 * <p>
 * The dialogue scope is not a passivating scope, so the contextual objects that
 * are saved in contexts of this scope do not have to be serializable. The
 * context is stored in a servlet context attribute.
 * </p>
 *
 * @author Marcel Kolsteren
 */
@Documented
@Retention(RUNTIME)
@Target({TYPE, METHOD, FIELD})
@NormalScope(passivating = false)
public @interface DialogueScoped {

}
