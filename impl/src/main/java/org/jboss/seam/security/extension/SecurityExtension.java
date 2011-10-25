package org.jboss.seam.security.extension;

import javax.enterprise.event.Observes;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.inject.spi.ProcessAnnotatedType;
import javax.inject.Inject;

import org.jboss.solder.logging.Logger;

/**
 * This class has been deprecated - please use org.jboss.seam.security.SecurityExtension instead.
 * 
 * @author Shane Bryzak
 *
 */
@Deprecated
public class SecurityExtension extends org.jboss.seam.security.SecurityExtension {
    
    private Logger log = Logger.getLogger(SecurityExtension.class);
    
    @Inject public void init() {
        log.warn("### WARNING ### - org.jboss.seam.security.extension.SecurityExtension is deprecated, " +
                 "please use org.jboss.seam.security.SecurityExtension instead.");        
    }
    
    public <X> void processAnnotatedType(@Observes ProcessAnnotatedType<X> event,
            final BeanManager beanManager) {
        super.processAnnotatedType(event, beanManager);
    }
}
