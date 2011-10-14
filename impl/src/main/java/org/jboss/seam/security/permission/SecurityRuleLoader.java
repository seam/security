package org.jboss.seam.security.permission;

import java.io.InputStream;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.drools.KnowledgeBase;
import org.drools.KnowledgeBaseConfiguration;
import org.drools.KnowledgeBaseFactory;
import org.drools.builder.KnowledgeBuilder;
import org.drools.builder.KnowledgeBuilderConfiguration;
import org.drools.builder.KnowledgeBuilderError;
import org.drools.builder.KnowledgeBuilderErrors;
import org.drools.builder.KnowledgeBuilderFactory;
import org.drools.builder.ResourceType;
import org.drools.io.ResourceFactory;
import org.jboss.solder.logging.Logger;
import org.jboss.solder.resourceLoader.Resource;

/**
 * Workaround until Drools has native CDI support
 *
 * @author Shane Bryzak
 */
@ApplicationScoped
public class SecurityRuleLoader {    
    @Inject Logger log;

    @Inject @Resource("security.drl") InputStream securityRules;

    @Inject @Resource("WEB-INF/security.drl") InputStream webInfSecurityRules;
    
    private KnowledgeBase kbase;
    
    public KnowledgeBase getKnowledgeBase() {
        return kbase;
    }

    @Inject
    public void init() {
        KnowledgeBuilderConfiguration config = KnowledgeBuilderFactory.newKnowledgeBuilderConfiguration();
        KnowledgeBaseConfiguration kBaseConfig = KnowledgeBaseFactory.newKnowledgeBaseConfiguration();

        KnowledgeBuilder kbuilder = KnowledgeBuilderFactory.newKnowledgeBuilder(config);

        InputStream rules = securityRules != null ? securityRules : webInfSecurityRules;
        
        if (rules != null) {
            org.drools.io.Resource resource = ResourceFactory.newInputStreamResource(rules);

            kbuilder.add(resource, ResourceType.DRL);
    
            KnowledgeBuilderErrors kbuildererrors = kbuilder.getErrors();
            if (kbuildererrors.size() > 0) {
                for (KnowledgeBuilderError kbuildererror : kbuildererrors) {
                    log.error(kbuildererror.getMessage());
                }
            }
    
            kbase = KnowledgeBaseFactory.newKnowledgeBase(kBaseConfig);
            kbase.addKnowledgePackages(kbuilder.getKnowledgePackages());
        } else {
            log.warn("No security rules configured - rule base permissions will be unavailable.");
        }
    }
}
