package org.jboss.seam.security.permission;

import java.io.InputStream;

import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.inject.Produces;
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
import org.jboss.logging.Logger;
import org.jboss.seam.security.qualifiers.Security;
import org.jboss.seam.solder.resourceLoader.Resource;

/**
 * Workaround until we have a seam-drools release
 *
 * @author Shane Bryzak
 */
public class SecurityRuleProducer {
    private static final Logger log = Logger.getLogger(SecurityRuleProducer.class);

    @Inject
    @Resource("security.drl")
    InputStream securityRules;

    @Produces
    @ApplicationScoped
    @Security
    public KnowledgeBase createSecurityKnowledgeBase() {
        KnowledgeBuilderConfiguration config = KnowledgeBuilderFactory.newKnowledgeBuilderConfiguration();
        KnowledgeBaseConfiguration kBaseConfig = KnowledgeBaseFactory.newKnowledgeBaseConfiguration();

        KnowledgeBuilder kbuilder = KnowledgeBuilderFactory.newKnowledgeBuilder(config);

        org.drools.io.Resource resource = ResourceFactory.newInputStreamResource(securityRules);
        kbuilder.add(resource, ResourceType.DRL);

        KnowledgeBuilderErrors kbuildererrors = kbuilder.getErrors();
        if (kbuildererrors.size() > 0) {
            for (KnowledgeBuilderError kbuildererror : kbuildererrors) {
                log.error(kbuildererror.getMessage());
            }
        }

        KnowledgeBase kbase = KnowledgeBaseFactory.newKnowledgeBase(kBaseConfig);
        kbase.addKnowledgePackages(kbuilder.getKnowledgePackages());

        return kbase;
    }
}
