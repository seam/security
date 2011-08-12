package org.jboss.seam.security.externaltest.integration.client;

import java.util.HashMap;
import java.util.Map;

import javax.enterprise.inject.spi.Extension;

import org.jboss.seam.security.external.ResponseHandler;
import org.jboss.seam.security.external.dialogues.DialogueContextExtension;
import org.jboss.seam.security.external.virtualapplications.VirtualApplicationContextExtension;
import org.jboss.seam.security.externaltest.integration.MetaDataLoader;
import org.jboss.seam.security.externaltest.integration.openid.op.OpCustomizer;
import org.jboss.seam.security.externaltest.integration.openid.rp.RpCustomizer;
import org.jboss.seam.security.externaltest.integration.saml.idp.IdpCustomizer;
import org.jboss.seam.security.externaltest.integration.saml.sp.SpCustomizer;
import org.jboss.shrinkwrap.api.GenericArchive;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.jboss.shrinkwrap.resolver.api.DependencyResolvers;
import org.jboss.shrinkwrap.resolver.api.maven.MavenDependencyResolver;

class ArchiveBuilder {
    static WebArchive idpArchive;

    static WebArchive spArchive;

    static Map<String, WebArchive> webArchives = new HashMap<String, WebArchive>();

    static WebArchive getArchive(String entity) {
        WebArchive webArchive = webArchives.get(entity);
        if (webArchive == null) {
            webArchive = createTestArchive(entity);
            webArchives.put(entity, webArchive);
        }
        return webArchive;
    }

    static private WebArchive createTestArchive(String entity) {
        WebArchive war = ShrinkWrap.create(WebArchive.class, entity + ".war");

        war.addAsLibraries(DependencyResolvers.use(MavenDependencyResolver.class)
        		.loadReposFromPom("pom.xml")
        		.artifact("org.jboss.seam.security:seam-security")
        		.artifact("org.jboss.seam.servlet:seam-servlet")
        		.artifact("org.jboss.seam.solder:seam-solder")
        		.artifact("org.jboss.seam.config:seam-config-xml")
        		.artifact("org.openid4java:openid4java-consumer:pom").exclusion("xerces:xercesImpl")
        		.artifact("nekohtml:nekohtml")
        		.artifact("org.apache:xmlsec")
        		.artifact("commons-httpclient:commons-httpclient")
        		.resolveAs(GenericArchive.class));

        war.addAsWebInfResource("WEB-INF/" + entity + "-beans.xml", "beans.xml");
        war.addAsWebInfResource("WEB-INF/" + entity + "-seam-beans.xml", "classes/META-INF/seam-beans.xml");
        war.addAsWebInfResource("WEB-INF/context.xml", "context.xml");

        war.addPackage(MetaDataLoader.class.getPackage());
        if (entity.equals("sp")) {
            war.addPackage(SpCustomizer.class.getPackage());
            war.addAsWebInfResource("test_keystore.jks");
        } else if (entity.equals("idp")) {
            war.addPackage(IdpCustomizer.class.getPackage());
            war.addAsWebInfResource("test_keystore.jks");
        } else if (entity.equals("op")) {
            war.addPackage(OpCustomizer.class.getPackage());
        } else if (entity.equals("rp")) {
            war.addPackage(RpCustomizer.class.getPackage());
        }

        war.addAsLibrary(createJarModule());

        return war;
    }

    private static JavaArchive createJarModule() {
        JavaArchive jar = ShrinkWrap.create(JavaArchive.class, "test.jar");

        // Add the package "org.jboss.seam.security.external" and all its
        // subpackages.
        jar.addPackages(true, ResponseHandler.class.getPackage());

        jar.addAsManifestResource("META-INF/beans.xml", "beans.xml");
        jar.addAsManifestResource("META-INF/web-fragment.xml", "web-fragment.xml");
        jar.addAsServiceProvider(Extension.class, VirtualApplicationContextExtension.class, DialogueContextExtension.class);

        return jar;
    }
}
