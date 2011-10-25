package org.jboss.seam.security.externaltest.integration.client;

import java.io.File;
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
import org.jboss.shrinkwrap.api.importer.ZipImporter;
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
        		.loadReposFromPom("../external/pom.xml")
        		.artifact("org.jboss.solder:solder-impl")
                .artifact("org.jboss.seam.security:seam-security")
        		.artifact("org.openid4java:openid4java-consumer:pom").exclusion("xerces:xercesImpl")
        		.artifact("nekohtml:nekohtml")
        		.artifact("org.apache:xmlsec")
        		.artifact("commons-httpclient:commons-httpclient")
        		.resolveAs(GenericArchive.class));

        war.addAsLibraries(
            ShrinkWrap.create(ZipImporter.class, "seam-security-external.jar")
              .importFrom(new File("../external/target/seam-security-external.jar"))
              .as(JavaArchive.class));

        war.addAsWebInfResource("WEB-INF/" + entity + "-beans.xml", "beans.xml");
        war.addAsWebInfResource("WEB-INF/" + entity + "-seam-beans.xml", "classes/META-INF/seam-beans.xml");
        war.addAsWebInfResource("WEB-INF/context.xml", "context.xml");

        war.addPackage(MetaDataLoader.class.getPackage());
        if (entity.equals("sp")) {
            war.addPackage(SpCustomizer.class.getPackage());
            war.addAsWebInfResource("test_keystore.jks", "classes/test_keystore.jks");
        } else if (entity.equals("idp")) {
            war.addPackage(IdpCustomizer.class.getPackage());
            war.addAsWebInfResource("test_keystore.jks", "classes/test_keystore.jks");
        } else if (entity.equals("op")) {
            war.addPackage(OpCustomizer.class.getPackage());
        } else if (entity.equals("rp")) {
            war.addPackage(RpCustomizer.class.getPackage());
        }

        return war;
    }
}
