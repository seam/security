#Seam Security Test Suite

##Running the testsuite on JBoss AS 7

    export JBOSS_HOME=/path/to/jboss-as-7.x
    mvn clean verify -Darquillian=jbossas-managed-7

##Running the testsuite on remote JBoss AS 7

Add `-Dsun.net.http.allowRestrictedHeaders=true` to server JAVA_OPTS before starting the server. This is required by the samlTest, as it spoofs hostnames.
    
    $JBOSS_HOME/bin/standalone.sh
    mvn clean verify -Darquillian=jbossas-remote-7

