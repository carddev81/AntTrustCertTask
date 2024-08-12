package com.omo.tools.ant.main;

import java.io.File;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.DefaultLogger;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.ProjectHelper;

/**
 * This class handles testing of the the Ant Trust Cert task.
 * 
 * @author Richard Salas JCCC 12 years ago
 */
public class Application {

    /**
     * This main method will run an ant script (projectTestFile.xml) programmatically. This is just for testing purposes (figured someone could use this in the future)
     * 
     * @param args
     *        - arguments that may be passed into the jvm...
     */
    public static void main(final String[] args) {
        File buildFile = new File("projectTestFile.xml");
        Project p = new Project();
        p.setUserProperty("ant.file", buildFile.getAbsolutePath()); // this is required as this tells ant where the file is located when being
                                                                    // ran
        // set logger up...
        DefaultLogger logger = new DefaultLogger();
        logger.setErrorPrintStream(System.err);
        logger.setOutputPrintStream(System.out);
        logger.setMessageOutputLevel(Project.MSG_VERBOSE);
        p.addBuildListener(logger);

        try{
            p.fireBuildStarted(); // build starting message to build listener/logger
            p.init();
            ProjectHelper helper = ProjectHelper.getProjectHelper();
            p.addReference("ant.projectHelper", helper);
            helper.parse(p, buildFile);
            p.executeTarget(p.getDefaultTarget());
            p.fireBuildFinished(null); // build ending message to build listener/logger
        }catch(BuildException e){
            p.fireBuildFinished(e);
        }//end try...catch
    }//end method

}//end class
