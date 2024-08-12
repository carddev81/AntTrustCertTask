package com.omo.free.trustcert;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Task;

import com.omo.free.security.ssl.TrustedCertficatesStore;

/**
 * This class handles the trust certificate process consisting of:
 * <ol>
 * <li>Create local directory</li>
 * <li>Export ALL certificates from keystore of JVM to local directory</li>
 * <li>Make call to {@code secureUrl} and export certificate chain from the call</li>
 * <li>Add certificate to local keystore</li>
 * <li>Set location to the local keystore to the {@code javax.net.ssl.trustStore} property</li>
 * </ol>
 *
 * @author Richard Salas, JCCC October 10, 2023
 */
public class TrustCertTask extends Task {

    private String secureUrl;//REQUIRED
    private String keystoreDir = ".";//OPTIONAL
    private boolean verbose;//OPTIONAL
    private boolean fail = true;//OPTIONAL

    /**
     * Called by the project to let the task initialize properly. The default implementation is a no-op.
     *
     * @Throws: BuildException - if something goes wrong with the build
     */
    @Override public void init() {
        super.init();
    }//end method

    /**
     * Called by the project to let the task do its work. This method may be called more than once, if the task is invoked more than once. For example, if target1 and target2 both depend on target3, then running "ant target1 target2" will run all tasks in target3 twice.
     *
     * @Throws BuildException - if something goes wrong with the build
     */
    @Override public void execute() throws BuildException {
        super.execute();

        //executing the tortoise patch
        vlog("Starting Trust Certficate task");

        initRequiredAttributes();
        trustCertificate();

        vlog("Ending Trust Certficate task");
    }//end method

    /**
     * Attempts to create directory that will be housed with the certificates exported from the currently running JVM along with the {@code secureUrl}'s certificate chain.
     */
    private void trustCertificate() {
        try{
            vlog("Adding certifcate to keystore from the following url: " + String.valueOf(secureUrl) + ".");
            new TrustedCertficatesStore(this.keystoreDir, this.secureUrl);
            vlog("Certifcate processing completed succesfully.");
        }catch(Exception e){
            vlog(">>>> ERROR  Could not add the certificate to keystore due to an exception. Error message: " + e.getMessage());
            if(fail){
                throw new BuildException("Could not extract the certificate from the certificate chain returned from the url " + String.valueOf(secureUrl) + ".  Please verify that this url exists. If it does exist then, please inform a known ant developer to find out how to encrypt your values.");
            }//end if
        }//end try...catch
    }//end method

    /**
     * Checking to see if this tasks required attribute is being utilized. If not a Build Exception will be thrown alerting the builder of a possible exception.
     *
     * @throws BuildException
     *         exception thrown when trying to initialize the value of the required field.
     */
    private void initRequiredAttributes() throws BuildException {
        vlog("Initializing the required attribute... secureUrl");

        if(this.secureUrl == null){
            throw new BuildException("Error!!! You didn't specify a 'secureUrl' name for the trustcert task!!!");
        }//end if

        vlog("The required attribute has been succesfully initialized");
    }//end method

    /**
     * Sets the secure URL that a certificate will be attempted to exported from so that any calls to it will be trusted.
     *
     * @param secureUrl the url to trust
     */
    public void setSecureUrl(String secureUrl){
        this.secureUrl = secureUrl;
    }//end method


    /**
     * sets verbose attribute
     *
     * @param verbose true or false value
     */
    public void setVerbose(boolean verbose) {
        this.verbose = verbose;
    }//end method

    /**
     * logs verbose messages
     *
     * @param msg
     */
    protected final void vlog(String msg) {
        if(this.verbose){
            log(msg);
        }//end if
    }//end method

    /**
     * sets whether to decrypt or not
     * @param decrypt true or false value
     */
    public void setFailOnError(boolean failonerror){
        this.fail = failonerror;
    }//end method

    /**
     * @param keystoreDir the keystoreDir to set
     */
    public void setKeystoreDir(String keystoreDir) {
        this.keystoreDir = keystoreDir;
    }//end method

}//end class
