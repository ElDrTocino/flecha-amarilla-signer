package org.flechaamarilla.rest;

import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import org.flechaamarilla.service.SignerService;
import org.jboss.logging.Logger;

/**
 * REST endpoint for XML signing
 * 
 * TODO: Change language convention to English in future refactorings
 */
@Path("/api/signer")
@Produces(MediaType.TEXT_PLAIN)
@Consumes(MediaType.TEXT_PLAIN)
public class SignerController {
    
    private static final Logger LOG = Logger.getLogger(SignerController.class);
    
    @Inject
    SignerService signerService;
    
    /**
     * Signs an XML document with the configured CSD
     */
    @POST
    @Path("/sign")
    public String signXml(String xmlContent) {
        LOG.info("Received signing request");
        
        // Añadimos registro para depuración
        if (xmlContent == null || xmlContent.trim().isEmpty()) {
            LOG.error("XML content received is null or empty");
            return "ERROR: XML content is null or empty";
        }
        
        LOG.info("XML Content length: " + xmlContent.length());
        
        try {
            // Sign the XML
            String signedXml = signerService.signXml(xmlContent);
            LOG.info("XML signing successful");
            return signedXml;
        } catch (Exception e) {
            LOG.error("Error during XML signing", e);
            return "ERROR: " + e.getMessage();
        }
    }
}