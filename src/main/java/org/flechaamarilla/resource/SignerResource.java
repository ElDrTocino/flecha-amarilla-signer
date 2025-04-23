package org.flechaamarilla.resource;


import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.flechaamarilla.service.SignerService;

@Path("/signXml")
@Consumes(MediaType.TEXT_PLAIN)
@Produces(MediaType.APPLICATION_XML)
public class SignerResource {

    @Inject
    SignerService signerService;

    @POST
    public Response signXml(String xml) {
        try {
            String signed = signerService.signXml(xml);
            return Response.ok(signed).build();
        } catch (Exception e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("Error al sellar XML: " + e.getMessage())
                    .build();
        }
    }
}