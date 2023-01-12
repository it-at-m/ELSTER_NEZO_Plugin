package de.muenchen.keycloak.custom.broker.saml;

import org.keycloak.Config;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.broker.saml.SAMLIdentityProviderConfig;
import org.keycloak.broker.saml.SAMLIdentityProviderFactory;
import org.keycloak.saml.validators.DestinationValidator;

/**
 * Richtet den angepassten ElsterIdentityProvider ein.
 *
 * @author Roland Werner
 */
public class ElsterIdentityProviderFactory extends SAMLIdentityProviderFactory {

    public static final String PROVIDER_ID = "ELSTER";
    
    private DestinationValidator destinationValidator;

    @Override
    public String getName() {
        return "ELSTER (custom SAML 2.0)";
    }

    @Override
    public ElsterIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new ElsterIdentityProvider(session, new SAMLIdentityProviderConfig(model), destinationValidator);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
    
    @Override
    public void init(Config.Scope config) {
        super.init(config);

        this.destinationValidator = DestinationValidator.forProtocolMap(config.getArray("knownProtocols"));
    }    

}
