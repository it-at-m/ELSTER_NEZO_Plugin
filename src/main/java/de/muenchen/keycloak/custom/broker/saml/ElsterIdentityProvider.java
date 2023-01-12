package de.muenchen.keycloak.custom.broker.saml;

import org.jboss.logging.Logger;
import org.keycloak.broker.saml.SAMLIdentityProvider;
import org.keycloak.broker.saml.SAMLIdentityProviderConfig;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.saml.validators.DestinationValidator;

/**
 * Abgeleitet von SAMLIdentityProvider. Hierdurch wird sichergestellt, dass im ElsterIdentityProvider der angepasste
 * CustomSAMLEndpoint eingesetzt wird.
 *
 * @author Roland Werner
 */
public class ElsterIdentityProvider extends SAMLIdentityProvider {

    private final DestinationValidator destinationValidator;

    protected static final Logger logger = Logger.getLogger(ElsterIdentityProvider.class);

    public ElsterIdentityProvider(KeycloakSession session, SAMLIdentityProviderConfig config, DestinationValidator destinationValidator) {
        super(session, config, destinationValidator);
        this.destinationValidator = destinationValidator;

    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new CustomSAMLEndpoint(realm, this, getConfig(), callback, destinationValidator);
    }

}
