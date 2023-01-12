package de.muenchen.keycloak.custom.broker.saml.mappers;

import de.muenchen.keycloak.custom.broker.saml.ElsterIdentityProviderFactory;
import org.keycloak.broker.saml.mappers.UserAttributeMapper;

/**
 * Diese Klasse wird benötigt, damit auf jeden Fall ein User-Attribute-Mapper zur Verfügung steht.
 *
 * @author Roland Werner
 */
public class ElsterUserAttributeMapper extends UserAttributeMapper {

    public static final String[] COMPATIBLE_PROVIDERS = {ElsterIdentityProviderFactory.PROVIDER_ID};
    public static final String PROVIDER_ID = "elster-saml-user-attribute-idp-mapper";

    @Override
    public String getDisplayCategory() {
        return "CUSTOM Attribute Importer";
    }

    @Override
    public String getDisplayType() {
        return "ELSTER Attribute Importer";
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
