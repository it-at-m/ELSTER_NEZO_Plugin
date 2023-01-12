package de.muenchen.keycloak.custom.broker.saml;

import org.jboss.logging.Logger;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.saml.SAMLEndpoint;
import org.keycloak.broker.saml.SAMLIdentityProvider;
import org.keycloak.broker.saml.SAMLIdentityProviderConfig;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.EncryptedElementType;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.assertion.SubjectType;
import org.keycloak.dom.saml.v2.protocol.ResponseType;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.saml.common.constants.GeneralConstants;
import org.keycloak.saml.common.constants.JBossSAMLConstants;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.saml.processing.core.parsers.saml.SAMLParser;
import org.keycloak.saml.processing.core.saml.v2.common.SAMLDocumentHolder;
import org.keycloak.saml.processing.core.saml.v2.util.AssertionUtil;
import org.keycloak.saml.processing.core.util.JAXPValidationUtil;
import org.keycloak.saml.processing.core.util.XMLEncryptionUtil;
import org.keycloak.saml.validators.DestinationValidator;
import org.w3c.dom.*;

import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.xml.namespace.NamespaceContext;
import javax.xml.namespace.QName;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.IOException;
import java.io.StringWriter;
import java.security.PrivateKey;
import java.util.Iterator;

public class CustomSAMLEndpoint extends SAMLEndpoint {
    protected static final Logger logger = Logger.getLogger(CustomSAMLEndpoint.class);

    public static final String EKONA = "ekona:";
    public static final String XSD_STRING = "xsd:string";

    public CustomSAMLEndpoint(RealmModel realm, SAMLIdentityProvider provider, SAMLIdentityProviderConfig config, IdentityProvider.AuthenticationCallback callback, DestinationValidator destinationValidator) {
        super(realm, provider, config, callback, destinationValidator);
    }

    //wird benötigt, weil session in der Super-Klasse leider private ist.
    @Context
    private KeycloakSession session;

    protected class PostBinding extends SAMLEndpoint.PostBinding {

        /**
         * Methode wird benötigt, um die ELSTER Response zu verarbeiten. Dabei wird
         * - die Assertion decrypted und dort die unbekannten Attribute umgeschrieben, BEVOR der Parser über diese stolpert
         * - die EncryptedID decrypted und dann in nameID abgelegt, damit der weitere Code dort etwas vorfindet
         * - WantAssertionsEncrypted auf false gesetzt, da sonst nochmal eine Decryption versucht wird
         * - super.handleLoginResponse aufgerufen
         * - danach WantAssertionsEncrypted wieder auf den Originalzustand gesetzt
         *
         * @param samlResponse
         * @param holder
         * @param responseType
         * @param relayState
         * @param clientId
         * @return
         */
        @Override
        protected Response handleLoginResponse(String samlResponse, SAMLDocumentHolder holder, ResponseType responseType, String relayState, String clientId) {
            logger.info("In custom handleLoginResponse");
            KeyManager.ActiveRsaKey keys = session.keys().getActiveRsaKey(realm);

            //Assertion decrypten falls nötig
            try {
                boolean assertionIsEncrypted = AssertionUtil.isAssertionEncrypted(responseType);
                if (assertionIsEncrypted) {
                    //decrypten...
                    Element assertionElement = decryptAssertion(holder, responseType, keys.getPrivateKey());
                    //...und als decrypted assertionElement zusätzlich im SAMLDocument einfügen
                    Document samlDocument = holder.getSamlDocument();
                    Node importedNode = samlDocument.importNode(assertionElement, true);
                    samlDocument.getFirstChild().appendChild(importedNode);
                }

            } catch (ParsingException | ProcessingException | ConfigurationException e) {
                e.printStackTrace();
            }


            //EncryptedID behandeln
            if (responseType != null && responseType.getAssertions() != null && responseType.getAssertions().size() > 0) {
                AssertionType assertion = responseType.getAssertions().get(0).getAssertion();
                SubjectType subject = assertion.getSubject();
                SubjectType.STSubType subType = subject.getSubType();
                if (subType.getBaseID() == null) {
                    //subType oder BaseID nicht existent --> statt NameID gibt es wohl eine encryptedID
                    EncryptedElementType encryptedID = subType.getEncryptedID();
                    if (encryptedID != null) {
                        Element decryptedElement = null;
                        try {
                            decryptedElement = decryptEncryptedID(encryptedID);
                        } catch (ConfigurationException | IOException | TransformerException | ProcessingException e) {
                            e.printStackTrace();
                        }

                        NameIDType nameIDType = new NameIDType();
                        nameIDType.setValue(decryptedElement.getTextContent());
                        nameIDType.setFormat(null);
                        subType.addBaseID(nameIDType);

                        subType.setEncryptedID(null);
                    }
                }
            }

            //"WantAssertionsEncrypted" temporär auf false setzen, bevor wir super() aufrufen
            boolean wantAssertionsEncryptedOriginal = config.isWantAssertionsEncrypted();
            config.setWantAssertionsEncrypted(false);
            Response response = super.handleLoginResponse(samlResponse, holder, responseType, relayState, clientId);
            //"wantAssertionsEncrypted" wieder auf Originalzustand zurücksetzen
            config.setWantAssertionsEncrypted(wantAssertionsEncryptedOriginal);
            return response;
        }
    }

    public Element decryptEncryptedID(EncryptedElementType encryptedID) throws ConfigurationException, IOException, TransformerException, ProcessingException {
        KeyManager.ActiveRsaKey keys = session.keys().getActiveRsaKey(realm);
        Document tempDoc = DocumentUtil.createDocument();
        Element encElement = encryptedID.getEncryptedElement();

        Node firstDocImportedNode = tempDoc.importNode(encElement, true);
        tempDoc.appendChild(firstDocImportedNode);

        Element decryptedElement = XMLEncryptionUtil.decryptElementInDocument(tempDoc, keys.getPrivateKey());
        return decryptedElement;
    }

    //LHM CODE AUS AssertionUtil Anfang
    /**
     * This method modifies the given responseType, and replaces the encrypted assertion with a decrypted version.
     * @param responseType a response containg an encrypted assertion
     * @return the assertion element as it was decrypted. This can be used in signature verification.
     */
    public static Element decryptAssertion(SAMLDocumentHolder holder, ResponseType responseType, PrivateKey privateKey) throws ParsingException, ProcessingException, ConfigurationException {
        logger.info("In custom decryptAssertion");
        Document doc = holder.getSamlDocument();
        Element enc = DocumentUtil.getElement(doc, new QName(JBossSAMLConstants.ENCRYPTED_ASSERTION.get()));

        if (enc == null) {
            throw new ProcessingException("No encrypted assertion found.");
        }

        String oldID = enc.getAttribute(JBossSAMLConstants.ID.get());
        Document newDoc = DocumentUtil.createDocument();
        Node importedNode = newDoc.importNode(enc, true);
        newDoc.appendChild(importedNode);

        Element decryptedDocumentElement = XMLEncryptionUtil.decryptElementInDocument(newDoc, privateKey);
        SAMLParser parser = SAMLParser.getInstance();

        JAXPValidationUtil.checkSchemaValidation(decryptedDocumentElement);

        //LHM ERGÄNZUNG ANFANG
        try {
            logger.info("\n\n\n  Original Response: \n ------- \n " + printElement(decryptedDocumentElement));
        } catch (IOException | TransformerException e) {
            e.printStackTrace();
        }

        decryptedDocumentElement = replaceUnknownType(decryptedDocumentElement);

        try {
            logger.info("\n\n\n  Angepasste Response: \n ------- \n " + printElement(decryptedDocumentElement));
        } catch (IOException | TransformerException e) {
            e.printStackTrace();
        }
        //LHM ERGÄNZUNG ENDE

        AssertionType assertion = (AssertionType) parser.parse(parser.createEventReader(DocumentUtil
                .getNodeAsStream(decryptedDocumentElement)));

        responseType.replaceAssertion(oldID, new ResponseType.RTChoiceType(assertion));

        return decryptedDocumentElement;
    }
    //LHM CODE AUS AssertionUtil Ende

    public static String printElement(Element doc) throws IOException, TransformerException {
        StringWriter writer = new StringWriter();
        StreamResult result = new StreamResult(writer);

        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer transformer = tf.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
        transformer.setOutputProperty(OutputKeys.METHOD, "xml");
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");

        transformer.transform(new DOMSource(doc), result);

        return writer.toString();
    }


    /**
     * Ersetzt Attribute vom Typ ekona:addresseType mit "flachgeklopften" Einträgen und wandelt alle sonstigen Typ
     * ekona:* in xsd:string um.
     *
     * @param element die Assertion, in der ersetzt weren soll
     * @return das angepasste Assertion element
     */
    public static Element replaceUnknownType(Element element) {
        XPath xPath = XPathFactory.newInstance().newXPath();

        xPath.setNamespaceContext(new NamespaceContext() {
            @Override
            public Iterator getPrefixes(String arg0) {
                return null;
            }
            @Override
            public String getPrefix(String arg0) {
                return null;
            }
            @Override
            public String getNamespaceURI(String arg0) {
                if ("saml2".equals(arg0)) {
                    return "urn:oasis:names:tc:SAML:2.0:assertion";
                } else
                if ("xsi".equals(arg0)) {
                    return "http://www.w3.org/2001/XMLSchema-instance";
                }
                return null;
            }
        });

        String expression = "/saml2:Assertion/saml2:AttributeStatement/saml2:Attribute/saml2:AttributeValue[starts-with(@xsi:type, 'ekona:')]";
        try {
            NodeList nodeList = (NodeList) xPath.compile(expression).evaluate(element, XPathConstants.NODESET);
            logger.debug("Found NodeList with " + nodeList.getLength() + " entries");
            for (int i = 0; i < nodeList.getLength(); i++) {
                Node node = nodeList.item(i);
                if (node.getNodeType() == Node.ELEMENT_NODE) {
                    Element nodeElement = (Element) node;

                    for (int j = 0; j < nodeElement.getAttributes().getLength(); j++) {
                        Node attribute = nodeElement.getAttributes().item(j);
                        if (attribute.getNodeType() == Node.ATTRIBUTE_NODE) {
                            Attr attributeNode = (Attr) attribute;
                            if (attribute.getNodeValue().startsWith(EKONA)) {
                                if (nodeElement.getFirstChild() != null &&
                                        nodeElement.getChildNodes().getLength() > 1 || nodeElement.getFirstChild().getNodeType() == Node.ELEMENT_NODE) {
                                    handleSubElements(nodeElement, attributeNode);
                                } else {
                                    attributeNode.setValue(XSD_STRING);
                                }
                            }

                        }
                    }
                }
            }
        } catch (XPathExpressionException e) {
            e.printStackTrace();
        }
        return element;
    }



    /**
     * Wandelt ein geschachteltes Attribut (wie Anschrift oder HandelndePerson) in einen String um, in dem die enthaltenden Werte
     * comma-separated aufgeführt sind.
     * Zusätzlich wird jedes Feld der Anschrift noch separat aufgenommen mit dem Feldnamen "[Parent].[Child]".
     *
     * @param nodeElement Das AttributeValue Element, das zu verarbeiten ist
     * @param attributeNode  Das Typ-Attribut, damit man es auf String umstellen kann
     */
    private static void handleSubElements(Element nodeElement, Attr attributeNode) {
        attributeNode.setValue(XSD_STRING);

        String parentName = getParentName(nodeElement);

        StringBuilder builder = new StringBuilder();

        NodeList nodeList = nodeElement.getChildNodes();
        for (int i = 0; i < nodeList.getLength(); i++) {
            Node node = nodeList.item(i);
            String value = node.getTextContent();

            if (value != null && !value.isEmpty()) {
                if (i > 0) {
                    builder.append(",");
                }
                builder.append(value);

                String newName = generateAttributeName(parentName, node);
                appendAttribute(nodeElement, newName, value);
            }
        }
        nodeElement.setTextContent(builder.toString());


    }

    private static String generateAttributeName(String parentName, Node node) {
        String name = node.getLocalName();
        String attributeValues = joinAttributeValues(node);
        String newName = parentName + "." + name;
        if (attributeValues.length() > 0) {
            newName = newName + "." + attributeValues;
        }
        if (newName.length() > 255) {
            newName = newName.substring(0, 255);
        }
        return newName;
    }

    private static String joinAttributeValues(Node node) {
        if (node.getAttributes() != null) {
            StringBuilder builder = new StringBuilder();
            for (int i= 0 ; i < node.getAttributes().getLength(); i++) {
                Node attribute = node.getAttributes().item(i);
                builder.append(attribute.getNodeValue());
            }
            return builder.toString();
        }

        return "";
    }


    private static String getParentName(Element nodeElement) {
        Node parentNode = nodeElement.getParentNode();
        if (parentNode != null) {
            if (parentNode.hasAttributes()) {
                Node nameAttribute = parentNode.getAttributes().getNamedItem("Name");
                if (nameAttribute != null) {
                    return nameAttribute.getTextContent();
                }
            }
        }
        return "NOT_FOUND";
    }

    private static void appendAttribute(Element nodeElement, String name, String value) {
        Element attributeClone = (Element) nodeElement.getParentNode().cloneNode(true);
        attributeClone.setAttribute("Name", name);
        attributeClone.getFirstChild().setTextContent(value);
        Node attributeStatement = nodeElement.getParentNode().getParentNode();
        attributeStatement.appendChild(attributeClone);
    }

    /**
     */
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response postBinding(@FormParam(GeneralConstants.SAML_REQUEST_KEY) String samlRequest,
                                @FormParam(GeneralConstants.SAML_RESPONSE_KEY) String samlResponse,
                                @FormParam(GeneralConstants.RELAY_STATE) String relayState) {
        return new CustomSAMLEndpoint.PostBinding().execute(samlRequest, samlResponse, relayState, null);
    }
}
