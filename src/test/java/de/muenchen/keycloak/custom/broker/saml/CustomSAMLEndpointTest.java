package de.muenchen.keycloak.custom.broker.saml;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Covers {@link CustomSAMLEndpoint#replaceUnknownType(Element)}, the core transform that lets
 * this plugin process ELSTER's SAML responses: it rewrites the ELSTER-specific {@code ekona:*}
 * attribute types to {@code xsd:string} before Keycloak's SAML parser sees them, flattening
 * composite (nested-element) attribute values in the process. These are pure DOM operations, so
 * they're exercised directly without a Keycloak server.
 */
class CustomSAMLEndpointTest {

    private static final String SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final String XSI_NS = "http://www.w3.org/2001/XMLSchema-instance";

    private Document document;
    private Element attributeStatement;

    @BeforeEach
    void setUp() throws ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        document = builder.newDocument();

        Element assertion = document.createElementNS(SAML_NS, "saml2:Assertion");
        document.appendChild(assertion);

        attributeStatement = document.createElementNS(SAML_NS, "saml2:AttributeStatement");
        assertion.appendChild(attributeStatement);
    }

    private Element addAttribute(String name) {
        Element attribute = document.createElementNS(SAML_NS, "saml2:Attribute");
        attribute.setAttribute("Name", name);
        attributeStatement.appendChild(attribute);
        return attribute;
    }

    private Element addAttributeValue(Element attribute, String ekonaType) {
        Element attributeValue = document.createElementNS(SAML_NS, "saml2:AttributeValue");
        attributeValue.setAttributeNS(XSI_NS, "xsi:type", ekonaType);
        attribute.appendChild(attributeValue);
        return attributeValue;
    }

    private Element addChild(Element parent, String localName, String textContent) {
        Element child = document.createElementNS(null, localName);
        child.setTextContent(textContent);
        parent.appendChild(child);
        return child;
    }

    private NodeList attributeElements() {
        return attributeStatement.getElementsByTagNameNS(SAML_NS, "Attribute");
    }

    @Test
    void simpleEkonaValue_isRewrittenToXsdStringWithoutFlattening() {
        Element attribute = addAttribute("Vorname");
        Element attributeValue = addAttributeValue(attribute, "ekona:simpleType");
        attributeValue.setTextContent("Max");

        CustomSAMLEndpoint.replaceUnknownType((Element) document.getFirstChild());

        assertEquals("xsd:string", attributeValue.getAttributeNS(XSI_NS, "type"));
        assertEquals("Max", attributeValue.getTextContent());
        assertEquals(1, attributeElements().getLength(), "no extra Attribute elements should be appended");
    }

    @Test
    void compositeEkonaValue_isFlattenedAndFieldsAppendedAsSiblingAttributes() {
        Element attribute = addAttribute("Anschrift");
        Element attributeValue = addAttributeValue(attribute, "ekona:addresseType");
        addChild(attributeValue, "Strasse", "Musterstr. 1");
        addChild(attributeValue, "Ort", "München");

        CustomSAMLEndpoint.replaceUnknownType((Element) document.getFirstChild());

        assertEquals("xsd:string", attributeValue.getAttributeNS(XSI_NS, "type"));
        assertEquals("Musterstr. 1,München", attributeValue.getTextContent());

        NodeList attributes = attributeElements();
        assertEquals(3, attributes.getLength(), "original Attribute plus one appended per flattened field");

        Element strasseAttribute = (Element) attributes.item(1);
        assertEquals("Anschrift.Strasse", strasseAttribute.getAttribute("Name"));
        assertEquals("Musterstr. 1", strasseAttribute.getElementsByTagNameNS(SAML_NS, "AttributeValue").item(0).getTextContent());

        Element ortAttribute = (Element) attributes.item(2);
        assertEquals("Anschrift.Ort", ortAttribute.getAttribute("Name"));
        assertEquals("München", ortAttribute.getElementsByTagNameNS(SAML_NS, "AttributeValue").item(0).getTextContent());
    }

    @Test
    void nonEkonaValue_isLeftUntouched() {
        Element attribute = addAttribute("Nachname");
        Element attributeValue = document.createElementNS(SAML_NS, "saml2:AttributeValue");
        attributeValue.setAttributeNS(XSI_NS, "xsi:type", "xsd:string");
        attributeValue.setTextContent("Mustermann");
        attribute.appendChild(attributeValue);

        CustomSAMLEndpoint.replaceUnknownType((Element) document.getFirstChild());

        assertEquals("xsd:string", attributeValue.getAttributeNS(XSI_NS, "type"));
        assertEquals("Mustermann", attributeValue.getTextContent());
        assertEquals(1, attributeElements().getLength());
    }

    @Test
    void generatedAttributeName_longerThan255Characters_isTruncated() {
        String longParentName = "Anschrift" + "X".repeat(300);
        Element attribute = addAttribute(longParentName);
        Element attributeValue = addAttributeValue(attribute, "ekona:addresseType");
        addChild(attributeValue, "Strasse", "Musterstr. 1");
        addChild(attributeValue, "Ort", "München");

        CustomSAMLEndpoint.replaceUnknownType((Element) document.getFirstChild());

        Element strasseAttribute = (Element) attributeElements().item(1);
        String name = strasseAttribute.getAttribute("Name");
        assertEquals(255, name.length());
        assertTrue(name.startsWith(longParentName.substring(0, 20)));
    }
}
