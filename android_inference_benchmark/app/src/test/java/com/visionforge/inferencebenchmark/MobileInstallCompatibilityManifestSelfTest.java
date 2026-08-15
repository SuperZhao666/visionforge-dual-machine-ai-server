package com.visionforge.inferencebenchmark;

import java.nio.file.Path;

import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/** Guards installation compatibility for devices without Qualcomm DSP RPC. */
final class MobileInstallCompatibilityManifestSelfTest {
    private static final String ANDROID_NAMESPACE =
            "http://schemas.android.com/apk/res/android";
    private static final String ACCESS_EXTERNAL_DTD =
            "http://javax.xml.XMLConstants/property/accessExternalDTD";
    private static final String ACCESS_EXTERNAL_SCHEMA =
            "http://javax.xml.XMLConstants/property/accessExternalSchema";
    private static final String QUALCOMM_RPC_LIBRARY = "libcdsprpc.so";

    private MobileInstallCompatibilityManifestSelfTest() {}

    static void run() throws Exception {
        String projectDirectory =
                System.getProperty("visionforge.android.project.dir", "").trim();
        require(!projectDirectory.isEmpty(), "Android project directory is unavailable");

        Path manifestPath = Path.of(
                projectDirectory, "src", "main", "AndroidManifest.xml");
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        factory.setFeature(
                "http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature(
                "http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature(
                "http://xml.org/sax/features/external-parameter-entities", false);
        factory.setAttribute(ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(ACCESS_EXTERNAL_SCHEMA, "");

        NodeList declarations = factory.newDocumentBuilder()
                .parse(manifestPath.toFile())
                .getElementsByTagName("uses-native-library");
        int matchingDeclarations = 0;
        for (int index = 0; index < declarations.getLength(); index++) {
            Element declaration = (Element) declarations.item(index);
            if (!QUALCOMM_RPC_LIBRARY.equals(
                    declaration.getAttributeNS(ANDROID_NAMESPACE, "name"))) {
                continue;
            }
            matchingDeclarations++;
            require(
                    "false".equals(
                            declaration.getAttributeNS(ANDROID_NAMESPACE, "required")),
                    QUALCOMM_RPC_LIBRARY
                            + " must be optional so non-Qualcomm devices can install");
        }
        require(
                matchingDeclarations == 1,
                "Expected exactly one " + QUALCOMM_RPC_LIBRARY
                        + " declaration but found " + matchingDeclarations);
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }
}
