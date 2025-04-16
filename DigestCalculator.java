/*
 * Trabalho 2 de Segurança da Informação
 * Sol Castilho Araújo de Moraes Sêda - 2511704
 * Leonardo Giuri Santiago - 2410725
 */

import java.io.*;
import java.security.*;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

public class DigestCalculator {

    // Armazena o caminho do XML passado na linha de comando.
    private static String caminhoXML;
    private static String caminhoPasta;

    public static void main(String[] args) {
        if (args.length != 3) {
            System.out.println("Uso: java DigestCalculator <Tipo_Digest> <Caminho_da_Pasta> <Caminho_ArqListaDigest>");
            return;
        }

        String tipoDigest = args[0].toUpperCase();
        caminhoPasta = args[1];
        caminhoXML = args[2];

        // Garantindo que o tipo foi passado correntamente dos 4 possiveis
        if (!tipoDigest.equals("MD5") && !tipoDigest.equals("SHA1") &&
                !tipoDigest.equals("SHA256") && !tipoDigest.equals("SHA512")) {
            System.out.println("Tipo de digest inválido. Use MD5, SHA1, SHA256 ou SHA512.");
            return;
        }

        // Checando se o caminho da pasta é válido
        File pasta = new File(caminhoPasta);
        if (!pasta.exists() || !pasta.isDirectory()) {
            System.out.println("Caminho da pasta inválido.");
            return;
        }

        // Pegando os arquivos contigos na pasta
        File[] arquivos = pasta.listFiles();
        if (arquivos == null) {
            System.out.println("Erro ao listar arquivos da pasta.");
            return;
        }

        for (File arquivo : arquivos) {
            if (arquivo.isFile()) {
                try {
                    String digest = calcularDigest(arquivo, tipoDigest);

                    // Compara o digest calculado com o listado no arquivo XML (ArqListaDigest) e
                    // retorna um status:
                    String status = compareList(arquivo.getName(), tipoDigest, digest);
                    System.out.println(
                            arquivo.getName() + " " + tipoDigest + " " + digest + " (" + status + ")");
                } catch (Exception e) {
                    System.out.println("Erro ao calcular digest de " + arquivo.getName() + ": " + e.getMessage());
                }
            }
        }
    }

    /**
     * Calcula o digest do conteudo de uma arquivo utlizando um algoritmo respetcivo
     * do tipo do digest
     *
     * @param arquivo    Arquivo em que o digest do conteudo deve ser calculado
     * @param tipoDigest Tipo do digest(MD5/SHA1/SHA256/SHA512)
     * @return Retorna uma string de um Hexadecimal que representa o digest
     *         calculado
     * @throws Exception Se um erro ocorre enquanto lê o arquivo ou se o tipo do
     *                   digest é invalido
     */
    public static String calcularDigest(File arquivo, String tipoDigest) throws Exception {
        MessageDigest md = MessageDigest.getInstance(tipoDigest);

        try (InputStream is = new FileInputStream(arquivo)) {
            byte[] buffer = new byte[512];
            int bytesLidos;
            while ((bytesLidos = is.read(buffer)) != -1) {
                md.update(buffer, 0, bytesLidos);
            }
        }

        byte[] digestBytes = md.digest();
        return bytesParaHex(digestBytes);
    }

    /**
     * Converte um array de bytes para hexadecimal representado por uma string
     *
     * @param bytes O array de bytes a ser convertido
     * @return Uma string contendo a representação em hexadecimal do array de bytes
     */
    public static String bytesParaHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

/**
 * Compara o digest calculado com os listados no XML (ArqListaDigest) e nos arquivos da pastaArquivos.
 * Retorna um status e, se necessário, atualiza o XML somente quando o status é "NOT FOUND".
 * 
 * OK = Igual e sem colisão.
 * NOT OK = Diferente e sem colisão.
 * NOT FOUND = Nenhuma entrada encontrada; neste caso, o digest é acrescentado.
 * COLISION = Digest colide com o de outro arquivo.
 */
public static String compareList(String fileName, String tipoDigest, String digestHex) throws Exception {
    // Obtém (ou cria) o documento XML.
    File xmlFile = new File(caminhoXML);
    Document doc = getOrCreateDocument(xmlFile);

    // Constrói mapas de digests: um para o XML e outro para os arquivos da pasta.
    java.util.Map<String, java.util.List<String>> xmlDigestMap = buildXmlDigestMap(doc, tipoDigest);
    java.util.Map<String, java.util.List<String>> computedDigestMap = buildComputedDigestMap(tipoDigest);

    // Verifica colisão nos dois mapas.
    if (isCollision(fileName, digestHex, xmlDigestMap) || isCollision(fileName, digestHex, computedDigestMap)) {
        return "COLISION";
    }

    // Procura uma entrada para o arquivo no XML.
    Element targetEntry = findTargetEntry(doc, fileName);
    if (targetEntry != null) {
        Element digestEntry = findDigestEntry(targetEntry, tipoDigest);
        if (digestEntry != null) {
            String storedDigest = digestEntry.getElementsByTagName("DIGEST_HEX").item(0).getTextContent();
            return storedDigest.equals(digestHex) ? "OK" : "NOT OK";
        } else {
            // Registro existe mas não há entrada para o tipo: acrescenta.
            addDigestEntry(targetEntry, tipoDigest, digestHex, doc, xmlFile);
            return "NOT FOUND";
        }
    } else {
        // Cria uma nova entrada para o arquivo.
        createNewFileEntry(doc, fileName, tipoDigest, digestHex, xmlFile);
        return "NOT FOUND";
    }
}

/**
 * Obtém o Document do arquivo XML, criando um novo se necessário.
 */
private static Document getOrCreateDocument(File xmlFile) throws Exception {
    DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
    dbFactory.setIgnoringElementContentWhitespace(true);
    DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
    Document doc;
    if (!xmlFile.exists() || xmlFile.length() == 0) {
        doc = dBuilder.newDocument();
        Element root = doc.createElement("CATALOG");
        doc.appendChild(root);
    } else {
        doc = dBuilder.parse(xmlFile);
        doc.getDocumentElement().normalize();
    }
    return doc;
}

/**
 * Constrói um mapa com os digests listados no XML para o dado tipo.
 * Chave: digest (hex), Valor: lista de nomes de arquivos.
 */
private static java.util.Map<String, java.util.List<String>> buildXmlDigestMap(Document doc, String tipoDigest) {
    java.util.Map<String, java.util.List<String>> map = new java.util.HashMap<>();
    NodeList fileEntries = doc.getElementsByTagName("FILE_ENTRY");
    for (int i = 0; i < fileEntries.getLength(); i++) {
        Element entry = (Element) fileEntries.item(i);
        String existingFileName = entry.getElementsByTagName("FILE_NAME").item(0).getTextContent();
        NodeList digestEntries = entry.getElementsByTagName("DIGEST_ENTRY");
        for (int j = 0; j < digestEntries.getLength(); j++) {
            Element de = (Element) digestEntries.item(j);
            String t = de.getElementsByTagName("DIGEST_TYPE").item(0).getTextContent();
            if (t.equals(tipoDigest)) {
                String storedDigest = de.getElementsByTagName("DIGEST_HEX").item(0).getTextContent();
                map.computeIfAbsent(storedDigest, k -> new java.util.ArrayList<>()).add(existingFileName);
            }
        }
    }
    return map;
}

/**
 * Constrói um mapa com os digests dos arquivos na pastaArquivos para o dado tipo.
 * Chave: digest (hex), Valor: lista de nomes de arquivos.
 */
private static java.util.Map<String, java.util.List<String>> buildComputedDigestMap(String tipoDigest) throws Exception {
    java.util.Map<String, java.util.List<String>> map = new java.util.HashMap<>();
    File pasta = new File(caminhoPasta);
    if (pasta.exists() && pasta.isDirectory()) {
        File[] arquivos = pasta.listFiles();
        if (arquivos != null) {
            for (File arquivo : arquivos) {
                if (arquivo.isFile()) {
                    String digestComp = calcularDigest(arquivo, tipoDigest);
                    map.computeIfAbsent(digestComp, k -> new java.util.ArrayList<>()).add(arquivo.getName());
                }
            }
        }
    }
    return map;
}

/**
 * Verifica se há colisão para o digest calculado, comparando com o mapa fornecido.
 */
private static boolean isCollision(String fileName, String digestHex, java.util.Map<String, java.util.List<String>> map) {
    if (map.containsKey(digestHex)) {
        java.util.List<String> files = map.get(digestHex);
        return files.size() > 1 || (files.size() == 1 && !files.get(0).equals(fileName));
    }
    return false;
}

/**
 * Procura e retorna a entrada (FILE_ENTRY) correspondente ao fileName no XML.
 */
private static Element findTargetEntry(Document doc, String fileName) {
    NodeList fileEntries = doc.getElementsByTagName("FILE_ENTRY");
    for (int i = 0; i < fileEntries.getLength(); i++) {
        Element entry = (Element) fileEntries.item(i);
        String existingFileName = entry.getElementsByTagName("FILE_NAME").item(0).getTextContent();
        if (existingFileName.equals(fileName)) {
            return entry;
        }
    }
    return null;
}

/**
 * Procura e retorna a entrada do digest (DIGEST_ENTRY) para o tipo especificado dentro de um FILE_ENTRY.
 */
private static Element findDigestEntry(Element targetEntry, String tipoDigest) {
    NodeList digestEntries = targetEntry.getElementsByTagName("DIGEST_ENTRY");
    for (int i = 0; i < digestEntries.getLength(); i++) {
        Element de = (Element) digestEntries.item(i);
        String t = de.getElementsByTagName("DIGEST_TYPE").item(0).getTextContent();
        if (t.equals(tipoDigest)) {
            return de;
        }
    }
    return null;
}

/**
 * Acrescenta uma nova entrada DIGEST_ENTRY a um FILE_ENTRY e grava o XML.
 */
private static void addDigestEntry(Element targetEntry, String tipoDigest, String digestHex, Document doc, File xmlFile) throws Exception {
    Element newDigestEntry = doc.createElement("DIGEST_ENTRY");

    Element typeElem = doc.createElement("DIGEST_TYPE");
    typeElem.appendChild(doc.createTextNode(tipoDigest));
    newDigestEntry.appendChild(typeElem);

    Element hexElem = doc.createElement("DIGEST_HEX");
    hexElem.appendChild(doc.createTextNode(digestHex));
    newDigestEntry.appendChild(hexElem);

    targetEntry.appendChild(newDigestEntry);
    gravarXML(doc, xmlFile);
}

/**
 * Cria uma nova entrada FILE_ENTRY com o digest calculado e grava o XML.
 */
private static void createNewFileEntry(Document doc, String fileName, String tipoDigest, String digestHex, File xmlFile) throws Exception {
    Element root = doc.getDocumentElement();
    Element newEntry = doc.createElement("FILE_ENTRY");

    Element nameElem = doc.createElement("FILE_NAME");
    nameElem.appendChild(doc.createTextNode(fileName));
    newEntry.appendChild(nameElem);

    Element newDigestEntry = doc.createElement("DIGEST_ENTRY");
    Element typeElem = doc.createElement("DIGEST_TYPE");
    typeElem.appendChild(doc.createTextNode(tipoDigest));
    newDigestEntry.appendChild(typeElem);

    Element hexElem = doc.createElement("DIGEST_HEX");
    hexElem.appendChild(doc.createTextNode(digestHex));
    newDigestEntry.appendChild(hexElem);

    newEntry.appendChild(newDigestEntry);
    root.appendChild(newEntry);
    gravarXML(doc, xmlFile);
}

/**
 * Método auxiliar para gravar o conteúdo do Document no arquivo XML.
 */
public static void gravarXML(Document doc, File xmlFile) throws Exception {
    TransformerFactory transformerFactory = TransformerFactory.newInstance();
    Transformer transformer = transformerFactory.newTransformer();
    transformer.setOutputProperty(OutputKeys.INDENT, "yes");
    transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
    DOMSource source = new DOMSource(doc);
    StreamResult result = new StreamResult(xmlFile);
    transformer.transform(source, result);
}

    /**
     * Remove espaços em branco e quebras de linha do nó XML fornecido e de seus
     * descendentes.
     * Este método percorre a árvore DOM recursivamente, removendo quaisquer nós de
     * texto que
     * contenham apenas espaços em branco ou quebras de linha.
     *
     * @param node O nó raiz do qual os espaços em branco e quebras de linha devem
     *             ser removidos.
     *             Este nó e todos os seus nós filhos serão processados.
     */
    public static void limparEspacosEmBranco(Node node) {
        NodeList children = node.getChildNodes();
        for (int i = children.getLength() - 1; i >= 0; i--) {
            Node child = children.item(i);
            if (child.getNodeType() == Node.TEXT_NODE && child.getTextContent().trim().isEmpty()) {
                node.removeChild(child);
            } else if (child.hasChildNodes()) {
                limparEspacosEmBranco(child);
            }
        }
    }
}