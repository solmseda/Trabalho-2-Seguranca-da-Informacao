/*
 * Trabalho 2 de Segurança da Informação
 * Sol Castilho Araújo de Moraes Sêda - 2511704
 *
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

    public static void main(String[] args) {
        if (args.length != 3) {
            System.out.println("Uso: java DigestCalculator <Tipo_Digest> <Caminho_da_Pasta> <Caminho_ArqListaDigest>");
            return;
        }

        String tipoDigest = args[0].toUpperCase();
        String caminhoPasta = args[1];
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
                    
                    // Atualiza (ou cria) o arquivo XML para adicionar o novo digest
                    String status = updateXML(arquivo.getName(), tipoDigest, digest);
                    System.out.println(arquivo.getName() + " " + tipoDigest + " " + digest + " (Status = " + status + ")");
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
            byte[] buffer = new byte[8192];
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
     * Atualiza (ou cria) o arquivo XML ArqListaDigest e retorna um status:
     * 
     * OK = Digest calculado igual ao digest armazenado no ArqListaDigest e sem
     * colisão.
     * NOT OK = Digest calculado diferente do armazenado no ArqListaDigest e sem
     * colisão.
     * NOT FOUND = Nenhuma entrada para o arquivo foi encontrada no ArqListaDigest e
     * sem colisão.
     * COLISION = Digest calculado colide com o digest de outro arquivo (nome
     * diferente) presente no ArqListaDigest.
     *
     * @param fileName   Nome do arquivo.
     * @param tipoDigest Tipo do digest (MD5, SHA1, SHA256, SHA512).
     * @param digestHex  Digest calculado (em hexadecimal).
     * @return Uma String representando o status conforme as regras acima.
     * @throws Exception Em caso de erro na leitura ou escrita do XML.
     */
    public static String updateXML(String fileName, String tipoDigest, String digestHex) throws Exception {
        File xmlFile = new File(caminhoXML);
        Document doc;
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();

        // Se o arquivo XML já existir, carregue-o; caso contrário, crie um novo
        // documento.
        if (xmlFile.exists()) {
            doc = dBuilder.parse(xmlFile);
            doc.getDocumentElement().normalize();
        } else {
            doc = dBuilder.newDocument();
            Element catalog = doc.createElement("CATALOG");
            doc.appendChild(catalog);
        }

        // Verifica colisão: se o mesmo digest (e tipo) existir para outro arquivo,
        // retorna "COLISION".
        if (detectCollision(fileName, tipoDigest, digestHex)) {
            return "COLISION";
        }

        // Procura uma entrada existente para o arquivo.
        NodeList fileEntries = doc.getElementsByTagName("FILE_ENTRY");
        Element targetEntry = null;
        for (int i = 0; i < fileEntries.getLength(); i++) {
            Element entry = (Element) fileEntries.item(i);
            String existingFileName = entry.getElementsByTagName("FILE_NAME").item(0).getTextContent();
            if (existingFileName.equals(fileName)) {
                targetEntry = entry;
                break;
            }
        }

        String status;
        if (targetEntry != null) {
            // Entrada encontrada; compare o digest armazenado com o calculado.
            Element digestEntry = (Element) targetEntry.getElementsByTagName("DIGEST_ENTRY").item(0);
            String storedDigest = digestEntry.getElementsByTagName("DIGEST_HEX").item(0).getTextContent();
            if (storedDigest.equals(digestHex)) {
                status = "OK";
            } else {
                status = "NOT OK";
                // Atualiza a entrada para refletir o digest calculado.
                digestEntry.getElementsByTagName("DIGEST_HEX").item(0).setTextContent(digestHex);
                Element digestTypeElement = (Element) digestEntry.getElementsByTagName("DIGEST_TYPE").item(0);
                digestTypeElement.setTextContent(tipoDigest);
            }
        } else {
            // Nenhuma entrada para o arquivo encontrada; adiciona uma nova entrada.
            status = "NOT FOUND";
            Element catalog = doc.getDocumentElement();
            Element newEntry = doc.createElement("FILE_ENTRY");

            Element fileNameElem = doc.createElement("FILE_NAME");
            fileNameElem.appendChild(doc.createTextNode(fileName));
            newEntry.appendChild(fileNameElem);

            Element digestEntry = doc.createElement("DIGEST_ENTRY");
            Element digestTypeElem = doc.createElement("DIGEST_TYPE");
            digestTypeElem.appendChild(doc.createTextNode(tipoDigest));
            digestEntry.appendChild(digestTypeElem);
            Element digestHexElem = doc.createElement("DIGEST_HEX");
            digestHexElem.appendChild(doc.createTextNode(digestHex));
            digestEntry.appendChild(digestHexElem);
            newEntry.appendChild(digestEntry);

            catalog.appendChild(newEntry);
        }

        // Escreve o documento XML atualizado de volta para o arquivo.
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(xmlFile);
        transformer.transform(source, result);

        return status;
    }

    /**
     * Verifica se já existe um digest com o mesmo tipo e valor para um arquivo
     * diferente.
     * Se existir, considera isso uma colisão.
     *
     * @param fileName   Nome do arquivo atual.
     * @param tipoDigest Tipo do digest (MD5, SHA1, SHA256, SHA512).
     * @param digestHex  Digest calculado (em hexadecimal).
     * @return true se detectar colisão, false caso contrário.
     * @throws Exception Em caso de erro ao ler ou interpretar o XML.
     */
    public static boolean detectCollision(String fileName, String tipoDigest, String digestHex) throws Exception {
        File xmlFile = new File(caminhoXML);
        if (!xmlFile.exists()) {
            // Se o XML não existir, não há colisão.
            return false;
        }

        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
        Document doc = dBuilder.parse(xmlFile);
        doc.getDocumentElement().normalize();

        NodeList fileEntries = doc.getElementsByTagName("FILE_ENTRY");
        for (int i = 0; i < fileEntries.getLength(); i++) {
            Element entry = (Element) fileEntries.item(i);
            String existingFileName = entry.getElementsByTagName("FILE_NAME").item(0).getTextContent();

            NodeList digestEntries = entry.getElementsByTagName("DIGEST_ENTRY");
            for (int j = 0; j < digestEntries.getLength(); j++) {
                Element deElement = (Element) digestEntries.item(j);
                String existingTipoDigest = deElement.getElementsByTagName("DIGEST_TYPE").item(0).getTextContent();
                String existingDigestHex = deElement.getElementsByTagName("DIGEST_HEX").item(0).getTextContent();

                // Se o digest type e o digest hex coincidirem e o arquivo for diferente, há
                // colisão.
                if (existingTipoDigest.equals(tipoDigest) && existingDigestHex.equals(digestHex)
                        && !existingFileName.equals(fileName)) {
                    return true;
                }
            }
        }
        return false;
    }

}