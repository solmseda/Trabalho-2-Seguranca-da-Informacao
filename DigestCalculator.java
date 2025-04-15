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
                    System.out.println(arquivo.getName() + " " + tipoDigest + " " + digest + " (Status = TODO)");
                    // Atualiza (ou cria) o arquivo XML para adicionar o novo digest
                    updateXML(arquivo.getName(), tipoDigest, digest);
                } catch (Exception e) {
                    System.out.println("Erro ao calcular digest de " + arquivo.getName() + ": " + e.getMessage());
                }
            }
        }
    }

    /**
     * Calcula o digest do conteudo de uma arquivo utlizando um algoritmo respetcivo do tipo do digest
     *
     * @param arquivo    Arquivo em que o digest do conteudo deve ser calculado
     * @param tipoDigest Tipo do digest(MD5/SHA1/SHA256/SHA512)
     * @return Retorna uma string de um Hexadecimal que representa o digest calculado
     * @throws Exception Se um erro ocorre enquanto lê o arquivo ou se o tipo do digest é invalido
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

    public static String CompareDigest(String digest) {
        // Implementar a comparação dos dois digests

        return "OK";
    }

    public static void updateXML(String fileName, String tipoDigest, String digestHex) throws Exception {
        File xmlFile = new File(caminhoXML);
        Document doc;
        DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();

        System.out.println("Atualizando o XML: " + xmlFile.getAbsolutePath());
        // Se o arquivo XML já existir, carregue-o; caso contrário, crie um novo documento
        if (xmlFile.exists()) {
            doc = dBuilder.parse(xmlFile);
            doc.getDocumentElement().normalize();
        } else {
            doc = dBuilder.newDocument();
            Element catalog = doc.createElement("CATALOG");
            doc.appendChild(catalog);
        }

        // Cria o novo elemento <FILE_ENTRY>
        Element fileEntry = doc.createElement("FILE_ENTRY");

        Element fileNameElement = doc.createElement("FILE_NAME");
        fileNameElement.appendChild(doc.createTextNode(fileName));
        fileEntry.appendChild(fileNameElement);

        Element digestEntry = doc.createElement("DIGEST_ENTRY");

        Element digestTypeElement = doc.createElement("DIGEST_TYPE");
        digestTypeElement.appendChild(doc.createTextNode(tipoDigest));
        digestEntry.appendChild(digestTypeElement);

        Element digestHexElement = doc.createElement("DIGEST_HEX");
        digestHexElement.appendChild(doc.createTextNode(digestHex));
        digestEntry.appendChild(digestHexElement);

        fileEntry.appendChild(digestEntry);

        // Adiciona o novo <FILE_ENTRY> ao elemento raiz <CATALOG>
        doc.getDocumentElement().appendChild(fileEntry);

        // Escreve o documento XML atualizado de volta para o arquivo
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.INDENT, "yes");
        transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
        DOMSource source = new DOMSource(doc);
        StreamResult result = new StreamResult(xmlFile);
        transformer.transform(source, result);
    }
    

}