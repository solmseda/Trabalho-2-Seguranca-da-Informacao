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
 
         // Cria o parser de XML ignorando espaços em branco entre os elementos
         DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
         dbFactory.setIgnoringElementContentWhitespace(true); // <- ESSENCIAL
         DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
 
         // Se o arquivo está vazio ou não existe, inicializa novo XML
         if (!xmlFile.exists() || xmlFile.length() == 0) {
             doc = dBuilder.newDocument();
             Element catalog = doc.createElement("CATALOG");
             doc.appendChild(catalog);
         } else {
             doc = dBuilder.parse(xmlFile);
             doc.getDocumentElement().normalize();
 
             // Só verifica colisão depois do XML estar garantidamente válido
             if (detectCollision(fileName, tipoDigest, digestHex)) {
                 return "COLISION";
             }
         }
 
         // Procura por uma entrada existente do arquivo
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
             // Verifica se o digest já existe para esse tipo
             NodeList digestEntries = targetEntry.getElementsByTagName("DIGEST_ENTRY");
             Element digestEntry = null;
             for (int i = 0; i < digestEntries.getLength(); i++) {
                 Element de = (Element) digestEntries.item(i);
                 String tipo = de.getElementsByTagName("DIGEST_TYPE").item(0).getTextContent();
                 if (tipo.equals(tipoDigest)) {
                     digestEntry = de;
                     break;
                 }
             }
 
             if (digestEntry != null) {
                 String storedDigest = digestEntry.getElementsByTagName("DIGEST_HEX").item(0).getTextContent();
                 if (storedDigest.equals(digestHex)) {
                     status = "OK";
                 } else {
                     status = "NOT OK";
                     digestEntry.getElementsByTagName("DIGEST_HEX").item(0).setTextContent(digestHex);
                 }
             } else {
                 // Não existia esse tipo de digest ainda
                 status = "NOT FOUND";
                 Element newDigestEntry = doc.createElement("DIGEST_ENTRY");
 
                 Element digestTypeElem = doc.createElement("DIGEST_TYPE");
                 digestTypeElem.appendChild(doc.createTextNode(tipoDigest));
                 newDigestEntry.appendChild(digestTypeElem);
 
                 Element digestHexElem = doc.createElement("DIGEST_HEX");
                 digestHexElem.appendChild(doc.createTextNode(digestHex));
                 newDigestEntry.appendChild(digestHexElem);
 
                 targetEntry.appendChild(newDigestEntry);
             }
 
         } else {
             // Arquivo não está no XML: adiciona nova entrada
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
 
         limparEspacosEmBranco(doc);
 
         // Escreve o XML com indentação bonita e sem espaços extras
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
         if (!xmlFile.exists() || xmlFile.length() == 0) {
             // Se o XML não existir ou estiver vazio, não há colisão.
             return false;
         }
 
         DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
         dbFactory.setIgnoringElementContentWhitespace(true);
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
 
    /**
     * Remove espaços em branco e quebras de linha do nó XML fornecido e de seus descendentes.
     * Este método percorre a árvore DOM recursivamente, removendo quaisquer nós de texto que
     * contenham apenas espaços em branco ou quebras de linha.
     *
     * @param node O nó raiz do qual os espaços em branco e quebras de linha devem ser removidos.
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