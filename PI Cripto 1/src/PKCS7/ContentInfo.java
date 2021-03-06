/***
 * ContentInfo ::= SEQUENCE { contentType ContentType,
 *                            content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL }
 */

package PKCS7;


public class ContentInfo {

    private ContentType contentType;
    private Content content;


    public ContentInfo(ContentType contentType, Content content) {

        this.contentType = contentType;
        this.content = content;
    }


    /***
     * Retorna um objecto ContentType, também definido nesta implementação do standard do PKCS7
     *
     * @return ContentType
     */
    public PKCS7.ContentType getContentType() {

        return this.contentType;
    }

    /***
     * Retorna um objecto Content, também definido nesta implementação do standard do PKCS7
     *
     * @return Content
     */
    public Content getContent() {

        return this.getContent();
    }


    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();

        sb.append(this.contentType.toString() + "\n");

        sb.append(this.content.toString());

        return sb.toString();
    }
}
