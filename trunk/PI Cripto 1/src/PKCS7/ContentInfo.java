package PKCS7;

public class ContentInfo {

    private ContentType contentType;
    private int version;


    public ContentInfo(ContentType contentType, int version) {

        this.contentType = contentType;
        this.version = version;
    }


    public ContentType getContentType() {

        return this.contentType;
    }

    public int getVersion() {

        return this.version;
    }
}
