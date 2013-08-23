package org.nick.customcert.https;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.params.ConnManagerParams;
import org.apache.http.conn.params.ConnPerRoute;
import org.apache.http.conn.params.ConnPerRouteBean;
import org.apache.http.conn.scheme.PlainSocketFactory;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.scheme.SocketFactory;
import org.apache.http.conn.ssl.BrowserCompatHostnameVerifier;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpConnectionParams;
import org.apache.http.params.HttpParams;
import org.apache.http.params.HttpProtocolParams;
import org.apache.http.protocol.HTTP;
import org.apache.http.util.EntityUtils;

import android.app.Activity;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Environment;
import android.text.Html;
import android.util.Log;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.Window;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.TextView;
import android.widget.Toast;

public class MainActivity extends Activity implements OnClickListener {

    private static final String TAG = MainActivity.class.getSimpleName();

    private static final String CLIENT_AUTH_URL = "https://myserver.com/clientauth";
    private static final String SERVER_AUTH_URL = "https://myserver.com/";

    private static final String TRUSTSTORE_PASSWORD = "secret";
    private static final String KEYSTORE_PASSWORD = "pass";

    private static final int MAX_CONN_PER_ROUTE = 10;
    private static final int MAX_CONNECTIONS = 20;

    private static final int TIMEOUT = 10 * 1000;

    private CheckBox setSystemPropCb;
    private CheckBox useClientAuthCb;

    private Button dumpTrustedCertsButton;
    private Button defaultConnectButton;
    private Button httpClientDefaultSockFactoryConnectButton;
    private Button httpClientConnectButton;
    private Button urlConnConnectButton;

    private TextView resultText;

    private static String trustStorePropDefault;

    private File localTrustStoreFile;

    private KeyStore keyStore;

    /** Called when the activity is first created. */
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);

        setContentView(R.layout.main);
        setProgressBarIndeterminateVisibility(false);


        localTrustStoreFile = new File(getFilesDir(), "mytruststore.bks");
        trustStorePropDefault = System.getProperty("javax.net.ssl.trustStore");

        setSystemPropCb = (CheckBox) findViewById(R.id.set_system_prop_cb);
        useClientAuthCb = (CheckBox) findViewById(R.id.use_client_auth_cb);

        dumpTrustedCertsButton = (Button) findViewById(R.id.dump_trusted_certs_button);
        dumpTrustedCertsButton.setOnClickListener(this);

        defaultConnectButton = (Button) findViewById(R.id.default_connect_button);
        defaultConnectButton.setOnClickListener(this);

        httpClientDefaultSockFactoryConnectButton = (Button) findViewById(R.id.http_client_ssl_sock_factory_connect_button);
        httpClientDefaultSockFactoryConnectButton.setOnClickListener(this);

        httpClientConnectButton = (Button) findViewById(R.id.http_client_connect_button);
        httpClientConnectButton.setOnClickListener(this);

        urlConnConnectButton = (Button) findViewById(R.id.url_conn_connect_button);
        urlConnConnectButton.setOnClickListener(this);

        resultText = (TextView) findViewById(R.id.result_text);

        copyTrustStore();
    }

    private void copyTrustStore() {
        new AsyncTask<Void, Void, Void>() {

            @Override
            protected Void doInBackground(Void... params) {
                if (localTrustStoreFile.exists()) {
                    return null;
                }

                try {
                    InputStream in = getResources().openRawResource(
                            R.raw.mytruststore);
                    FileOutputStream out = new FileOutputStream(
                            localTrustStoreFile);
                    byte[] buff = new byte[1024];
                    int read = 0;

                    try {
                        while ((read = in.read(buff)) > 0) {
                            out.write(buff, 0, read);
                        }
                    } finally {
                        in.close();

                        out.flush();
                        out.close();
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }

                return null;
            }
        }.execute();
    }

    @Override
    public void onClick(View v) {
        if (v.getId() == R.id.dump_trusted_certs_button) {
            setPropAndDumpCerts();
        } else if (v.getId() == R.id.default_connect_button) {
            defaultConnect();
        } else if (v.getId() == R.id.http_client_ssl_sock_factory_connect_button) {
            httpClientDefaultSocketFactoryConnect();
        } else if (v.getId() == R.id.http_client_connect_button) {
            httpClientConnect();
        } else if (v.getId() == R.id.url_conn_connect_button) {
            urlConnConnect();
        }
    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        MenuInflater inflater = getMenuInflater();
        inflater.inflate(R.menu.main, menu);

        return super.onCreateOptionsMenu(menu);
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == R.id.menu_add_cert) {
            addCertifciatesFromExternalStroage();
        } else if (item.getItemId() == R.id.menu_remove_cert) {
            removeCertificates();
        }

        return super.onOptionsItemSelected(item);
    }

    abstract class ManipulateTrustStoreTask extends
            AsyncTask<Void, Void, Integer> {

        Exception error;

        @Override
        protected void onPreExecute() {
            setProgressBarIndeterminateVisibility(true);
        }

        @Override
        protected Integer doInBackground(Void... params) {
            try {
                return manipulate();
            } catch (GeneralSecurityException e) {
                Log.e(TAG, "Security Error: " + e.getMessage(), e);
                error = e;

                return null;
            } catch (IOException e) {
                Log.e(TAG, "I/O Error: " + e.getMessage(), e);
                error = e;

                return null;
            }
        }

        protected abstract int manipulate() throws GeneralSecurityException,
                IOException;

        protected abstract String getSuccessMessage();

        protected void saveTrustStore(KeyStore localTrustStore)
                throws IOException, GeneralSecurityException {
            FileOutputStream out = new FileOutputStream(localTrustStoreFile);
            localTrustStore.store(out, TRUSTSTORE_PASSWORD.toCharArray());
        }

        @Override
        protected void onPostExecute(Integer result) {
            setProgressBarIndeterminateVisibility(false);

            if (result != null) {
                Toast.makeText(MainActivity.this,
                        String.format(getSuccessMessage(), result),
                        Toast.LENGTH_LONG).show();
            } else {
                Toast.makeText(
                        MainActivity.this,
                        "Error manipulating local trust store: "
                                + error.getMessage(), Toast.LENGTH_LONG).show();
            }
        }
    }

    private void addCertifciatesFromExternalStroage() {
        new ManipulateTrustStoreTask() {

            @Override
            protected int manipulate() throws GeneralSecurityException,
                    IOException {
                String[] certs = listCertificateFiles();
                KeyStore localTrustStore = loadTrustStore();

                int certsAdded = 0;
                for (String certFilename : certs) {
                    File certFile = new File(
                            Environment.getExternalStorageDirectory(),
                            certFilename);
                    X509Certificate cert = readCertificate(certFile);
                    String alias = hashName(cert.getSubjectX500Principal());
                    localTrustStore.setCertificateEntry(alias, cert);
                    certsAdded++;
                }

                saveTrustStore(localTrustStore);

                return certsAdded;
            }

            @Override
            protected String getSuccessMessage() {
                return "Added %d certificate(s) to local trust store.";
            }
        }.execute();
    }

    private static String[] listCertificateFiles() {
        File externalStorage = Environment.getExternalStorageDirectory();
        FilenameFilter ff = new FilenameFilter() {

            @Override
            public boolean accept(File dir, String filename) {
                if (filename.contains(".")) {
                    String[] filenameExt = filename.split("\\.");
                    String ext = filenameExt[filenameExt.length - 1]
                            .toLowerCase();
                    if (ext.equals("cer") || ext.equals("der")) {
                        return true;
                    }
                }

                return false;
            }
        };

        return externalStorage.list(ff);
    }

    private void removeCertificates() {
        new ManipulateTrustStoreTask() {

            @Override
            protected int manipulate() throws GeneralSecurityException,
                    IOException {
                String[] certs = listCertificateFiles();
                KeyStore localTrustStore = loadTrustStore();

                int certsRemoved = 0;
                for (String certFilename : certs) {
                    File certFile = new File(
                            Environment.getExternalStorageDirectory(),
                            certFilename);
                    X509Certificate cert = readCertificate(certFile);
                    String alias = hashName(cert.getSubjectX500Principal());
                    localTrustStore.deleteEntry(alias);
                    certsRemoved++;
                }

                saveTrustStore(localTrustStore);

                return certsRemoved;
            }

            @Override
            protected String getSuccessMessage() {
                return "Removed %d certificate(s) from local trust store.";
            }
        }.execute();
    }

    private static X509Certificate readCertificate(File file) {
        if (!file.isFile()) {
            return null;
        }

        InputStream is = null;
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X509");
            is = new BufferedInputStream(new FileInputStream(file));
            return (X509Certificate) cf.generateCertificate(is);
        } catch (IOException e) {
            return null;
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } finally {
            try {
                is.close();
            } catch (IOException e) {
            }
        }
    }

    private static String hashName(X500Principal principal) {
        try {
            byte[] digest = MessageDigest.getInstance("MD5").digest(
                    principal.getEncoded());

            String result = Integer.toString(leInt(digest), 16);
            if (result.length() > 8) {
                StringBuffer buff = new StringBuffer();
                int padding = 8 - result.length();
                for (int i = 0; i < padding; i++) {
                    buff.append("0");
                }
                buff.append(result);

                return buff.toString();
            }

            return result;
        } catch (NoSuchAlgorithmException e) {
            throw new AssertionError(e);
        }
    }

    private static int leInt(byte[] bytes) {
        int offset = 0;
        return ((bytes[offset++] & 0xff) << 0)
                | ((bytes[offset++] & 0xff) << 8)
                | ((bytes[offset++] & 0xff) << 16)
                | ((bytes[offset] & 0xff) << 24);
    }

    private void setPropAndDumpCerts() {
        try {
            if (setSystemPropCb.isChecked()) {
                System.setProperty("javax.net.ssl.trustStore",
                        localTrustStoreFile.getAbsolutePath());
            }
            Log.d(TAG,
                    "javax.net.ssl.trustStore: "
                            + System.getProperty("javax.net.ssl.trustStore"));
            dumpTrustedCerts();
        } finally {
            if (trustStorePropDefault != null) {
                System.setProperty("javax.net.ssl.trustStore",
                        trustStorePropDefault);
            } else {
                System.clearProperty("javax.net.ssl.trustStore");
            }
        }
    }

    abstract class GetHtmlTask extends AsyncTask<Void, Void, String> {
        Exception error;

        @Override
        protected void onPreExecute() {
            setProgressBarIndeterminateVisibility(true);
            resultText.setText("");
        }

        @Override
        protected void onPostExecute(String result) {
            setProgressBarIndeterminateVisibility(false);

            if (result != null) {
                resultText.setText(Html.fromHtml(result));
            } else {
                Toast.makeText(MainActivity.this,
                        "Error: " + error.getMessage(), Toast.LENGTH_LONG)
                        .show();
            }
        }
    }

    private void defaultConnect() {
        new GetHtmlTask() {

            @Override
            protected String doInBackground(Void... arg0) {
                try {
                    if (setSystemPropCb.isChecked()) {
                        System.setProperty("javax.net.ssl.trustStore",
                                localTrustStoreFile.getAbsolutePath());
                    }

                    URL url = new URL(SERVER_AUTH_URL);
                    java.net.URLConnection conn = url.openConnection();
                    HttpsURLConnection urlConnection = (HttpsURLConnection) conn;
                    urlConnection.setUseCaches(false);
                    urlConnection.setRequestProperty("Connection", "close");
                    urlConnection.setConnectTimeout(TIMEOUT);
                    urlConnection.setReadTimeout(TIMEOUT);

                    try {
                        Log.d(TAG, "ClientSessionContext: "
                                + SSLContext.getInstance("TLS")
                                        .getClientSessionContext().getClass()
                                        .getName());

                        Log.d(TAG, "SSLSocketFactory "
                                + urlConnection.getSSLSocketFactory()
                                        .getClass().getName());
                        urlConnection.connect();

                        if (urlConnection.getResponseCode() != HttpURLConnection.HTTP_OK) {
                            return urlConnection.getResponseMessage();
                        }

                        return readLines(urlConnection.getInputStream(),
                                urlConnection.getContentEncoding());
                    } finally {
                        urlConnection.disconnect();
                    }
                } catch (Exception e) {
                    Log.d(TAG, "Error: " + e.getMessage(), e);

                    error = e;
                    return null;
                } finally {
                    if (trustStorePropDefault != null) {
                        System.setProperty("javax.net.ssl.trustStore",
                                trustStorePropDefault);
                    } else {
                        System.clearProperty("javax.net.ssl.trustStore");
                    }
                }
            }
        }.execute();
    }

    private void httpClientConnect() {
        new GetHtmlTask() {

            @Override
            protected String doInBackground(Void... arg0) {
                try {
                    boolean useClientAuth = useClientAuthCb.isChecked();
                    SSLContext sslContext = createSslContext(useClientAuth);
                    MySSLSocketFactory socketFactory = new MySSLSocketFactory(
                            sslContext, new BrowserCompatHostnameVerifier());
                    HttpClient client = createHttpClient(socketFactory);

                    HttpGet get = new HttpGet(useClientAuth ? CLIENT_AUTH_URL
                            : SERVER_AUTH_URL);
                    HttpResponse response = client.execute(get);
                    if (response.getStatusLine().getStatusCode() != 200) {
                        return "Error: " + response.getStatusLine();
                    } else {
                        return EntityUtils.toString(response.getEntity());
                    }
                } catch (Exception e) {
                    Log.d(TAG, "Error: " + e.getMessage(), e);

                    error = e;
                    return null;
                }
            }
        }.execute();
    }

    private void httpClientDefaultSocketFactoryConnect() {
        new GetHtmlTask() {

            @Override
            protected String doInBackground(Void... arg0) {
                try {
                    KeyStore trustStore = loadTrustStore();
                    KeyStore keyStore = loadKeyStore();

                    boolean useClientAuth = useClientAuthCb.isChecked();
                    HttpClient client = createHttpClientWithDefaultSocketFactory(
                            keyStore, trustStore);

                    HttpGet get = new HttpGet(useClientAuth ? CLIENT_AUTH_URL
                            : SERVER_AUTH_URL);
                    HttpResponse response = client.execute(get);
                    if (response.getStatusLine().getStatusCode() != 200) {
                        return "Error: " + response.getStatusLine();
                    } else {
                        return EntityUtils.toString(response.getEntity());
                    }
                } catch (Exception e) {
                    Log.d(TAG, "Error: " + e.getMessage(), e);

                    error = e;
                    return null;
                }
            }
        }.execute();
    }

    private void urlConnConnect() {
        new GetHtmlTask() {

            @Override
            protected String doInBackground(Void... arg0) {
                try {
                    boolean useClientAuth = useClientAuthCb.isChecked();
                    SSLContext sslCtx = createSslContext(useClientAuth);

                    URL url = new URL(useClientAuth ? CLIENT_AUTH_URL
                            : SERVER_AUTH_URL);
                    HttpsURLConnection urlConnection = (HttpsURLConnection) url
                            .openConnection();
                    urlConnection.setUseCaches(false);
                    urlConnection.setRequestProperty("Connection", "close");
                    urlConnection.setConnectTimeout(TIMEOUT);
                    urlConnection.setReadTimeout(TIMEOUT);

                    urlConnection
                            .setSSLSocketFactory(sslCtx.getSocketFactory());

                    HostnameVerifier verifier = urlConnection
                            .getHostnameVerifier();
                    Log.d(TAG, "hostname verifier: "
                            + verifier.getClass().getName());
                    try {
                        urlConnection.connect();

                        if (urlConnection.getResponseCode() != HttpURLConnection.HTTP_OK) {
                            return urlConnection.getResponseMessage();
                        }

                        return readLines(urlConnection.getInputStream(),
                                urlConnection.getContentEncoding());
                    } finally {
                        urlConnection.disconnect();
                    }
                } catch (Exception e) {
                    Log.d(TAG, "Error: " + e.getMessage(), e);

                    error = e;
                    return null;
                }
            }
        }.execute();
    }

    private void dumpTrustedCerts() {
        try {
            TrustManagerFactory tmf = TrustManagerFactory
                    .getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null);
            X509TrustManager xtm = (X509TrustManager) tmf.getTrustManagers()[0];
            StringBuffer buff = new StringBuffer();
            for (X509Certificate cert : xtm.getAcceptedIssuers()) {
                String certStr = "S:" + cert.getSubjectDN().getName() + "\nI:"
                        + cert.getIssuerDN().getName();
                Log.d(TAG, certStr);
                buff.append(certStr + "\n\n");
            }

            resultText.setText(buff.toString());
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private HttpClient createHttpClientWithDefaultSocketFactory(
            KeyStore keyStore, KeyStore trustStore) {
        try {
            SSLSocketFactory sslSocketFactory = SSLSocketFactory
                    .getSocketFactory();
            if (keyStore != null && trustStore != null) {
                sslSocketFactory = new SSLSocketFactory(keyStore,
                        KEYSTORE_PASSWORD, trustStore);
            } else if (trustStore != null) {
                sslSocketFactory = new SSLSocketFactory(trustStore);
            }

            return createHttpClient(sslSocketFactory);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private HttpClient createHttpClient(SocketFactory socketFactory) {
        HttpParams params = new BasicHttpParams();
        HttpProtocolParams.setContentCharset(params,
                HTTP.DEFAULT_CONTENT_CHARSET);
        HttpConnectionParams.setConnectionTimeout(params, TIMEOUT);
        ConnPerRoute connPerRoute = new ConnPerRouteBean(MAX_CONN_PER_ROUTE);
        ConnManagerParams.setMaxConnectionsPerRoute(params, connPerRoute);
        ConnManagerParams.setMaxTotalConnections(params, MAX_CONNECTIONS);

        SchemeRegistry schemeRegistry = new SchemeRegistry();
        schemeRegistry.register(new Scheme("http", PlainSocketFactory
                .getSocketFactory(), 80));
        SocketFactory sslSocketFactory = SSLSocketFactory.getSocketFactory();
        if (socketFactory != null) {
            sslSocketFactory = socketFactory;
        }
        schemeRegistry.register(new Scheme("https", sslSocketFactory, 443));
        ClientConnectionManager cm = new ThreadSafeClientConnManager(params,
                schemeRegistry);

        return new DefaultHttpClient(cm, params);
    }

    private KeyStore loadTrustStore() {
        try {
            KeyStore localTrustStore = KeyStore.getInstance("BKS");
            //            InputStream in = getResources().openRawResource(R.raw.mytruststore);
            InputStream in = new FileInputStream(localTrustStoreFile);
            try {
                localTrustStore.load(in, TRUSTSTORE_PASSWORD.toCharArray());
            } finally {
                in.close();
            }

            return localTrustStore;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private KeyStore loadKeyStore() {
        if (keyStore != null) {
            return keyStore;
        }

        try {
            keyStore = KeyStore.getInstance("PKCS12");
            InputStream in = getResources().openRawResource(R.raw.mytruststore);
            try {
                keyStore.load(in, KEYSTORE_PASSWORD.toCharArray());
            } finally {
                in.close();
            }

            return keyStore;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private SSLContext createSslContext(boolean clientAuth)
            throws GeneralSecurityException {
        KeyStore trustStore = loadTrustStore();
        KeyStore keyStore = loadKeyStore();

        MyTrustManager myTrustManager = new MyTrustManager(trustStore);
        TrustManager[] tms = new TrustManager[] { myTrustManager };

        KeyManager[] kms = null;
        if (clientAuth) {
            KeyManagerFactory kmf = KeyManagerFactory
                    .getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, KEYSTORE_PASSWORD.toCharArray());
            kms = kmf.getKeyManagers();
        }

        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kms, tms, null);

        return context;
    }

    private String readLines(InputStream in, String encoding)
            throws IOException {
        try {
            StringBuffer buff = new StringBuffer();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    in, encoding != null ? encoding : "UTF-8"));
            String line = null;
            while ((line = reader.readLine()) != null) {
                buff.append(line + "\n");
            }

            return buff.toString();
        } finally {
            in.close();
        }
    }
}
