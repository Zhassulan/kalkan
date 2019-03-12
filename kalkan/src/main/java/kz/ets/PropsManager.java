package kz.ets;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Properties;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

public class PropsManager {

    private static Logger logger = LogManager.getLogger(PropsManager.class);
    private static volatile PropsManager _instance = null;
    private Properties appProps;

    private PropsManager()	{
        appProps = new Properties();
        try {
            appProps.load(PropsManager.class.getResourceAsStream("/app.properties"));
        }
        catch (FileNotFoundException ex) {
            logger.info(ex.getMessage(), ex);
        }
        catch (IOException ex) {
            logger.error(ex.getMessage(), ex);
        }
    }

    public static synchronized PropsManager getInstance() {
        if (_instance == null)
            synchronized (PropsManager.class) {
                if (_instance == null)
                    _instance = new PropsManager();
            }
        return _instance;
    }

    public String getProperty(String param)	{
        return appProps.getProperty(param);
    }

    public void setValueProperty(String key, String value)	{
        appProps.setProperty(key, value);
        try {
            appProps.store(new FileOutputStream("app.properties"), "new value " + value + " for key " + key);
        } catch (IOException e) {
            logger.error(e.getMessage(), e);
        }
    }
}