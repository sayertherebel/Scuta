using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Configuration;


namespace uk.co.jamiesayer.scuta
{
    public static class ScutaConfig
    {
        public static string logName;
        public static string logSourceName;
        public static int banMinutes;
        public static bool enableMessageForwarding;
        public static bool enableIOT;
        public static bool enablePBI;
        public static string messageForwardingIP;
        public static int messageForwardingPort;
        public static string iotHubDeviceName;
        public static string iotHubConnectionString;
        public static string iotHubUri;
        public static string pbiServiceUri;
        public static bool watchEventLog;
        public static bool watchLogFile;
        public static string watchLogFilePath;
        public static string watchLogFileName;
        public static string ipCountryResolverAPIServiceURI;
        public static string ipCountryResolverAPIKey;

        public static void load()
        {
            logName = System.Configuration.ConfigurationManager.AppSettings["EVTLOGNAME"];
            logSourceName = System.Configuration.ConfigurationManager.AppSettings["EVTLOGSOURCE"];
            Int32.TryParse(System.Configuration.ConfigurationManager.AppSettings["BANMINUTES"], out banMinutes);
            messageForwardingIP = System.Configuration.ConfigurationManager.AppSettings["MSGFORWARDINGIP"];
            Int32.TryParse(System.Configuration.ConfigurationManager.AppSettings["MSGFORWARDINGPORT"], out messageForwardingPort);
            iotHubDeviceName = System.Configuration.ConfigurationManager.AppSettings["IOTDEVICEID"];
            iotHubConnectionString = System.Configuration.ConfigurationManager.AppSettings["IOTCONNECTIONSTRING"];
            iotHubUri = System.Configuration.ConfigurationManager.AppSettings["IOTHUBURI"];
            pbiServiceUri = System.Configuration.ConfigurationManager.AppSettings["PBISERVICEURI"];
            watchLogFilePath = System.Configuration.ConfigurationManager.AppSettings["WATCHLOGFILEPATH"];
            watchLogFileName = System.Configuration.ConfigurationManager.AppSettings["WATCHLOGFILENAME"];
            ipCountryResolverAPIServiceURI = System.Configuration.ConfigurationManager.AppSettings["IPCOUNTRYRESOLVERAPISERVICEURI"];
            ipCountryResolverAPIKey = System.Configuration.ConfigurationManager.AppSettings["IPCOUNTRYRESOLVERAPIKEY"];

            if (System.Configuration.ConfigurationManager.AppSettings["ENABLEIOT"].ToUpper() == "TRUE")
            {
                enableIOT = true;
            }
            else
            {
                enableIOT = false;
            }

            if (System.Configuration.ConfigurationManager.AppSettings["ENABLEPBI"].ToUpper() == "TRUE")
            {
                enablePBI = true;
            }
            else
            {
                enablePBI = false;
            }

            if (System.Configuration.ConfigurationManager.AppSettings["WATCHEVENTLOG"].ToUpper() == "TRUE")
            {
                watchEventLog = true;
            }
            else
            {
                watchEventLog = false;
            }

            if (System.Configuration.ConfigurationManager.AppSettings["WATCHLOGFILE"].ToUpper() == "TRUE")
            {
                watchLogFile = true;
            }
            else
            {
                watchLogFile = false;
            }

            if (System.Configuration.ConfigurationManager.AppSettings["ENABLEMESSAGEFORWARDING"].ToUpper() == "TRUE")
            {
                enableMessageForwarding = true;
            }
            else
            {
                enableMessageForwarding = false;
            }
        }
    }

}
