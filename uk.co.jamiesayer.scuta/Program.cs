using System;
using System.Reflection;
using System.Diagnostics;
using System.Collections.Generic;
using System.Threading;
using uk.co.jamiesayer.helperfunctions;
using System.Text.RegularExpressions;
using System.ServiceProcess;
using System.Configuration.Install;
using System.ComponentModel;
using uk.co.jamiesayer.scuta.msgforwarding;
using uk.co.jamiesayer.fwctrl;
using System.IO;
using System.Collections;
using System.Net.Http;
using uk.co.jamiesayer.iotlibrary;
using System.Threading.Tasks;
using uk.co.jamiesayer.library.powerbistreaming;

namespace uk.co.jamiesayer.scuta
{

    public class IOTAttackInstance
    {
        public string ip { get; set; }
        public string userName { get; set; }
        public Guid attemptId { get; set; }
        public string sourceCountry { get; set; }
        public DateTime timestamp { get; set; }
        public string date { get; set; }

    }

    public class CarnifexWorker : Worker
    {
        //Worker to execute IP bans

        public string TAG = "Carnifex Worker";
        public int id;
        public string user;
        public string ip;

        public async Task recordToIOT(string ip, string username)
        {
            HelperFunctions.debugMessage(0, "Begin post to IOT", 0);
            HelperFunctions.debugMessage(0, "Begin post to IOT.", 2, 103, HelperFunctions.MessageType.Information, TAG);
            string sourceCountry = ResolveCountry(ip);

            IOTAttackInstance attackInstance = new IOTAttackInstance { userName = username, ip = ip, sourceCountry = sourceCountry, attemptId = Guid.NewGuid(), timestamp = DateTime.Now };

            await IOTCtrl.Send(attackInstance);
            
        }

        public async Task recordToPBI(string ip, string username)
        {
            HelperFunctions.debugMessage(0, "Begin POST to PBI.", 0, 500, HelperFunctions.MessageType.Information, TAG);
            string sourceCountry = ResolveCountry(ip);
            IOTAttackInstance attackInstance = new IOTAttackInstance { userName = username, ip = ip, sourceCountry = sourceCountry, attemptId = Guid.NewGuid(), timestamp = DateTime.Now, date = (DateTime.Now.ToShortDateString()) };

            try
            {
                await PowerBICtrl.post(attackInstance);
            }
            catch (Exception ex)
            {
                HelperFunctions.debugMessage(0, "An error occurred POSTing to PBI.", 0, 590, HelperFunctions.MessageType.Error, TAG);
            }
            
        }

        public static string ResolveCountry(string IP)
        {
            HelperFunctions.debugMessage(0, String.Format("Begin ip to country resolution for {0}", IP), 0);

            if (!String.IsNullOrEmpty(ScutaConfig.ipCountryResolverAPIKey) && !String.IsNullOrEmpty(ScutaConfig.ipCountryResolverAPIServiceURI))
            {
                // Build resolver API service URI
                // I use IP Info DB, similar to http://api.ipinfodb.com/v3/ip-city/?key=<KEY>&ip=<IP>

                string serviceQueryUri = String.Format("{0}/?key={1}&ip={2}", ScutaConfig.ipCountryResolverAPIServiceURI, ScutaConfig.ipCountryResolverAPIKey, IP);

                var response = ScutaService.httpClient.GetAsync(serviceQueryUri).Result;

                if (response.IsSuccessStatusCode)
                {
                    // by calling .Result you are performing a synchronous call
                    var responseContent = response.Content;

                    // by calling .Result you are synchronously reading the result
                    string responseString = responseContent.ReadAsStringAsync().Result;


                    string[] responseParts = null;

                    try
                    {
                        responseParts = responseString.Split(';');
                    }
                    catch { }

                    if (responseParts != null)
                    {
                        if (responseParts.Length >= 5)
                        {
                            return responseParts[4];
                        }
                        else
                        {
                            return "";
                        }
                    }
                    else
                    {
                        return "";
                    }


                }
                else
                {
                    return "";
                }
            }
            else
            {
                HelperFunctions.debugMessage(0, String.Format("Resolve country: Missing service IP or Key", IP), 0);
                return "";
            }
        }

        public void ban(string ip, string user)
        {
            // Ban the IP indicated in the event log message

            FWCtrl.ban(ip, ScutaConfig.banMinutes, user);

            if (ScutaConfig.enableIOT) { recordToIOT(ip, user); };
            if (ScutaConfig.enablePBI) { recordToPBI(ip, user); };

            if (ScutaConfig.enableMessageForwarding) { MsgForwarding forwarder = new MsgForwarding(); forwarder.SendMessage(String.Format("Banning user {0} from {1}", user, ip)); }

            

        }

        public void Begin()
        {
            HelperFunctions.debugMessage(id, "Begin.", 0, 100, HelperFunctions.MessageType.Information, TAG);
            ban(ip, user);
        }

        public int GetId()
        {
            return id;
        }

        public void SetId(int id)
        {
            this.id = id;
        }

        public CarnifexWorker(string user, string ip)
        {
            this.ip = ip;
            this.user = user;
        }
    }

    public interface Worker
    {
        void Begin();
        int GetId();
        void SetId(int id);
    }

    public class EventWorker : Worker
    {
        public string TAG = "EventLogWorker";
        public int id { get; set; }
        private object source;
        private EntryWrittenEventArgs entry;
        static AutoResetEvent signal;

        public EventWorker(object source, EntryWrittenEventArgs entry)
        {
            this.source = source;
            this.entry = entry;
        }

        public void Begin()
        {
            HelperFunctions.debugMessage(id, "Event Processor Worker starting...", 3);
            if (entry.Entry.Source.ToString().Equals("sshd"))
            {
                if (entry.Entry.Message.ToString().Contains("Invalid user"))
                {
                    ban(entry.Entry.Message.ToString());
                }

                if (entry.Entry.Message.ToString().Contains("Failed password"))
                {
                    int pid;

                    Int32.TryParse((entry.Entry.Message.ToString().Split(':')[1].Replace(" PID ","" )), out pid);

                    int count = FailedLoginCorrelator.failedLogin(pid);

                    if (count > 1)
                    {
                        ban(entry.Entry.Message.ToString());
                    }
                }

            }
            

        }

        public void ban(string sshdmessage)
        {
            // Ban the IP indicated in the event log message

            Regex IPV4 = new Regex(@"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b");
            Regex User = new Regex(@"(?<=user ).*?(?= from)");

            Match ip = IPV4.Match(sshdmessage);
            Match user = User.Match(sshdmessage);

            if (ScutaConfig.enableIOT) {

                
            };

            if (ScutaConfig.enableMessageForwarding) { MsgForwarding forwarder = new MsgForwarding(); forwarder.SendMessage(String.Format("Banning user {0} from {1}", user.Value, ip.Value)); }

            FWCtrl.ban(ip.Value, ScutaConfig.banMinutes, user.Value );            

        }

        public int GetId()
        {
            return this.id;
        }

        public void SetId(int id)
        {
            this.id = id;
        }
    }

    public class EventLogWorker : Worker
    {
        public string TAG = "EventWorker";
        public int id { get; set; }
        public AutoResetEvent signal;

        public EventLogWorker()
        {

        }

        public void Begin()
        {
            HelperFunctions.debugMessage(id, "Event Log Worker starting...", 3);

            signal = new AutoResetEvent(false);
            EventLog monitoredLog = new EventLog("Security", ".", "Microsoft Windows security auditing.");

            monitoredLog.EntryWritten += new EntryWrittenEventHandler(HandleEvent);
            monitoredLog.EnableRaisingEvents = true;
            while (1!=2)
            {
                signal.WaitOne();
            }


        }

        public void HandleEvent(object source, EntryWrittenEventArgs entry)
        {
            HelperFunctions.debugMessage(0, "Event trigger occurred.", 3);
            EventWorker newWorker = new EventWorker(source, entry);
            ThreadManager.LaunchWorker(newWorker);
            this.signal.Set();
            
        }

        public int GetId()
        {
            return this.id;
        }

        public void SetId(int id)
        {
            this.id = id;
        }
    }

    public class LogFileWorker : Worker
    {

        //Worker to watch a file based log

        public string TAG = "ExcubiarumFileWorker";
        public int id { get; set; }
        public AutoResetEvent signal;
        private string logFilePath;
        private string logFileName;
        private long highWaterMark;
        private object fileLock;

        public LogFileWorker(string logFilePath, string logFileName)
        {
            this.logFileName = logFileName;
            this.logFilePath = logFilePath;
            this.fileLock = new object();
            initialiseHighWaterMark();

            HelperFunctions.debugMessage(0, (String.Format("Watching {0}", (this.logFilePath + "\\" + this.logFileName))), 0, 100, HelperFunctions.MessageType.Information, TAG);
        }

        private void initialiseHighWaterMark()
        {
            if (File.Exists(this.logFilePath + "\\" + this.logFileName))
            {
                using (var file = new FileStream(((this.logFilePath + "\\" + this.logFileName)), FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (var sr = new StreamReader(file))
                {
                    //Move to the high water mark

                    for (int i = 1; i <= this.highWaterMark; ++i) { sr.ReadLine(); }

                    //Process each subsequent line

                    while (!sr.EndOfStream)
                    {
                        sr.ReadLine();
                        this.highWaterMark++;
                    }

                    sr.Close();
                    sr.Dispose();
                    file.Close();
                }
            }
        }

        public void Begin()
        {

            if (Directory.Exists(this.logFilePath))
            {
                FileSystemWatcher watcher = new FileSystemWatcher();
                watcher.Path = this.logFilePath;
                signal = new AutoResetEvent(false);
                watcher.NotifyFilter = NotifyFilters.LastWrite;

                watcher.Filter = this.logFileName;

                watcher.Changed += new FileSystemEventHandler(OnChanged);

                watcher.EnableRaisingEvents = true;

                while (1 != 2)
                {
                    signal.WaitOne();
                }
            }
            else
            {
                HelperFunctions.debugMessage(0, String.Format("Watched directory {0} does not exist.", this.logFilePath), 0);
            }

        }

        // Define the event handlers.
        private void OnChanged(object source, FileSystemEventArgs e)
        {
            // Specify what is done when a file is changed, created, or deleted.

            HelperFunctions.debugMessage(0, "Change in log file detected.", 5, 100, HelperFunctions.MessageType.Information, TAG);

            lock (this.fileLock)
            {
                ArrayList bannedThisIteration = new ArrayList();//Because of the way the way data is flushed to disk in the log file, there is potential for bans to be duplicated. As such we'll keep a 
                                                                //list of the IPs we've banned this time round to avoid creating duplicates

                using (var file = new FileStream(e.FullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (var sr = new StreamReader(file))
                {
                    //Move to the high water mark

                    for (int i = 1; i <= this.highWaterMark; ++i) { sr.ReadLine(); }

                    //Process each subsequent line

                    while (!sr.EndOfStream)
                    {
                        string logLine = sr.ReadLine();
                        logLine = logLine.ToLower();

                        highWaterMark++;

                        Console.WriteLine(logLine);

                        Regex regxIP = new Regex(@"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b");
                        Match regxIPM = regxIP.Match(logLine);
                        string ip = regxIPM.Value;

                        if (logLine.ToLower().Contains("not listed in allowusers"))
                        {

                            Regex regxUser = new Regex(@"(?<=user ).*?(?= from)");
                            Match regxUserM = regxUser.Match(logLine);
                            string user = regxUserM.Value;

                            if (!bannedThisIteration.Contains(regxIPM.Value))
                            {
                                bannedThisIteration.Add(regxIPM.Value);
                                CarnifexWorker worker = new CarnifexWorker(user, ip);
                                ThreadManager.LaunchWorker(worker);
                                //ban(ip, user);
                            }
                        }

                        if (logLine.ToLower().Contains("failed password"))
                        {

                            Regex regxUser = new Regex(@"(?<=for ).*?(?= from)");
                            Match regxUserM = regxUser.Match(logLine);
                            string user = regxUserM.Value;

                            if (!bannedThisIteration.Contains(ip))
                            {
                                int pid;

                                Int32.TryParse((logLine.Split(' ')[0]), out pid);

                                int count = FailedLoginCorrelator.failedLogin(pid);

                                if (count > 1)
                                {
                                    bannedThisIteration.Add(ip);
                                    CarnifexWorker worker = new CarnifexWorker(user, ip);
                                    ThreadManager.LaunchWorker(worker);
                                    //ban(ip, user);
                                }
                            }
                        }

                        if (logLine.ToLower().Contains("invalid user"))
                        {

                            Regex regxUser = new Regex(@"(?<=user ).*?(?= from)");
                            Match regxUserM = regxUser.Match(logLine);
                            string user = regxUserM.Value;

                            if (!bannedThisIteration.Contains(ip))
                            {
                                int pid;

                                Int32.TryParse((logLine.Split(' ')[0]), out pid);

                                int count = FailedLoginCorrelator.failedLogin(pid);


                                bannedThisIteration.Add(ip);
                                CarnifexWorker worker = new CarnifexWorker(user, ip);
                                ThreadManager.LaunchWorker(worker);
                                //ban(ip, user);

                            }
                        }

                        if (logLine.ToLower().Contains("received disconnect from"))
                        {

                            if (!bannedThisIteration.Contains(ip))
                            {
                                int pid;

                                Int32.TryParse(ip.Replace(".",""), out pid);

                                int count = FailedLoginCorrelator.failedLogin(pid);

                                if (count > 1)
                                {
                                    bannedThisIteration.Add(ip);
                                    CarnifexWorker worker = new CarnifexWorker("", ip);
                                    ThreadManager.LaunchWorker(worker);
                                    //ban(ip, user);
                                }
                            }
                        }

                    }

                    sr.Close();
                    sr.Dispose();
                    file.Close();
                }




            }
        }


        public int GetId()
        {
            return this.id;
        }

        public void SetId(int id)
        {
            this.id = id;
        }
    }

    static class ThreadManager
    {
        static int MAXTHREADS = 20;
        public static int threadCounter;
        static Thread[] threads;
        private static string TAG = "ThreadManager";

        public static Thread LaunchWorker(Worker newWorker)
        {

            if (threads == null) { threads = new Thread[MAXTHREADS]; }

            //First do cleanup

            CleanUp();

            int newThreadHandleId = findFree();

            if (newThreadHandleId > -1)
            {
                newWorker.SetId(newThreadHandleId);
                threadCounter++;

                Thread newThread = new Thread(new ThreadStart(newWorker.Begin));
                newThread.Start();

                threads[newThreadHandleId] = newThread;
                HelperFunctions.debugMessage(0, (String.Format("Launched thread with ID '{0}'", newThreadHandleId)), 0, 100, HelperFunctions.MessageType.Information, TAG);
                return newThread;

            }
            else
            {
                HelperFunctions.debugMessage(0, "Server busy, launch request dropped.", 0, 100, HelperFunctions.MessageType.Warning, TAG);
                return null; //Server busy

            }
        }

        public static void CleanUp()
        {
            for (int i = 0; i < MAXTHREADS; i++)
            {
                if (threads[i] != null)
                {
                    if (threads[i].ThreadState == System.Threading.ThreadState.Stopped) { threads[i] = null; HelperFunctions.debugMessage(0, TAG, "Disposed thread handle " + i, 3); };
                }
            }
        }

        private static int findFree()
        {
            for (int i = 0; i < MAXTHREADS; i++)
            {
                if (threads[i] == null)
                {
                    return i;
                }
            }

            return -1; //None free
        }
   
   
    }

    static class FailedLoginCorrelator
    {

        private static Dictionary<int, FailedLogin> failedLogins;

        private class FailedLogin
        {
            public DateTime firstInstanceTime;
            public int count { get; set; }

            public FailedLogin()
            {
                this.firstInstanceTime = DateTime.UtcNow;
                this.count = 1;
            }

        }

        public static int failedLogin(int correlator)
        {
            //Record a failed login attempt for a given correlation - in the case of SSHD this will be the PID

            //Initialise the dictionary if it hasn't already been

            if (failedLogins == null) { failedLogins = new Dictionary<int, FailedLogin>(); }

            FailedLogin correlation;

            if (failedLogins.TryGetValue(correlator, out correlation))
            {
                // Correlation exists, update and return new count

                correlation.count++;
                failedLogins[correlator] = correlation;
                return correlation.count;

            }
            else
            {
                // Correlation does not exist, create and return 1
                correlation = new FailedLogin();
                failedLogins.Add(correlator, correlation);
                return 1;

            }

            cleanup();



        }

        private static void cleanup()
        {
            Dictionary<int, FailedLogin> correlationsToRemove = new Dictionary<int, FailedLogin>();

            foreach (KeyValuePair<int, FailedLogin> kvp in failedLogins)
            {
                if (kvp.Value.firstInstanceTime > (DateTime.UtcNow.AddHours(-1)))
                {
                    correlationsToRemove.Add(kvp.Key, kvp.Value);
                }
            }

            foreach (KeyValuePair<int, FailedLogin> kvp in correlationsToRemove)
            {
                try
                {
                    failedLogins.Remove(kvp.Key);
                }
                catch
                {
                    HelperFunctions.debugMessage(0, "An error occurred while attempting correlation cleanup.", 0, 101, HelperFunctions.MessageType.Warning);
                }
            }
        }

    }
    
    class ScutaService : ServiceBase
    {

        static Thread rootThread;
        public static HttpClient httpClient;
        
        public ScutaService()
        {
            this.ServiceName = "Scuta Service";
            this.EventLog.Log = "Application";

            this.CanHandlePowerEvent = false;
            this.CanHandleSessionChangeEvent = true;
            this.CanPauseAndContinue = false;
            this.CanShutdown = true;
            this.CanStop = true;

            ScutaConfig.load();
        }

        static void Main()
        {
            
            ServiceBase.Run(new ScutaService());
        }


        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
        }

        protected override void OnStart(string[] args)
        {
            base.OnStart(args);
            //Initialise
            ScutaConfig.load();
            HelperFunctions.configure(3, 3, false, true, "", "Scuta", "Scuta Service");
            HelperFunctions.debugMessage(0, ("Scuta v" + Assembly.GetExecutingAssembly().GetName().Version + " is starting..."), 0, 100, HelperFunctions.MessageType.Information); 

            FWCtrl.Setup();

            httpClient = new HttpClient();

            if (ScutaConfig.enableIOT) { IOTCtrl.Initialise(ScutaConfig.iotHubConnectionString, ScutaConfig.iotHubDeviceName, ScutaConfig.iotHubUri); }

            if (ScutaConfig.enablePBI) { PowerBICtrl.serviceURI = ScutaConfig.pbiServiceUri; PowerBICtrl.enableDebugToLog = true; };

            if (ScutaConfig.enableMessageForwarding)
            {
                MsgForwarding.Setup(ScutaConfig.messageForwardingIP, ScutaConfig.messageForwardingPort);
            }

            if (ScutaConfig.watchEventLog)
            {
                EventLogWorker newWorker = new EventLogWorker();
                rootThread = ThreadManager.LaunchWorker(newWorker);
            }

            if (ScutaConfig.watchLogFile)
            {
                LogFileWorker logFileWorker = new LogFileWorker(ScutaConfig.watchLogFilePath,ScutaConfig.watchLogFileName);
                ThreadManager.LaunchWorker(logFileWorker);
            }

        }

        protected override void OnStop()
        {
            base.OnStop();
            rootThread.Abort();
        }

         protected override void OnPause()
        {
            base.OnPause();
            rootThread.Suspend();
        }

        protected override void OnContinue()
        {
            base.OnContinue();
            rootThread.Resume();
        }

        protected override void OnShutdown()
        {
            base.OnShutdown();
            rootThread.Abort();
        }


        protected override void OnCustomCommand(int command)
        {

            base.OnCustomCommand(command);
        }

        protected override bool OnPowerEvent(PowerBroadcastStatus powerStatus)
        {
            return base.OnPowerEvent(powerStatus);
        }

        protected override void OnSessionChange(
                  SessionChangeDescription changeDescription)
        {
            base.OnSessionChange(changeDescription);
        }
    }

    [RunInstaller(true)]
    public class WindowsServiceInstaller : Installer
    {

        public WindowsServiceInstaller()
        {
            ServiceProcessInstaller serviceProcessInstaller = new ServiceProcessInstaller();
            ServiceInstaller serviceInstaller = new ServiceInstaller();

            //# Service Account Information
            serviceProcessInstaller.Account = ServiceAccount.LocalSystem;
            serviceProcessInstaller.Username = null;
            serviceProcessInstaller.Password = null;

            //# Service Information
            serviceInstaller.DisplayName = "Scuta Service";
            serviceInstaller.StartType = ServiceStartMode.Automatic;

            //# This must be identical to the WindowsService.ServiceBase name
            //# set in the constructor of WindowsService.cs
            serviceInstaller.ServiceName = "Scuta Service";

            this.Installers.Add(serviceProcessInstaller);
            this.Installers.Add(serviceInstaller);
        }
    }

    class Program
    {
        static void Main2()
        {
            //Initialise
            ScutaConfig.load();
            HelperFunctions.configure(3, 1, false, true, "", "Application", "Scuta");
            HelperFunctions.debugMessage(0, ("Scuta v" + Assembly.GetExecutingAssembly().GetName().Version + " is starting..."), 0, 100, HelperFunctions.MessageType.Information);

            FWCtrl.Setup();

            if (ScutaConfig.enableIOT) { IOTCtrl.Initialise(ScutaConfig.iotHubConnectionString, ScutaConfig.iotHubDeviceName, ScutaConfig.iotHubUri); }

            if (ScutaConfig.enableMessageForwarding)
            {
                MsgForwarding.Setup(ScutaConfig.messageForwardingIP, ScutaConfig.messageForwardingPort);
            }

            if (ScutaConfig.watchEventLog)
            {
                EventLogWorker newWorker = new EventLogWorker();
                ThreadManager.LaunchWorker(newWorker);
            }

            if (ScutaConfig.watchLogFile)
            {
                LogFileWorker logFileWorker = new LogFileWorker(ScutaConfig.watchLogFilePath, ScutaConfig.watchLogFileName);
                ThreadManager.LaunchWorker(logFileWorker);
            }



        }


    }
     
    
}
