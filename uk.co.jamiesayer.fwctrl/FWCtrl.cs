using System;
using NetFwTypeLib;
using uk.co.jamiesayer.helperfunctions;

namespace uk.co.jamiesayer.fwctrl
{

    public static class FWCtrl
    {
        const string guidFWPolicy2 = "{E2B3C97F-6AE1-41AC-817A-F6F92166D7DD}";
        const string guidRWRule = "{2C5BC43E-3369-4C33-AB0C-BE9469677AF4}";
        private static INetFwPolicy2 fwPolicy;
        private static Type typeFWPolicy2 = Type.GetTypeFromCLSID(new Guid(guidFWPolicy2));
        private static Type typeFWRule = Type.GetTypeFromCLSID(new Guid(guidRWRule));
        private static string TAG = "FWCtrl";

        public static void Setup()
        {

            fwPolicy = (INetFwPolicy2)Activator.CreateInstance(typeFWPolicy2);
            cleanup(true);



        }
        public static void ban(string IP, int minutes, string user)
        {
            if (fwPolicy == null) { Setup(); }

            HelperFunctions.debugMessage(0, (String.Format("Banning user {0} from {1} for {2} minutes.", user, IP, minutes)), 0, 101, HelperFunctions.MessageType.Information, TAG);

            INetFwRule newRule = (INetFwRule)Activator.CreateInstance(typeFWRule);
            newRule.Name = "Scuta[" + Guid.NewGuid().ToString() + "]";
            newRule.Description = ("Scuta Generated Rule -" + DateTime.UtcNow + "- Ban " + IP);
            newRule.Protocol = (int)NET_FW_IP_PROTOCOL_.NET_FW_IP_PROTOCOL_TCP;
            newRule.RemoteAddresses = IP;
            newRule.Direction = NET_FW_RULE_DIRECTION_.NET_FW_RULE_DIR_IN;
            newRule.Enabled = true;
            newRule.Grouping = "ScutaRules";
            newRule.Profiles = fwPolicy.CurrentProfileTypes;
            newRule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;
            fwPolicy.Rules.Add(newRule);

            cleanup();
        }

        private static void cleanup()
        {
            cleanup(false);
        }

        private static void cleanup(bool clearAll) //Does this need a mutex?
        {
            foreach (INetFwRule rule in fwPolicy.Rules)
            {
                if (rule.Grouping == "ScutaRules")
                {
                    string ruleAge = rule.Description.ToString().Split('-')[1];
                    DateTime ruleDT;
                    if (DateTime.TryParse(ruleAge, out ruleDT))
                    {

                        if (ruleDT < (DateTime.UtcNow.AddHours(-1)) || clearAll)
                        {
                            //Rule is older than one hour - Or we are performing startup clear-down
                            try
                            {
                                fwPolicy.Rules.Remove(rule.Name);
                                
                                HelperFunctions.debugMessage(0, (String.Format("Removed rule '{0}'.", rule.Description)), 0, 102, HelperFunctions.MessageType.Information, TAG);
                            }
                            catch
                            {
                                HelperFunctions.debugMessage(0, (String.Format("An error occurred removing rule '{0}'.", rule.Description)), 0, 103, HelperFunctions.MessageType.Error, TAG);
                            }

                        }
                    }
                    else
                    {
                        //Could not parse datetime stamp, delete rule
                        try
                        {
                            fwPolicy.Rules.Remove(rule.Name);
                            HelperFunctions.debugMessage(0, (String.Format("Removed rule '{0}'.", rule.Description)), 0, 102, HelperFunctions.MessageType.Information, TAG);
                        }
                        catch
                        {
                            HelperFunctions.debugMessage(0, (String.Format("An error occurred removing rule '{0}'.", rule.Description)), 0, 103, HelperFunctions.MessageType.Error, TAG);
                        }
                    }


                }
            }
        }
    }

}
