using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.IO;
using System.Net.Sockets;

namespace uk.co.jamiesayer.scuta.msgforwarding
{
    class MsgForwarding
    {

        private static IPEndPoint remoteEndpoint;

        private Socket socket;

        public static void Setup(string setWatcherIP, int setWatcherPort)
        {
            remoteEndpoint = new IPEndPoint(IPAddress.Parse(setWatcherIP), setWatcherPort);

        }

        public MsgForwarding()
        {
            this.socket = new Socket(remoteEndpoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);
        }

        public void SendMessage(string message)
        {
            
            try
            {
                this.socket.Connect(remoteEndpoint);

                if (this.socket.Connected)
                {
                    byte[] sendBytes = System.Text.Encoding.ASCII.GetBytes(message);

                    this.socket.Send(sendBytes, sendBytes.Length, SocketFlags.None);

                    this.socket.Shutdown(SocketShutdown.Both);

                    this.socket.Close();

                }

            }
            catch { }

            


        }


    }
}
