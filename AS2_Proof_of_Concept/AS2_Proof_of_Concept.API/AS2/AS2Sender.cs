using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using nsoftware.InEDI;

namespace AS2_Proof_of_Concept.API.AS2
{
    public class AS2Sender
    {
        [HttpPost]
        public void Post()
        {
            As2sender as2Sender = new As2sender
            {
                AS2From = "TestAS2Sender",
                AS2To = "TestAS2Receiver",
                SigningCert = new Certificate(CertStoreTypes.cstPFXFile,
                    "C:\\files\\PickUp\\cert.txt", "password", "*")
            };


            // Your private certificate. Used to sign the outgoing messages.

            // Your trading partner's public certificate. Used to encrypt the outgoing message.
            as2Sender.RecipientCerts.Add(new Certificate(CertStoreTypes.cstPublicKeyFile,
                "C:\\files\\partnercert.cer", "", "*"));

            // To request an MDN (Message Disposition Notification) based receipt, you
            // should set the MDNTo property. By default the component will request a
            // SIGNED receipt, with a Received-Content-MIC value that establishes
            // digital non-repudiation.
            as2Sender.MDNTo = "christoffer.ljungqvist@edisolutions.se"; // Note: the actual value is irrelevant;

            // If you set a log directory, the component will produce detailed log files.
            as2Sender.LogDirectory = "C:\\logs";

            // The URL to which the request will be posted.
            as2Sender.URL = "C:\\files\\Dump\\";

            as2Sender.EDIData = new EDIData();
            as2Sender.EDIData.EDIType = "application/edi-x12";
            //as2Sender.EDIData.Data = data;

            // Send request and verify the MDN. This call to Post will throw an exception
            // if any errors or warnings occur.
            as2Sender.Post();

            // At this point the MDNReceipt property may be inspected.
            Console.WriteLine(as2Sender.MDNReceipt.Message);
        }
    }
}
