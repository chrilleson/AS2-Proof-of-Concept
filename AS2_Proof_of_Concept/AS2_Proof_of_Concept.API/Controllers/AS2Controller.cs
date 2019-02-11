using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using nsoftware.InEDI;

namespace AS2_Proof_of_Concept.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AS2Controller : ControllerBase
    {
        [HttpGet]
        public void Get()
        {
            As2receiver as2Receiver = new As2receiver(HttpContext);

            as2Receiver.ReadRequest();

            // At this point, you should check the values of AS2From and AS2To.
            as2Receiver.Certificate = new Certificate(CertStoreTypes.cstPFXFile,
                "C:\\files\\Dump\\cert.txt", "password", "*");
            as2Receiver.SignerCert = new Certificate("C:\\files\\partnercert.cer");
            as2Receiver.LogDirectory = "C:\\as2logs";

            string receiptMessage = "";
            try
            {
                as2Receiver.ParseRequest();
                // At this point the EDIData will be populated. At a minimum
                // you will want to save EDIData to a file for later processing.
            }
            catch (InEDIException ex)
            {
                // Set the unexpected processing error status in the MDN
                as2Receiver.Config("ProcessingError=true");
                receiptMessage = ex.Message;
            }
            finally
            {
                // If no error was encountered, the component will generate a default message
                as2Receiver.CreateMDNReceipt("", "", receiptMessage);

                // Actually send the response (including the MDN receipt)
                as2Receiver.SendResponse();
            }
        }
    }
}