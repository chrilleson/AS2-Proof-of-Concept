using System.Web;
using System.Web.Configuration;

namespace AS2_Proof_of_Concept.WebApplication
{
    /// <summary>
    /// Summary description for AS2Listener
    /// </summary>
    public class AS2Listener : IHttpHandler
    {
        public void ProcessRequest(HttpContext context)
        {
            string stringTo = context.Request.Headers["AS2-To"];
            string stringFrom = context.Request.Headers["AS2-From"];

            if (context.Request.HttpMethod == "POST" || context.Request.HttpMethod == "PUT" ||
                (context.Request.HttpMethod == "GET" && context.Request.QueryString.Count > 0))
            {
                if (string.IsNullOrEmpty(stringFrom) || string.IsNullOrEmpty(stringTo))
                {
                    //Invalid AS2 Request.
                    //Section 6.2 The AS2-To and AS2-From header fields MUST be present
                    //in all AS2 messages
                    if (!(context.Request.HttpMethod == "GET" && context.Request.QueryString[0].Length == 0))
                    {
                        As2Receive.BadRequest(context.Response, "Invalid or unauthorized AS2 request received.");
                    }
                }
                else
                {
                    As2Receive.Process(context, WebConfigurationManager.AppSettings["DropLocation"]);
                }
            }
            else
            {
                As2Receive.GetMessage(context.Response);
            }
        }

        public bool IsReusable => false;
    }
}