using System;
using AS2_Proof_of_Concept.AS2Helper;

namespace AS2_Proof_of_Concept
{
    class Program
    {
        static void Main(string[] args)
        {
            string inboundUri = null;

            do
            {
                Console.WriteLine("Where should I send this?");
                inboundUri = Console.ReadLine();
            } while (string.IsNullOrEmpty(inboundUri));

            FilePickUp pickUp = new FilePickUp();
            Uri uri = new Uri(inboundUri);

            pickUp.PickUpFiles(uri);

            Console.WriteLine("Press any key to exit.");
            Console.ReadKey();
        }
    }
}
