using System;
using AS2_Proof_of_Concept.AS2Helper;

namespace AS2_Proof_of_Concept
{
    class Program
    {
        static void Main(string[] args)
        {
            string path = null;
            string inboundUri = null;

            do
            {
                Console.WriteLine("Where should I send this?");
                inboundUri = Console.ReadLine();
                Console.WriteLine("Please enter a directory.");
                path = Console.ReadLine();
            } while (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(inboundUri));

            FilePickUp pickUp = new FilePickUp();
            Uri uri = new Uri(inboundUri);

            pickUp.PickUpFiles(uri, path);

            Console.WriteLine("Press any key to exit.");
            Console.ReadKey();
        }
    }
}
