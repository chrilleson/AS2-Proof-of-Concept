using System;
using System.Data.SQLite;
using System.IO;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using MimeKit.Cryptography;

namespace AS2_Proof_of_Concept.WebAPI
{
    public class MySecureMimeContext : DefaultSecureMimeContext
    {
        public MySecureMimeContext() : base(OpenDatabase(@"C:\files\certdb\certificateDB.db"))
        {
        }

        static IX509CertificateDatabase OpenDatabase(string fileName)
        {
            var builder = new SQLiteConnectionStringBuilder();
            builder.DateTimeFormat = SQLiteDateFormats.Ticks;
            builder.DataSource = fileName;

            if (!File.Exists(fileName))
                SQLiteConnection.CreateFile(fileName);

            var sqlite = new SQLiteConnection(builder.ConnectionString);
            sqlite.Open();

            return new SqliteCertificateDatabase(sqlite, "password");
        }
    }
}
