using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using MongoDB.Driver;

namespace IndividualAuthentication_MongoDB.Models
{
    public class MongoDBContext
    {
        private IMongoDatabase _database { get; }

        public MongoDBContext(string connectionString, string database, bool ssl)
        {
            try
            {
                MongoClientSettings settings = MongoClientSettings.FromUrl(new MongoUrl(connectionString));
                if (ssl)
                {
                    settings.SslSettings = new SslSettings { EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 };
                }
                var mongoClient = new MongoClient(settings);
                _database = mongoClient.GetDatabase(database);
            }
            catch (Exception ex)
            {
                throw new Exception("Can not access to db server.", ex);
            }
        }

        public IMongoCollection<Account> Accounts => _database.GetCollection<Account>("account");
    }
}
