using MySql.Data.MySqlClient;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IndividualAuthentication_MySql.Models
{
    public class Account : BaseModel
    {
        public int Id { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
        public bool Online { get; set; }
    }

    public class AccountContext : BaseModelContext
    {
        public string ConnectionString { get; set; }

        public AccountContext(string connectionString)
        {
            this.ConnectionString = connectionString;
        }

        private MySqlConnection GetConnection()
        {
            return new MySqlConnection(ConnectionString);
        }

        public async Task<Account> GetAccountAsync(int id)
        {
            Account account = null;

            using (var conn = GetConnection())
            {
                await conn.OpenAsync();
                var cmd = new MySqlCommand("SELECT * FROM account WHERE id = @id", conn);
                cmd.Parameters.AddWithValue("@id", id);

                using (var reader = cmd.ExecuteReader())
                {
                    if (await reader.ReadAsync())
                    {
                        account = new Account
                        {
                            Id = reader.GetInt32("id"),
                            Email = reader.GetString("email"),
                            Password = reader.GetString("password"),
                            Online = reader.GetBoolean("online")
                        };
                    }
                    else
                    {
                        await conn.CloseAsync();
                        return null;
                    }

                }
                await conn.CloseAsync();
            }

            account.Password = Dencrypt(account.Password);

            return account;
        }

        public async Task<Account> GetAccountAsync(string email)
        {
            Account account = null;

            using (var conn = GetConnection())
            {
                await conn.OpenAsync();
                var cmd = new MySqlCommand("SELECT * FROM account WHERE email = @email", conn);
                cmd.Parameters.AddWithValue("@email", email);

                using (var reader = cmd.ExecuteReader())
                {
                    if (await reader.ReadAsync())
                    {
                        account = new Account
                        {
                            Id = reader.GetInt32("id"),
                            Email = reader.GetString("email"),
                            Password = reader.GetString("password"),
                            Online = reader.GetBoolean("online")
                        };
                    }
                    else
                    {
                        await conn.CloseAsync();
                        return null;
                    }

                }
                await conn.CloseAsync();
            }

            account.Password = Dencrypt(account.Password);

            return account;
        }

        public async Task<bool> UpdateAccountAsync(Account account)
        {
            var result = false;

            using (var conn = GetConnection())
            {
                await conn.OpenAsync();
                var cmd = new MySqlCommand("Update account SET email = @email, password = @password, online = @online WHERE id = @id", conn);
                cmd.Parameters.AddWithValue("@id", account.Id);
                cmd.Parameters.AddWithValue("@email", account.Email);
                cmd.Parameters.AddWithValue("@password", Encrypt(account.Password));
                cmd.Parameters.AddWithValue("@online", account.Online);

                var cmResult = await cmd.ExecuteNonQueryAsync();

                if (cmResult > 0)
                    result = true;

                await conn.CloseAsync();
            }

            return result;
        }

        public async Task<long> PostAccountAsync(Account account)
        {
            long result = -1;

            using (var conn = GetConnection())
            {
                await conn.OpenAsync();

                var cmd = new MySqlCommand("INSERT INTO account (email, password, online) VALUES(@email, @password, @online)", conn);
                cmd.Parameters.AddWithValue("@email", account.Email);
                cmd.Parameters.AddWithValue("@password", Encrypt(account.Password));
                cmd.Parameters.AddWithValue("@online", false);

                var cmResult = await cmd.ExecuteNonQueryAsync();

                if (cmResult > 0)
                    result = cmd.LastInsertedId;

                await conn.CloseAsync();
            }

            return result;
        }

        public async Task<bool> DeleteAccountAsync(int id)
        {
            var result = false;

            using (var conn = GetConnection())
            {
                await conn.OpenAsync();

                var cmd = new MySqlCommand("DELETE FROM account WHERE id = @id", conn);
                cmd.Parameters.AddWithValue("@id", id);

                var cmResult = await cmd.ExecuteNonQueryAsync();

                if (cmResult > 0)
                    result = true;

                await conn.CloseAsync();
            }

            return result;
        }
    }
}
