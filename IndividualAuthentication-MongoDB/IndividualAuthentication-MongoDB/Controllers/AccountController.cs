using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using IndividualAuthentication_MongoDB.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using MongoDB.Driver;

namespace IndividualAuthentication_MongoDB.Controllers
{
    [Produces("application/json")]
    [Route("api/Account")]
    public class AccountController : Controller
    {
        // GET api/Account/Login
        [HttpGet]
        [Route("Login")]
        public async Task<IActionResult> Login(LoginBindingModel model)
        {
            var context = HttpContext.RequestServices.GetService(typeof(MongoDBContext)) as MongoDBContext;

            if (context == null)
            {
                return BadRequest();
            }

            var userList = await context.Accounts.FindAsync(t => t.Email == model.UserName);
            var user = await userList.FirstOrDefaultAsync();

            if (user == null || model.Password != user.Password)
            {
                return NotFound();
            }

            await context.Accounts.UpdateOneAsync(t => t.Email == model.UserName, Builders<Account>.Update.Set(t => t.Online, true));

            return Ok();
        }

        // GET api/Account/Logout
        [HttpGet]
        [Route("Logout")]
        public async Task<IActionResult> Logout(LoginBindingModel model)
        {
            var context = HttpContext.RequestServices.GetService(typeof(MongoDBContext)) as MongoDBContext;

            if (context == null)
            {
                return BadRequest();
            }

            var userList = await context.Accounts.FindAsync(t => t.Email == model.UserName);
            var user = await userList.FirstOrDefaultAsync();

            if (user == null || model.Password != user.Password)
            {
                return NotFound();
            }

            await context.Accounts.UpdateOneAsync(t => t.Email == model.UserName, Builders<Account>.Update.Set(t => t.Online, false));

            return Ok();
        }
        
        // POST api/Account/Register
        [AllowAnonymous]
        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register(RegisterBindingModel model)
        {
            var context = HttpContext.RequestServices.GetService(typeof(MongoDBContext)) as MongoDBContext;

            if (model.Password != model.ConfirmPassword)
            {
                return BadRequest();
            }

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var userList = await context.Accounts.FindAsync(t => t.Email == model.Email);
            var user = await userList.FirstOrDefaultAsync();

            if (user != null)
                return BadRequest("User exist");

            await context.Accounts.InsertOneAsync(new Account { Email = model.Email, Password = model.Password, Online = false });

            return Ok();
        }

        // DELETE api/Account/Delete
        [HttpDelete]
        [Route("Delete")]
        public async Task<IActionResult> Delete(int id)
        {
            var context = HttpContext.RequestServices.GetService(typeof(MongoDBContext)) as MongoDBContext;

            if (context == null)
            {
                return BadRequest();
            }

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var userList = await context.Accounts.FindAsync(t => t.Id == id);
            var user = await userList.FirstOrDefaultAsync();

            if (user == null)
                return NotFound();

            await context.Accounts.DeleteOneAsync(t => t.Id == id);

            return Ok();
        }

        #region helpers

        private string hash = "CEGSKUNX6W4LBGBG65H4ESPNYK9W67Y9";

        private string Encrypt(string text)
        {
            var key = Encoding.UTF8.GetBytes(hash);

            using (var aesAlg = Aes.Create())
            {
                using (var encryptor = aesAlg.CreateEncryptor(key, aesAlg.IV))
                {
                    using (var msEncrypt = new MemoryStream())
                    {
                        using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                        using (var swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(text);
                        }

                        var iv = aesAlg.IV;

                        var decryptedContent = msEncrypt.ToArray();

                        var result = new byte[iv.Length + decryptedContent.Length];

                        Buffer.BlockCopy(iv, 0, result, 0, iv.Length);
                        Buffer.BlockCopy(decryptedContent, 0, result, iv.Length, decryptedContent.Length);

                        return Convert.ToBase64String(result);
                    }
                }
            }
        }

        private string Dencrypt(string text)
        {
            var fullCipher = Convert.FromBase64String(text);

            var iv = new byte[16];
            var cipher = new byte[16];

            Buffer.BlockCopy(fullCipher, 0, iv, 0, iv.Length);
            Buffer.BlockCopy(fullCipher, iv.Length, cipher, 0, iv.Length);
            var key = Encoding.UTF8.GetBytes(hash);

            using (var aesAlg = Aes.Create())
            {
                using (var decryptor = aesAlg.CreateDecryptor(key, iv))
                {
                    string result;
                    using (var msDecrypt = new MemoryStream(cipher))
                    {
                        using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                        {
                            using (var srDecrypt = new StreamReader(csDecrypt))
                            {
                                result = srDecrypt.ReadToEnd();
                            }
                        }
                    }

                    return result;
                }
            }
        }

        #endregion
    }
}