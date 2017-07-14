using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IndividualAuthentication_MySql.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace IndividualAuthentication_MySql.Controllers
{
    [Authorize]

    [Produces("application/json")]
    [Route("api/Account")]
    public class AccountController : Controller
    {
        // GET api/Account/Login
        [HttpGet]
        [Route("Login")]
        public async Task<IActionResult> Login(LoginBindingModel model)
        {
            var context = HttpContext.RequestServices.GetService(typeof(AccountContext)) as AccountContext;

            if (context == null)
            {
                return BadRequest();
            }

            var user = await context.GetAccountAsync(model.UserName);

            if (user == null || model.Password != user.Password)
            {
                return NotFound();
            }

            user.Online = true;
            await context.UpdateAccountAsync(user);

            return Ok();
        }

        // GET api/Account/Logout
        [HttpGet]
        [Route("Logout")]
        public async Task<IActionResult> Logout(LoginBindingModel model)
        {
            var context = HttpContext.RequestServices.GetService(typeof(AccountContext)) as AccountContext;

            if (context == null)
            {
                return BadRequest();
            }

            var user = await context.GetAccountAsync(model.UserName);

            if (user == null || model.Password != user.Password)
            {
                return NotFound();
            }

            user.Online = false;
            await context.UpdateAccountAsync(user);

            return Ok();
        }

        // POST api/Account/Register
        [AllowAnonymous]
        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register(RegisterBindingModel model)
        {
            var context = HttpContext.RequestServices.GetService(typeof(AccountContext)) as AccountContext;

            if (context == null || model.Password != model.ConfirmPassword)
            {
                return BadRequest();
            }

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            if (await context.GetAccountAsync(model.Email) != null)
                return BadRequest("User exist");

            await context.PostAccountAsync(new Account { Email = model.Email, Password = model.Password, Online = false });

            return Ok();
        }

        // DELETE api/Account/Delete
        [HttpDelete]
        [Route("Delete")]
        public async Task<IActionResult> Delete(int id)
        {
            var context = HttpContext.RequestServices.GetService(typeof(AccountContext)) as AccountContext;

            if (context == null)
            {
                return BadRequest();
            }

            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            if (await context.GetAccountAsync(id) == null)
                return NotFound();

            await context.DeleteAccountAsync(id);

            return Ok();
        }
    }
}