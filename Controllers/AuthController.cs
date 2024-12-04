using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace SocialLoginApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        [HttpGet("google")]
        public IActionResult RedirectToGoogle()
        {
            string returnUrl = Url.Action(nameof(HandleGoogleCallback));
            var properties = new AuthenticationProperties
            {
                RedirectUri = returnUrl
            };
            return Challenge(properties, GoogleDefaults.AuthenticationScheme);
        }

        [HttpGet("googleloggedin")]
        public async Task<IActionResult> HandleGoogleCallback()
        {
            // Retrieve tokens and user information
            var authenticateResult = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (!authenticateResult.Succeeded || authenticateResult.Principal == null)
            {
                return Unauthorized("Google login failed.");
            }

            var claims = authenticateResult.Principal.Claims.ToDictionary(c => c.Type, c => c.Value);

            // Extract information
            var userInfo = new
            {
                Name = claims.GetValueOrDefault("name"),
                Email = claims.GetValueOrDefault("email"),
                Picture = claims.GetValueOrDefault("picture")
            };

            return Ok(userInfo);
        }
    }
}
