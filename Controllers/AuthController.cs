using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authentication.Cookies;
using SocialLoginApi.Models;
using Microsoft.Extensions.Options;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.Net;

namespace SocialLoginApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        JwtSetting _jwtSetting;
        public AuthController(IOptions<JwtSetting> jwtSetting)
        {
            _jwtSetting = jwtSetting.Value;
        }
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
            var auth = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            if (!auth.Succeeded || auth.Principal == null)
            {
                return Unauthorized("Google login failed.");
            }

            var claims = auth.Principal.Identities.FirstOrDefault()?.Claims;
            var email = string.Empty;
            email = claims?.FirstOrDefault(c => c.Type == System.Security.Claims.ClaimTypes.Email)?.Value;

            // Get parameters to send back to the callback
            var qs = new Dictionary<string, string>
                {
                    { "access_token", auth.Properties.GetTokenValue("access_token") },
                    { "refresh_token", auth.Properties.GetTokenValue("refresh_token") ?? string.Empty },
                    { "expires_in", (auth.Properties.ExpiresUtc?.ToUnixTimeSeconds() ?? -1).ToString() },
                    { "email", email }
                };
            return Ok(qs);
        }

        [HttpPost("login")]
        public IActionResult Login(ViewModels.Login login)
        {
            string token = GenerateJWToken(login.Email);
            return Ok(token);
        }
        private string GenerateJWToken(string Email)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Email, Email),
                new Claim(ClaimTypes.NameIdentifier, Email),
            };

            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSetting.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwtSetting.Issuer,
                audience: _jwtSetting.Audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(_jwtSetting.Expires),
                signingCredentials: signingCredentials);
            return new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
        }
        //string GenerateSecretKey(int length = 32)
        //{
        //    byte[] randomBytes = new byte[length / 2];
        //    RandomNumberGenerator.Fill(randomBytes);

        //    // Convert random bytes to a string of characters and digits
        //    char[] chars = new char[length];
        //    for (int i = 0; i < length; i += 2)
        //    {
        //        byte b = randomBytes[i / 2];
        //        chars[i] = (char)(b % 62 + 48); // 0-9
        //        chars[i + 1] = (char)(b / 62 % 26 + 65); // A-Z
        //    }

        //    return new string(chars);
        //}
    }
}
