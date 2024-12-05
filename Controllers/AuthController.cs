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
                new Claim(JwtRegisteredClaimNames.Email, Email),
                new Claim("uid", Email.ToString()),
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
