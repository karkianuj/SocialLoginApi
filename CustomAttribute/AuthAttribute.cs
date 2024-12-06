using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using SocialLoginApi.Models;
using Microsoft.Extensions.Options;

namespace SocialLoginApi.CustomAttribute
{
    [AttributeUsage(AttributeTargets.All)]
    public class AuthAttribute : Attribute, IAuthorizationFilter
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly string[] _requiredRoles;
        private readonly bool _validateToken;

        /// <summary>
        /// Custom authorization attribute with optional role-based authorization
        /// </summary>
        /// <param name="requiredRoles">Optional roles required to access the endpoint</param>
        public AuthAttribute (params string[] requiredRoles)
        {
            _httpContextAccessor = new HttpContextAccessor();
            _requiredRoles = requiredRoles;
            _validateToken = true;
        }

        /// <summary>
        /// Custom authorization attribute with control over token validation
        /// </summary>
        /// <param name="validateToken">Whether to perform token validation</param>
        /// <param name="requiredRoles">Optional roles required to access the endpoint</param>
        public AuthAttribute(bool validateToken = true, params string[] requiredRoles)
        {
            _httpContextAccessor = new HttpContextAccessor();
            _validateToken = validateToken;
            _requiredRoles = requiredRoles;
        }

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            JwtSetting _jwtSetting;
            // Skip validation if token validation is disabled
            if (!_validateToken)
                return;

            // Retrieve JwtSettings using IOptions
            var jwtSetting = context.HttpContext.RequestServices
                .GetService(typeof(IOptions<JwtSetting>)) as IOptions<JwtSetting>;

            if (jwtSetting == null)
                throw new InvalidOperationException("JWT is not properly configured");

            _jwtSetting = jwtSetting.Value;


            // Retrieve authorization header
            var authHeader = context.HttpContext.Request.Headers["Authorization"].FirstOrDefault();

            if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
            {
                context.Result = new UnauthorizedResult();
                return;
            }

            // Extract token
            var token = authHeader.Substring("Bearer ".Length).Trim();

            try
            {
                // Token validation parameters
                var tokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(
                        Encoding.UTF8.GetBytes(_jwtSetting.Key)),
                    ValidateIssuer = true,
                    ValidIssuer = _jwtSetting.Issuer,
                    ValidateAudience = true,
                    ValidAudience = _jwtSetting.Audience,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.Zero
                };

                // Validate token
                var tokenHandler = new JwtSecurityTokenHandler();
                var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out _);

                // Role-based authorization if roles are specified
                if (_requiredRoles != null && _requiredRoles.Any())
                {
                    var userRoles = principal.Claims
                        .Where(c => c.Type == ClaimTypes.Role)
                        .Select(c => c.Value);

                    if (!_requiredRoles.Any(role => userRoles.Contains(role)))
                    {
                        context.Result = new ForbidResult();
                        return;
                    }
                }

                // Store the validated principal in HttpContext for further use
                context.HttpContext.User = principal;
            }
            catch (SecurityTokenExpiredException)
            {
                context.Result = new UnauthorizedObjectResult(new
                {
                    Message = "Token has expired",
                    StatusCode = 401
                });
                return;
            }
            catch (Exception)
            {
                context.Result = new UnauthorizedResult();
                return;
            }
        }

        /// <summary>
        /// Helper method to extract specific claim from token
        /// </summary>
        public string GetClaim(string claimType)
        {
            var context = _httpContextAccessor.HttpContext;

            if (context == null)
            {
                throw new UnauthorizedAccessException();
            }

            string value = context.User.Claims.FirstOrDefault(c => c.Type == claimType)?.Value ?? string.Empty;
            return value;
        }

        /// <summary>
        /// Helper method to get user ID from token
        /// </summary>
        public string GetUserId()
        {
            return GetClaim(ClaimTypes.NameIdentifier);
        }

        /// <summary>
        /// Helper method to get user email from token
        /// </summary>
        public string GetUserEmail()
        {
            return GetClaim(ClaimTypes.Email);
        }
    }
}
