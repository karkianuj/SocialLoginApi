using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using SocialLoginApi.CustomAttribute;

namespace SocialLoginApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        [Auth]
        [HttpGet("getemail")]
        public IActionResult GetEmail()
        {
            var userId =  new AuthAttribute().GetUserId();
            var userEmail = new AuthAttribute().GetUserEmail();

            // Use user information
            return Ok(new { UserId = userId, Email = userEmail });
        }
    }
}
