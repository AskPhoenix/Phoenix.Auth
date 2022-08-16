using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Phoenix.Auth.Models.Auth;
using Phoenix.DataHandle.Identity;
using Phoenix.DataHandle.Main.Types;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Phoenix.Auth.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthenticationController : Controller
    {
        private readonly ILogger<AuthenticationController> _logger;
        private readonly IConfiguration _configuration;
        private readonly ApplicationUserManager _userManager;

        public AuthenticationController(
            ApplicationUserManager userManager,
            ILogger<AuthenticationController> logger,
            IConfiguration configuration)
        {
            _logger = logger;
            _userManager = userManager;
            _configuration = configuration;
        }
        
        [HttpPost("basic-phone")]
        public async Task<IActionResult> LoginBasicAsync([FromBody] LoginBasicPhoneModel loginBasic)
        {
            _logger.LogInformation("Api -> Login -> Authenticate -> Basic Phone");

            try
            {
                var appUser = await AuthenticateBasicPhoneAsync(loginBasic);
                if (appUser is null)
                    return NotFound("User not found");

                return Ok(await GenerateTokenAsync(appUser));
            }
            catch (Exception ex)
            {
                _logger.LogCritical(ex, "Basic Phone authentication failed");
                return StatusCode(StatusCodes.Status500InternalServerError,  "Authentication failed");
            }
        }

        [HttpPost("basic-email")]
        public async Task<IActionResult> LoginBasicAsync([FromBody] LoginBasicEmailModel loginBasic)
        {
            _logger.LogInformation("Api -> Login -> Authenticate -> Basic Email");

            try
            {
                var appUser = await AuthenticateBasicEmailAsync(loginBasic);
                if (appUser is null)
                    return NotFound("User not found");

                return Ok(await GenerateTokenAsync(appUser));
            }
            catch (Exception ex)
            {
                _logger.LogCritical(ex, "Basic Email authentication failed");
                return StatusCode(StatusCodes.Status500InternalServerError, "Authentication failed");
            }
        }

        [HttpPost("facebook")]
        public async Task<IActionResult> LoginFacebookAsync([FromBody] LoginFacebookModel tokenRequest)
        {
            _logger.LogInformation("Api -> Authentication -> Authenticate -> Facebook");

            if (tokenRequest is null)
                return BadRequest(nameof(tokenRequest) + " argument cannot be null.");

            try
            {
                var appUser = await AuthenticateFacebookAsync(tokenRequest);
                if (appUser is null)
                    return NotFound("User not found");

                return Ok(await GenerateTokenAsync(appUser));
            }
            catch (Exception ex)
            {
                _logger.LogCritical(ex, "Facebook authentication failed");
                return StatusCode(StatusCodes.Status500InternalServerError, "Authentication failed.");
            }
        }

        private async Task<ApplicationUser?> AuthenticateBasicPhoneAsync(LoginBasicPhoneModel model,
            CancellationToken cancellationToken = default)
        {
            var fullPhone = model.PhoneCountryCode + model.Phone;

            var appUser = await _userManager.FindByPhoneNumberAsync(fullPhone, cancellationToken);

            if (appUser is null)
            {
                _logger.LogError("No User found with phone number {phone}", fullPhone);
                return null;
            }

            if (!appUser.PhoneNumberConfirmed && !appUser.EmailConfirmed)
            {
                _logger.LogError("The phone number {phone} must be confirmed", appUser.PhoneNumber);
                return null;
            }

            if (!await this._userManager.CheckPasswordAsync(appUser, model.Password))
            {
                _logger.LogError("The password for user with phone number {phone} is not correct", appUser.PhoneNumber);
                return null;
            }

            return appUser;
        }

        private async Task<ApplicationUser?> AuthenticateBasicEmailAsync(LoginBasicEmailModel model)
        {
            var appUser = await _userManager.FindByEmailAsync(model.Email);

            if (appUser is null)
            {
                _logger.LogError("No User found with email {email}", model.Email);
                return null;
            }

            if (!appUser.EmailConfirmed)
            {
                _logger.LogError("The email {email} must be confirmed before authentication", appUser.Email);
                return null;
            }

            if (!await this._userManager.CheckPasswordAsync(appUser, model.Password))
            {
                _logger.LogError("The password for user with email {eamil} is not correct", appUser.Email);
                return null;
            }

            return appUser;
        }

        private async Task<ApplicationUser?> AuthenticateFacebookAsync(LoginFacebookModel tokenRequest,
            CancellationToken cancellationToken = default)
        {
            var appUser = await _userManager.FindByProviderKeyAsync(ChannelProvider.Facebook.ToString(), tokenRequest.FacebookId, cancellationToken);

            if (appUser is null)
            {
                _logger.LogDebug("No User found with facebook id {fbid}", tokenRequest.FacebookId);
                return null;
            }

            if (!appUser.PhoneNumberConfirmed)
            {
                _logger.LogDebug("User's phone number with ID {userId} must be confirmed", appUser.Id);
                return null;
            }

            if (!appUser.VerifyHashSignature(tokenRequest.Signature))
            {
                _logger.LogDebug("The VerifyHashSignature failed. Generated signature: {genSignature}", appUser.GetHashSignature());
                return null;
            }

            return appUser;
        }

        private async Task<string> GenerateTokenAsync(ApplicationUser appUser)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new List<Claim>()
            {
                new Claim(ClaimTypes.NameIdentifier, appUser.UserName),
                new Claim(ClaimTypes.MobilePhone, appUser.PhoneNumber)
            };
            claims.AddRange((await _userManager.GetRolesAsync(appUser)).Select(r => new Claim(ClaimTypes.Role, r)));

            var token = new JwtSecurityToken(
                _configuration["Jwt:Issuer"],
                _configuration["Jwt:Audience"],
                claims,
                expires: DateTime.UtcNow.AddHours(1),
                signingCredentials: credentials);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
