using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Phoenix.Auth.Models.Account;
using Phoenix.DataHandle.Base;
using Phoenix.DataHandle.Identity;
using Phoenix.DataHandle.Main.Models;
using Phoenix.DataHandle.Main.Types;
using Phoenix.DataHandle.Repositories;
using Phoenix.DataHandle.Senders;
using System.ComponentModel.DataAnnotations;
using System.Text;
using System.Text.Encodings.Web;

namespace Phoenix.Auth.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AccountController : Controller
    {
        private readonly ILogger<AccountController> _logger;
        private readonly ApplicationUserManager _userManager;
        private readonly EmailSender _emailSender;

        private readonly UserRepository _userRepository;
        private readonly DevRegistrationRepository _devRegistrationRepository;

        public AccountController(
            ILogger<AccountController> logger,
            ApplicationUserManager userManager,
            PhoenixContext phoenixContext,
            EmailSender emailSender)
        {
            _logger = logger;
            _userManager = userManager;
            _emailSender = emailSender;

            _userRepository = new(phoenixContext);
            _devRegistrationRepository = new(phoenixContext);
        }

        [HttpPost("register")]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RegisterAsync([FromBody] RegisterModel model)
        {
            _logger.LogInformation("Creating Application User...");

            var devReg = await _devRegistrationRepository.FindUniqueAsync(model.Email);
            if (devReg is null || !devReg.Equals(model.Key.Trim()))
                return BadRequest("Invalid e-mail address or/and registration key.");

            var appUser = Activator.CreateInstance<ApplicationUser>();
            string username = UserExtensions.GenerateUserName(
                new int[1] { 0 }, model.PhoneNumber, dependenceOrder: 0);

            await _userManager.SetEmailAsync(appUser, model.Email);
            await _userManager.SetPhoneNumberAsync(appUser, model.PhoneNumber);
            await _userManager.SetUserNameAsync(appUser, username);
            await _userManager.AddToRoleAsync(appUser, RoleRank.SchoolDeveloper.ToNormalizedString());

            var identityResult = await _userManager.CreateAsync(appUser, model.Password);
            if (!identityResult.Succeeded)
            {
                string errorMsg = string.Join('\n', identityResult.Errors.Select(e => e.Description));
                
                _logger.LogError("{ErrorMessage}", errorMsg);

                return BadRequest("Problem creating account:\n" + errorMsg);
            }

            int userId = int.Parse(await _userManager.GetUserIdAsync(appUser));

            _logger.LogInformation("Application User created successfully");
            _logger.LogInformation("Creating Phoenix User...");

            var user = model.User.ToUser();
            user.AspNetUserId = userId;

            await _userRepository.CreateAsync(user);

            devReg.DeveloperId = userId;
            devReg.RegisteredAt = DateTime.UtcNow;
            await _devRegistrationRepository.UpdateAsync(devReg);

            _logger.LogInformation("Phoenix user created successfully.");
            _logger.LogInformation("Sending email confirmation link...");

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(appUser);
            token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

            string callbackUrl = Url.Page(
                        "api/account/confirm-email",
                        pageHandler: null,
                        values: new { userId, token },
                        protocol: Request.Scheme)!;
            callbackUrl = HtmlEncoder.Default.Encode(callbackUrl);

            await _emailSender.SendAsync(
                to: model.Email,
                subject: "Confirm your email",
                plainTextContent: null,
                htmlContent: $"Please confirm your account by <a href='{callbackUrl}'>clicking here</a>.");

            return Ok("Account created successfully. Please check your email to verify your account.");
        }

        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmailAsync(int userId, string token)
        {
            if (userId <= 0)
                return BadRequest("Parameter " + nameof(userId) + " cannot have a negative or zero value.");
            if (string.IsNullOrWhiteSpace(token))
                return BadRequest("Parameter " + nameof(token) + " cannot be empty.");

            var appUser = await _userManager.FindByIdAsync(userId.ToString());
            if (appUser is null)
                return NotFound($"Unable to load user with ID '{userId}'.");

            token = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));

            var identityResult = await _userManager.ConfirmEmailAsync(appUser, token);
            if (!identityResult.Succeeded)
                return BadRequest("Error confirming your email.");

            return Ok("Thank you for confirming your email.");
        }

        [HttpPost("resend-email-confirmation")]
        public async Task<IActionResult> ResendEmailConfirmationAsync([FromBody] string email)
        {
            var appuser = await _userManager.FindByEmailAsync(email);
            if (appuser is null)
                return Ok("Verification email sent. Please check your email.");

            int userId = int.Parse(await _userManager.GetUserIdAsync(appuser));
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(appuser);
            token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

            string callbackUrl = Url.Page(
                "api/account/confirm-email",
                pageHandler: null,
                values: new { userId, token },
                protocol: Request.Scheme)!;
            callbackUrl = HtmlEncoder.Default.Encode(callbackUrl);

            await _emailSender.SendAsync(
                to: email,
                subject: "Confirm your email",
                plainTextContent: null,
                htmlContent: $"Please confirm your account by <a href='{callbackUrl}'>clicking here</a>.");

            return Ok("Verification email sent. Please check your email.");
        }

        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePasswordAsync([FromBody, EmailAddress] string email)
        {
            var appUser = await _userManager.FindByEmailAsync(email);
            if (appUser is null || !await _userManager.IsEmailConfirmedAsync(appUser))
            {
                // Don't reveal that the user does not exist or is not confirmed
                return Ok("Please check your email to change your password.");
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(appUser);
            token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

            string callbackUrl = Url.Page(
                "/account/reset-password",
                pageHandler: null,
                values: null,
                protocol: Request.Scheme)!;
            callbackUrl = HtmlEncoder.Default.Encode(callbackUrl);

            await _emailSender.SendAsync(
                to: email,
                subject: "Change your password",
                plainTextContent: null,
                htmlContent: "You can reset your password by including the following token " +
                    $"in a POST request to <a href='{callbackUrl}'>:\n" +
                    $"token = <i>{token}</i>");

            return Ok("Please check your email to change your password.");
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPasswordAsync([FromBody] ChangePasswordModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user is null)
            {
                // Don't reveal that the user does not exist
                return Ok("Password reset successfully.");
            }

            var identityResult = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);
            if (!identityResult.Succeeded)
                return BadRequest("Error reseting your password.");

            return Ok("Password reset successfully.");
        }
    }
}
