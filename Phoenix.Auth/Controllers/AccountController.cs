using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Phoenix.Auth.Models.Account;
using Phoenix.DataHandle.Api;
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
    public class AccountController : ApplicationController
    {
        private readonly ApplicationStore _appStore;
        private readonly EmailSender _emailSender;
        private readonly DevRegistrationRepository _devRegistrationRepository;

        public AccountController(
            PhoenixContext phoenixContext,
            ApplicationUserManager userManager,
            ILogger<AccountController> logger,
            IUserStore<ApplicationUser> appStore,
            EmailSender emailSender)
            : base(phoenixContext, userManager, logger)
        {
            _appStore = (appStore as ApplicationStore)!;
            _emailSender = emailSender;
            _devRegistrationRepository = new(phoenixContext);
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync([FromBody] RegisterModel model)
        {
            _logger.LogInformation("Creating Application User...");

            var devReg = await _devRegistrationRepository.FindUniqueAsync(model.Email);
            if (devReg is null || !devReg.RegisterKey.Equals(model.Key.Trim()))
                return BadRequest("Invalid e-mail address or/and registration key.");

            var appUser = Activator.CreateInstance<ApplicationUser>();
            string username = UserExtensions.GenerateUserName(
                new int[1] { 0 }, model.PhoneNumber, dependenceOrder: 0);

            await _appStore.SetUserNameAsync(appUser, username);
            await _appStore.SetNormalizedUserNameAsync(appUser, ApplicationUser.NormFunc(username));

            await _appStore.SetEmailAsync(appUser, model.Email);
            await _appStore.SetNormalizedEmailAsync(appUser, ApplicationUser.NormFunc(model.Email));

            await _appStore.SetPhoneNumberAsync(appUser, model.PhoneNumber);
            
            var identityResult = await _userManager.CreateAsync(appUser, model.Password);
            if (!identityResult.Succeeded)
            {
                string errorMsg = string.Join('\n', identityResult.Errors.Select(e => e.Description));
                
                _logger.LogError("{ErrorMessage}", errorMsg);

                return BadRequest("Problem creating account:\n" + errorMsg);
            }

            await _userManager.AddToRoleAsync(appUser, RoleRank.SchoolDeveloper.ToNormalizedString());

            int userId = int.Parse(await _userManager.GetUserIdAsync(appUser));

            _logger.LogInformation("Application User created successfully");
            _logger.LogInformation("Creating Phoenix User...");

            var user = new User()
            {
                AspNetUserId = userId,
                FirstName = model.Firstname,
                LastName = model.LastName,
                DependenceOrder = 0,
                IsSelfDetermined = true
            };

            await _userRepository.CreateAsync(user);

            devReg.DeveloperId = userId;
            devReg.RegisteredAt = DateTime.UtcNow;
            await _devRegistrationRepository.UpdateAsync(devReg);

            _logger.LogInformation("Phoenix user created successfully.");
            _logger.LogInformation("Sending email confirmation link...");

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(appUser);
            token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

            string callbackUrl = Url.ActionLink(
                action: nameof(this.ConfirmEmailAsync).Replace("Async", ""),
                controller: nameof(AccountController).Replace("Controller", ""),
                values: new { userId, token },
                protocol: Request.Scheme)!;
            callbackUrl = HtmlEncoder.Default.Encode(callbackUrl);

            await _emailSender.SendAsync(
                to: model.Email,
                subject: "AskPhoenix Dev - Account Confirmation",
                htmlContent: $"Please confirm your account by <a href='{callbackUrl}'>clicking here</a>.");

            return Ok("Account created successfully. Please check your email to verify your account.");
        }

        [HttpPost("resend-email-confirmation")]
        public async Task<IActionResult> ResendEmailConfirmationAsync([FromBody, EmailAddress] string email)
        {
            var appuser = await _userManager.FindByEmailAsync(email);
            if (appuser is null)
                return Ok("Verification email sent. Please check your email.");

            if (await _userManager.IsEmailConfirmedAsync(appuser))
                return Ok("Account is already verified.");

            int userId = int.Parse(await _userManager.GetUserIdAsync(appuser));
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(appuser);
            token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

            string callbackUrl = Url.ActionLink(
                action: nameof(this.ConfirmEmailAsync).Replace("Async", ""),
                controller: nameof(AccountController).Replace("Controller", ""),
                values: new { userId, token },
                protocol: Request.Scheme)!;
            callbackUrl = HtmlEncoder.Default.Encode(callbackUrl);

            await _emailSender.SendAsync(
                to: email,
                subject: "AskPhoenix Dev - Account Confirmation",
                htmlContent: $"Please confirm your account by <a href='{callbackUrl}'>clicking here</a>.");

            return Ok("Verification email sent. Please check your email.");
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

        [Authorize(AuthenticationSchemes = "Bearer")]
        [HttpPost("change-password")]
        public async Task<IActionResult> ChangePasswordAsync([FromBody] ChangePasswordModel model)
        {
            if (!CheckUserAuth())
                return Unauthorized($"User not authorized.");

            var identityRes = await _userManager.ChangePasswordAsync(AppUser!, model.OldPassword, model.NewPassword);
            if (!identityRes.Succeeded)
                return BadRequest("Error changing your password.");

            _logger.LogInformation("User changed their password successfully.");

            return Ok("Your password has been changed.");
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPasswordAsync([FromBody, EmailAddress] string email)
        {
            var appuser = await _userManager.FindByEmailAsync(email);
            if (appuser is null || !await _userManager.IsEmailConfirmedAsync(appuser))
            {
                // Don't reveal that the user does not exist or is not confirmed
                return Ok("Please check your email to reset your password.");
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(appuser);
            token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

            string callbackUrl = Url.ActionLink(
                action: nameof(this.ResetPasswordAsync).Replace("Async", ""),
                controller: nameof(AccountController).Replace("Controller", ""),
                values: null,
                protocol: Request.Scheme)!;
            callbackUrl = HtmlEncoder.Default.Encode(callbackUrl);

            await _emailSender.SendAsync(
                to: email,
                subject: "AskPhoenix Dev - Reset Password",
                htmlContent: "Please reset your password by using the following token in a POST request at " +
                    $"<a href='{callbackUrl}'>{callbackUrl}</a>:\n\n{token}\n");

            return Ok("Please check your email to reset your password.");
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPasswordAsync([FromBody] ResetPasswordModel model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user is null)
            {
                // Don't reveal that the user does not exist
                return Ok("Password reset successfully.");
            }

            string token = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(model.Token));

            var identityResult = await _userManager.ResetPasswordAsync(user, token, model.Password);
            if (!identityResult.Succeeded)
                return BadRequest("Error reseting your password.");

            return Ok("Password reset successfully.");
        }
    }
}
