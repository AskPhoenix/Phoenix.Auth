# nullable disable

using Newtonsoft.Json;
using System.ComponentModel.DataAnnotations;

namespace Phoenix.Auth.Models.Account
{
    public class ChangePasswordModel
    {
        [Required]
        [EmailAddress]
        [JsonProperty("email", Required = Required.Always)]
        public string Email { get; set; }

        [Required]
        [JsonProperty("token", Required = Required.Always)]
        public string Token { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [JsonProperty("old_password", Required = Required.Always)]
        public string OldPassword { get; set; }

        [Required]
        [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [JsonProperty("new_password", Required = Required.Always)]
        public string NewPassword { get; set; }

        [DataType(DataType.Password)]
        [Compare("NewPassword", ErrorMessage = "The new password and confirmation password do not match.")]
        [JsonProperty("confirm_password", Required = Required.Always)]
        public string ConfirmPassword { get; set; }
    }
}
