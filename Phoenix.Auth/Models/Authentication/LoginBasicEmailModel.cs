#nullable disable

using Newtonsoft.Json;
using System.ComponentModel.DataAnnotations;

namespace Phoenix.Auth.Models.Auth
{
    public class LoginBasicEmailModel
    {
        [Required]
        [EmailAddress]
        [JsonProperty("email", Required = Required.Always)]
        public string Email { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [JsonProperty("password", Required = Required.Always)]
        public string Password { get; set; }
    }
}
