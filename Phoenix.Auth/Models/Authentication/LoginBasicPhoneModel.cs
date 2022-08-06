#nullable disable

using Newtonsoft.Json;
using System.ComponentModel.DataAnnotations;

namespace Phoenix.Auth.Models.Auth
{
    public class LoginBasicPhoneModel
    {
        [Required]
        [Phone]
        [JsonProperty("phone", Required = Required.Always)]
        public string Phone { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [JsonProperty("password", Required = Required.Always)]
        public string Password { get; set; }
    }
}
