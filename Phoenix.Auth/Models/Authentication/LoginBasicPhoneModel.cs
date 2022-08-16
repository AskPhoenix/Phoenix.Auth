#nullable disable

using Newtonsoft.Json;
using System.ComponentModel.DataAnnotations;

namespace Phoenix.Auth.Models.Auth
{
    public class LoginBasicPhoneModel
    {
        [Required]
        [RegularExpression(@"^\+\d{1,3}$")]
        [JsonProperty("phone_country_code", Required = Required.Always)]
        public string PhoneCountryCode { get; set; }

        [Required]
        [Phone]
        [RegularExpression(@"^\d{1,12}$")]
        [JsonProperty("phone", Required = Required.Always)]
        public string Phone { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [JsonProperty("password", Required = Required.Always)]
        public string Password { get; set; }
    }
}
