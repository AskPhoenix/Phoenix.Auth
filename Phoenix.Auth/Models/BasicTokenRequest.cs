using Newtonsoft.Json;
using System.ComponentModel.DataAnnotations;

namespace Phoenix.Auth.Models
{
    public class BasicTokenRequest
    {
        [Required]
        [JsonProperty("phone")]
        public string Phone { get; set; } = null!;

        [Required]
        [JsonProperty("password")]
        public string Password { get; set; } = null!;
    }
}
