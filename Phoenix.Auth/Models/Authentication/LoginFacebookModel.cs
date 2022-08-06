#nullable disable

using Newtonsoft.Json;
using System.ComponentModel.DataAnnotations;

namespace Phoenix.Auth.Models.Auth
{
    public class LoginFacebookModel
    {
        [Required]
        [JsonProperty("facebook_id")]
        public string FacebookId { get; set; }

        [Required]
        [JsonProperty("signature")]
        public string Signature { get; set; }
    }
}
