﻿#nullable disable

using Newtonsoft.Json;
using Phoenix.DataHandle.Api.Models;
using System.ComponentModel.DataAnnotations;

namespace Phoenix.Auth.Models.Account
{
    public class RegisterModel
    {
        [EmailAddress]
        [JsonProperty("email", Required = Required.Always)]
        public string Email { get; set; }

        [JsonProperty("key", Required = Required.Always)]
        public string Key { get; set; }

        [Phone]
        [JsonProperty("phone", Required = Required.Always)]
        public string PhoneNumber { get; set; }

        [StringLength(100, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
        [DataType(DataType.Password)]
        [JsonProperty("password", Required = Required.Always)]
        public string Password { get; set; }

        [DataType(DataType.Password)]
        [Compare(nameof(Password), ErrorMessage = "The password and confirmation password do not match.")]
        [JsonProperty("confirm_password", Required = Required.Always)]
        public string ConfirmPassword { get; set; }

        [JsonProperty("user_info", Required = Required.Always)]
        public UserApi User { get; set; }
    }
}
