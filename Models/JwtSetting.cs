namespace SocialLoginApi.Models
{
    public class JwtSetting
    {
        public required string Key { get; set; }
        public required string Issuer { get; set; }
        public required string Audience { get; set; }
        public int Expires { get; set; }
    }
}
