namespace MilkStore.ModelViews.AuthModelViews
{

    public class AuthResponse
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public string TokenType { get; set; }
        public string AuthType { get; set; }
        public DateTime ExpiresIn { get; set; }
        public UserInfo User { get; set; }
    }

    public class UserInfo
    {
        public string Email { get; set; }
        public List<string> Roles { get; set; }
    }
}