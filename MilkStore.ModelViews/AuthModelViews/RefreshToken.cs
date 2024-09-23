using System.ComponentModel.DataAnnotations;

public class RefreshTokenModel
{
    [Required(ErrorMessage = "RefreshToken không được để trống")]
    public string refreshToken { get; set; }
}