using System.ComponentModel.DataAnnotations;

public class TokenGoogleModel
{
    [Required(ErrorMessage = "Token không được để trống")]
    public string token { get; set; }
}