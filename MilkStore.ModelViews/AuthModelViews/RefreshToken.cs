using System.ComponentModel.DataAnnotations;
namespace MilkStore.ModelViews.AuthModelViews;
public class RefreshTokenModel
{
    [Required(ErrorMessage = "RefreshToken không được để trống")]
    public string refreshToken { get; set; }
}