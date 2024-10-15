using System.ComponentModel.DataAnnotations;
namespace MilkStore.ModelViews.AuthModelViews;
public class TokenGoogleModel
{
    [Required(ErrorMessage = "Token không được để trống")]
    public string token { get; set; }
}