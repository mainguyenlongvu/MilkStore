using System.ComponentModel.DataAnnotations;
namespace MilkStore.ModelViews.AuthModelViews;
public class TokenGoogleModel
{
    [Required(ErrorMessage = "Token is required")]
    public string token { get; set; }
}