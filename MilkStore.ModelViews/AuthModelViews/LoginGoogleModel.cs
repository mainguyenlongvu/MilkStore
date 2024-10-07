
using System.ComponentModel.DataAnnotations;

namespace MilkStore.ModelViews.AuthModelViews;
public class LoginGoogleModel
{
    [Required(ErrorMessage = "Gmail is required")]
    [EmailAddress(ErrorMessage = "Gmail is invalid")]
    public string Gmail { get; set; }
    public string ProviderKey { get; set; }
}