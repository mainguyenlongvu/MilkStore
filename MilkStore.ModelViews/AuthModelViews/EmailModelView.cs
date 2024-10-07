using System.ComponentModel.DataAnnotations;
namespace MilkStore.ModelViews.AuthModelViews;
public class EmailModelView
{
    [Required(ErrorMessage = "Email is required")]
    [EmailAddress(ErrorMessage = "Email is invalid")]
    public string Email { get; set; }
}