
using System.ComponentModel.DataAnnotations;


namespace MilkStore.ModelViews.UserModelViews
{
    public class UserModelView
    {
        [Required(ErrorMessage = "Name is required")]
        public string Name { get; set; }
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Email is not valid")]
        public string Email { get; set; }
        [Required(ErrorMessage = "PhoneNumber is required")]
        [Phone(ErrorMessage = "PhoneNumber is not valid")]
        public string? PhoneNumber { get; set; }
        [Required(ErrorMessage = "RoleID is required")]

        public string RoleID { get; set; }
    }
}
