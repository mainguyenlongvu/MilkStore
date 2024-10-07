using System.ComponentModel.DataAnnotations;

namespace MilkStore.ModelViews.AuthModelViews
{
    public class RegisterModelView
    {
        [Required(ErrorMessage = "Name is required")]
        public string Name { get; set; }

        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Email is invalid")]
        public string Email { get; set; }

        [Phone(ErrorMessage = "Phone number is invalid")]
        public string? PhoneNumber { get; set; }

        [Required(ErrorMessage = "Password is required")]
        [RegularExpression(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&.])[A-Za-z\d@$!%*?&.]{8,16}$", ErrorMessage = "Password must be at least 8 characters, 1 uppercase, 1 lowercase, 1 number and 1 special character")]
        public string Password { get; set; }


    }
}