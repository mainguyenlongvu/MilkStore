using System.ComponentModel.DataAnnotations;

namespace MilkStore.ModelViews.PostModelViews
{
    public class PostModelView
    {
        [Required(ErrorMessage = "Tiêu đề không được để trống")]
        public required string Title { get; set; }
        [Required(ErrorMessage = "Nội dung không được để trống")]
        public required string Content { get; set; }
        public string? Image { get; set; }
        public DateTime? DeletedTime { get; set; } = null;
        public ICollection<string>? ProductIDs { get; set; }
    }
}