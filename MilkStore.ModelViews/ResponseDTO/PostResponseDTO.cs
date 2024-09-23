
namespace MilkStore.ModelViews.ResponseDTO
{
    public class PostResponseDTO
    {
        public required string ID { get; set; }
        public required string Title { get; set; }
        public required string Content { get; set; }
        public string? Image { get; set; }
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.Now;
        public required string CreatedBy { get; set; }
        public DateTimeOffset LastUpdatedAt { get; set; } = DateTimeOffset.Now;
        public DateTimeOffset? DeletedTime { get; set; } = null;
        public List<ProductResponseDTO> Products { get; set; } = new List<ProductResponseDTO>();
    }
}
