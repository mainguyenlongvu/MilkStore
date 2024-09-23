namespace MilkStore.ModelViews.ResponseDTO
{
    public class ProductResponseDTO
    {
        public required string ProductID { get; set; }
        public required string ProductName { get; set; }
        public required string Description { get; set; }
        public double Price { get; set; }
        public int QuantityInStock { get; set; }
        public required string ImageUrl { get; set; }
        public required string CategoryId { get; set; }
    }
}
