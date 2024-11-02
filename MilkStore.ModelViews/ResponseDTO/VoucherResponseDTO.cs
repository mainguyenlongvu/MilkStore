namespace MilkStore.ModelViews.ResponseDTO
{
    public class VoucherResponseDTO
    {
        public required string ID { get; set; }
        public required string Name { get; set; }
        public string Description { get; set; }
        public int SalePrice { get; set; }
        public int SalePercent { get; set; }
        public int LimitSalePrice { get; set; }
        public DateTime ExpiryDate { get; set; }
        public int UsingLimit { get; set; }
        public int UsedCount { get; set; }
        public int Status { get; set; }
        public string VoucherCode { get; set; } = string.Empty;  // Thêm mã voucher
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.Now;
        public DateTimeOffset LastUpdatedAt { get; set; } = DateTimeOffset.Now;
        public DateTimeOffset? DeletedTime { get; set; } = null;
    }
}
