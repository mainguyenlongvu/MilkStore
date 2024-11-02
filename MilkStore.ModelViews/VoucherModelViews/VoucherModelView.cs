using System.ComponentModel.DataAnnotations;


namespace MilkStore.ModelViews.VoucherModelViews
{
    public class VoucherModelView
    {
        [Required(ErrorMessage = "Không được để trống")]
        public string Description { get; set; }
        [Required(ErrorMessage = "Không được để trống")]
        public int SalePrice { get; set; }
        [Required(ErrorMessage = "Không được để trống")]
        public int SalePercent { get; set; }
        [Required(ErrorMessage = "Không được để trống")]
        public int LimitSalePrice { get; set; }
        [Required(ErrorMessage = "Không được để trống")]
        public DateTime ExpiryDate { get; set; }
        public int UsingLimit { get; set; }
        public int UsedCount { get; set; }
        public int Status { get; set; }
        [Required(ErrorMessage = "Không được để trống")]
        public string Name { get; set; }
        public string VoucherCode { get; set; } = string.Empty;
    }
}