using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.ModelViews.ResponseDTO
{
    public class ProductRevenueDTO
    {
        public string? ProductId { get; set; }
        public double TotalQuantity { get; set; }
        public double TotalRevenue { get; set; }
    }
}
