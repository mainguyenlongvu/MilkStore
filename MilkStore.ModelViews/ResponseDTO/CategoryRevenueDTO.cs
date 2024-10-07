using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.ModelViews.ResponseDTO
{
    public class CategoryRevenueDTO
    {
        public string? CategoryId { get; set; }
        public string? CategoryName { get; set; }
        public double TotalRevenue { get; set; }
    }
}
