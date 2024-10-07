using MilkStore.ModelViews.ResponseDTO;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.Contract.Services.Interface
{
    public interface IStatisticalProductService
    {
        Task<List<ProductSalesDTO>> GetTopSellingProducts(int topN, DateTime? startDate, DateTime? endDate, string? productName, string? categoryName);
        Task<List<ProductStockDTO>> GetLowStockProducts(int threshold);
    }
}
